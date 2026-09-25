"""OpenSSL certificate-authority operations.

All operations that touch the CA private key take the passphrase as an argument
(or None when the key is unencrypted). The passphrase is never written to disk;
callers pass it in and it is used only to build `-passin`/`-passout pass:` args
for the openssl child process.
"""
import functools
import os
import shutil
import sqlite3
import stat
import subprocess
import threading
from datetime import datetime, timedelta, timezone

from cryptography import x509 as _cx509

from paths import Layout
from store import CertStore
from certparse import (parse_certificate, parse_index, find_key_for_cn,
                       certificate_fingerprint, crl_next_update)


class CaError(Exception):
    """Raised when an openssl operation fails; message is user-safe."""


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def _passin(passphrase):
    return ["-passin", f"pass:{passphrase}"] if passphrase else []


def _looks_like_ip(s):
    import ipaddress
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False


def _serialized(method):
    """Run a CaOps method under the per-instance signing lock. `openssl ca`
    mutates the shared `serial` and `index.txt` files and is NOT safe to run
    concurrently — parallel invocations race and most fail (duplicate serials,
    TXT_DB errors). This serializes signing/revoking so many simultaneous ACME
    enrolments (Caddy converting lots of sites at once) all succeed."""
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._sign_lock:
            return method(self, *args, **kwargs)
    return wrapper


def _csr_san_tokens(csr_pem):
    """SAN entries of a CSR as openssl config tokens (e.g. 'DNS:x', 'IP:1.2.3.4')."""
    data = csr_pem.encode("ascii") if isinstance(csr_pem, str) else csr_pem
    csr = _cx509.load_pem_x509_csr(data)
    tokens = []
    try:
        san = csr.extensions.get_extension_for_class(_cx509.SubjectAlternativeName).value
        tokens += [f"DNS:{n}" for n in san.get_values_for_type(_cx509.DNSName)]
        tokens += [f"IP:{ip}" for ip in san.get_values_for_type(_cx509.IPAddress)]
    except _cx509.ExtensionNotFound:
        pass
    return tokens


def _acme_extfile_content(cert_type, san_tokens):
    """A self-contained openssl [acme_ext] section for signing ACME CSRs.

    ACME CSRs (e.g. from Caddy) have an EMPTY subject and put the identity only
    in the SAN. RFC 5280 §4.1.2.6 requires the SAN to be *critical* when the
    subject is empty, otherwise browsers reject the cert (Chrome: ERR_CERT_INVALID).
    So we emit the SAN ourselves, marked critical, instead of copying the client's
    non-critical one.
    """
    if cert_type == "server":
        ku, eku = "critical, digitalSignature, keyEncipherment", "serverAuth"
    else:
        ku, eku = ("critical, nonRepudiation, digitalSignature, keyEncipherment",
                   "clientAuth, emailProtection")
    lines = [
        "[ acme_ext ]",
        "basicConstraints = CA:FALSE",
        'nsComment = "OpenSSL Generated Certificate"',
        "subjectKeyIdentifier = hash",
        "authorityKeyIdentifier = keyid,issuer",
        f"keyUsage = {ku}",
        f"extendedKeyUsage = {eku}",
    ]
    if san_tokens:
        lines.append("subjectAltName = critical, " + ", ".join(san_tokens))
    return "\n".join(lines) + "\n"


class CaOps:
    def __init__(self, ca_root, defaults=None):
        self.layout = Layout(ca_root)
        self.store = CertStore(self.layout.sqlite_db)
        self.defaults = defaults or {}
        # Serializes `openssl ca` (serial/index.txt are shared, not parallel-safe).
        self._sign_lock = threading.RLock()

    # ------------------------------------------------------------------ config
    def write_openssl_conf(self):
        """(Re)generate configs/openssl.cnf with paths derived from the CA root."""
        L = self.layout
        content = f"""
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = {L.root}
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/certs
database          = {L.index}
serial            = {L.serial}
RANDFILE          = $dir/private/.rand
private_key       = {L.signing_key}
certificate       = {L.signing_cert}
crlnumber         = {L.crlnumber}
crl               = {L.crl}
crl_extensions    = crl_ext
default_crl_days  = 30
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose
copy_extensions   = copy
unique_subject    = no

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = optional
emailAddress            = optional

[ req ]
default_bits        = 2048
default_md          = sha256
prompt              = no
distinguished_name  = req_distinguished_name
x509_extensions     = v3_ca

[ req_distinguished_name ]

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true

[ usr_cert ]
basicConstraints = CA:FALSE
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
basicConstraints = CA:FALSE
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ crl_ext ]
authorityKeyIdentifier=keyid:always
"""
        os.makedirs(self.layout.configs_dir, exist_ok=True)
        with open(self.layout.openssl_conf, "w") as f:
            f.write(content)

    # ------------------------------------------------------------- CA key state
    # These operate on the *signing* key — the intermediate when two-tier, else
    # the root — because that is the key ACME actually uses and the UI unlocks.
    def _key_encrypted(self, key_path):
        try:
            with open(key_path, "r") as f:
                head = f.read(2000)
        except OSError:
            return False
        return ("ENCRYPTED" in head) or ("Proc-Type: 4,ENCRYPTED" in head)

    def ca_key_encrypted(self):
        """True if the operational signing key is passphrase-protected."""
        return self._key_encrypted(self.layout.signing_key)

    def _verify_key(self, key_path, passphrase):
        """True if `passphrase` unlocks `key_path` (or the key is unencrypted)."""
        if not self._key_encrypted(key_path):
            return True
        r = _run(["openssl", "rsa", "-in", key_path,
                  "-passin", f"pass:{passphrase or ''}", "-noout", "-check"])
        return r.returncode == 0

    def verify_passphrase(self, passphrase):
        """Return True if `passphrase` unlocks the signing key (or it's unencrypted)."""
        return self._verify_key(self.layout.signing_key, passphrase)

    def encrypt_ca_key(self, new_passphrase, current_passphrase=None):
        """Add or change the signing key passphrase (AES-256)."""
        key = self.layout.signing_key
        if self._key_encrypted(key) and not self.verify_passphrase(current_passphrase):
            raise CaError("Current CA passphrase is incorrect.")
        tmp = key + ".tmp"
        cmd = ["openssl", "rsa", "-in", key,
               *(_passin(current_passphrase) if self._key_encrypted(key) else []),
               "-aes256", "-passout", f"pass:{new_passphrase}", "-out", tmp]
        r = _run(cmd)
        if r.returncode != 0:
            _safe_unlink(tmp)
            raise CaError(f"Failed to encrypt CA key: {r.stderr.strip()}")
        os.replace(tmp, key)
        os.chmod(key, 0o400)

    def remove_ca_key_passphrase(self, current_passphrase):
        """Strip the passphrase, leaving an unencrypted signing key."""
        key = self.layout.signing_key
        if not self._key_encrypted(key):
            return
        if not self.verify_passphrase(current_passphrase):
            raise CaError("Current CA passphrase is incorrect.")
        tmp = key + ".tmp"
        r = _run(["openssl", "rsa", "-in", key,
                  "-passin", f"pass:{current_passphrase}", "-out", tmp])
        if r.returncode != 0:
            _safe_unlink(tmp)
            raise CaError(f"Failed to remove CA passphrase: {r.stderr.strip()}")
        os.replace(tmp, key)
        os.chmod(key, 0o400)

    # -------------------------------------------------- two-tier / intermediate
    def two_tier_status(self):
        """Snapshot of the two-tier / offline-root state for the UI."""
        L = self.layout
        info = {"two_tier": L.is_two_tier(), "root_key_present": L.root_key_present(),
                "root_encrypted": self._key_encrypted(L.ca_key), "intermediate": None}
        if L.is_two_tier():
            info["intermediate"] = parse_certificate(L.int_cert) or {}
        return info

    def create_intermediate(self, dn, validity_days, root_passphrase=None,
                            int_passphrase=None, key_bits=4096):
        """Create a subordinate (intermediate) CA signed by the root, then switch
        operational leaf-signing to it. The root key is used ONCE here; afterwards
        it can be taken offline. `root_passphrase` is required only if the root key
        is currently encrypted. `int_passphrase` (optional) encrypts the
        intermediate key — leave blank for unattended ACME signing."""
        L = self.layout
        if not L.is_ca_initialized():
            raise CaError("Root CA is not initialized.")
        if L.is_two_tier():
            raise CaError("An intermediate CA already exists.")
        if not L.root_key_present():
            raise CaError("The root private key is offline — restore it to create an intermediate.")
        if not self._verify_key(L.ca_key, root_passphrase):
            raise CaError("Root CA passphrase is incorrect.")
        os.makedirs(L.int_dir, exist_ok=True)
        os.chmod(L.int_dir, 0o700)
        stamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
        ext_file = os.path.join(L.int_dir, f".int-{stamp}.ext")
        root_encrypted = self._key_encrypted(L.ca_key)
        try:
            # 1. intermediate private key (encrypted only if a passphrase is given)
            if int_passphrase:
                r = _run(["openssl", "genrsa", "-aes256", "-passout",
                          f"pass:{int_passphrase}", "-out", L.int_key, str(key_bits)])
            else:
                r = _run(["openssl", "genrsa", "-out", L.int_key, str(key_bits)])
            if r.returncode != 0:
                raise CaError(f"Failed to generate intermediate key: {r.stderr.strip()}")
            os.chmod(L.int_key, 0o400)

            # 2. CSR for the intermediate
            r = _run(["openssl", "req", "-new", "-sha256", "-key", L.int_key,
                      "-out", L.int_csr, "-subj", _subject_string(dn),
                      *(_passin(int_passphrase) if int_passphrase else [])])
            if r.returncode != 0:
                raise CaError(f"Failed to create intermediate CSR: {r.stderr.strip()}")

            # 3. root signs it as a subordinate CA (pathlen:0 → can't mint more CAs)
            with open(ext_file, "w") as f:
                f.write("basicConstraints = critical, CA:TRUE, pathlen:0\n"
                        "keyUsage = critical, digitalSignature, cRLSign, keyCertSign\n"
                        "subjectKeyIdentifier = hash\n"
                        "authorityKeyIdentifier = keyid:always,issuer\n")
            r = _run(["openssl", "x509", "-req", "-in", L.int_csr,
                      "-CA", L.ca_cert, "-CAkey", L.ca_key,
                      "-CAserial", os.path.join(L.int_dir, "root.srl"), "-CAcreateserial",
                      "-days", str(int(validity_days)), "-sha256",
                      "-extfile", ext_file, "-out", L.int_cert,
                      *(["-passin", f"pass:{root_passphrase or ''}"] if root_encrypted else [])])
            if r.returncode != 0:
                raise CaError(f"Root failed to sign the intermediate: {r.stderr.strip()}")
            os.chmod(L.int_cert, 0o444)

            # 4. sanity: the chain must verify against the root
            v = _run(["openssl", "verify", "-CAfile", L.ca_cert, L.int_cert])
            if v.returncode != 0:
                raise CaError(f"Intermediate did not verify against the root: {v.stderr.strip()}")

            # 5. chain file (intermediate + root) for serving
            with open(L.int_chain, "wb") as out:
                for p in (L.int_cert, L.ca_cert):
                    with open(p, "rb") as f:
                        out.write(f.read().rstrip() + b"\n")
            os.chmod(L.int_chain, 0o444)
        except Exception:
            # roll back a partial intermediate so we stay single-tier and usable
            for p in (L.int_cert, L.int_key, L.int_csr, L.int_chain):
                _safe_unlink(p)
            raise
        finally:
            _safe_unlink(ext_file)

        # 6. flip operational signing to the intermediate
        self.write_openssl_conf()
        return {"int_cert": L.rel(L.int_cert), "chain": L.rel(L.int_chain)}

    def read_root_key(self):
        """Return the (possibly encrypted) root private-key bytes, for export."""
        if not self.layout.root_key_present():
            raise CaError("The root private key is not on this server.")
        with open(self.layout.ca_key, "rb") as f:
            return f.read()

    def remove_root_key(self):
        """Delete the root private key from this box (it must be two-tier first,
        so leaf signing keeps working off the intermediate). IRREVERSIBLE."""
        L = self.layout
        if not L.is_two_tier():
            raise CaError("Create an intermediate before removing the root key — "
                          "otherwise this CA can no longer sign anything.")
        if not L.root_key_present():
            return
        if not self._key_encrypted(L.ca_key):
            raise CaError("Refusing to remove an unencrypted root key — encrypt it first.")
        os.remove(L.ca_key)

    # ---------------------------------------------------------------- CA init
    def init_ca(self, dn, passphrase=None, key_bits=4096, days=3650):
        L = self.layout
        L.ensure_dirs()
        self.write_openssl_conf()
        if L.is_ca_initialized():
            raise CaError("CA is already initialized.")

        if passphrase:
            r = _run(["openssl", "genrsa", "-aes256", "-passout",
                      f"pass:{passphrase}", "-out", L.ca_key, str(key_bits)])
        else:
            r = _run(["openssl", "genrsa", "-out", L.ca_key, str(key_bits)])
        if r.returncode != 0:
            raise CaError(f"Failed to generate CA key: {r.stderr.strip()}")
        os.chmod(L.ca_key, 0o400)

        subject = _subject_string(dn)
        r = _run(["openssl", "req", "-config", L.openssl_conf, "-key", L.ca_key,
                  "-new", "-x509", "-days", str(days), "-sha256", "-extensions",
                  "v3_ca", "-out", L.ca_cert, "-subj", subject, *_passin(passphrase)])
        if r.returncode != 0:
            raise CaError(f"Failed to create CA certificate: {r.stderr.strip()}")
        os.chmod(L.ca_cert, 0o444)

        _run(["openssl", "crl2pkcs7", "-nocrl", "-certfile", L.ca_cert, "-out", L.ca_p7b])

        for name, seed in ((L.index, ""), (L.serial, "1000\n"), (L.crlnumber, "1000\n")):
            if not os.path.exists(name):
                with open(name, "w") as f:
                    f.write(seed)

    # ------------------------------------------------------------- issue cert
    @_serialized
    def issue(self, common_name, cert_type, sans, validity_days, dn, passphrase,
              key_spec="rsa2048", source="ui"):
        """Create and sign a certificate. Returns the new serial (hex)."""
        L = self.layout
        self.write_openssl_conf()  # keep paths in sync with the current CA root
        common_name = _validate_cn(common_name)
        if cert_type not in ("server", "client"):
            raise CaError("Certificate type must be 'server' or 'client'.")
        extensions = "server_cert" if cert_type == "server" else "usr_cert"

        sans = list(sans or [])
        if not sans and cert_type == "server":
            sans = [f"DNS:{common_name}"]

        key_file = os.path.join(L.certs_dir, f"{common_name}.key")
        csr_file = os.path.join(L.certs_dir, f"{common_name}.csr")
        crt_file = os.path.join(L.certs_dir, f"{common_name}.crt")

        r = _genkey(key_spec, key_file)
        if r.returncode != 0:
            raise CaError(f"Failed to generate key: {r.stderr.strip()}")
        os.chmod(key_file, 0o600)

        san_conf = os.path.join(L.configs_dir, f"{common_name}_req.cnf")
        _write_req_conf(san_conf, dn, common_name, sans)
        try:
            r = _run(["openssl", "req", "-new", "-key", key_file, "-out", csr_file,
                      "-config", san_conf])
            if r.returncode != 0:
                raise CaError(f"Failed to create CSR: {r.stderr.strip()}")

            r = _run(["openssl", "ca", "-config", L.openssl_conf, "-batch",
                      "-extensions", extensions, "-days", str(validity_days),
                      "-notext", "-md", "sha256", "-in", csr_file, "-out", crt_file,
                      *_passin(passphrase)])
            if r.returncode != 0:
                raise CaError(_clean_ca_error(r.stderr))
        finally:
            _safe_unlink(san_conf)
        os.chmod(crt_file, 0o644)

        serial = self._serial_of(crt_file)
        cert_pem = L.cert_pem_for_serial(serial)
        details = parse_certificate(crt_file) or {}
        self._record({
            "serial": serial,
            "common_name": common_name,
            "cert_type": cert_type,
            "status": "valid",
            "subject": details.get("subject"),
            "sans": details.get("sans", sans),
            "issued_at": details.get("not_before") or datetime.now(timezone.utc),
            "expires_at": details.get("not_after"),
            "cert_path": L.rel(cert_pem) if os.path.exists(cert_pem) else L.rel(crt_file),
            "key_path": L.rel(key_file),
            "key_present": True,
            "source": source,
        }, f"Certificate {serial} for {common_name} was signed")
        self._notify("cert_issued", f"Certificate issued: {common_name}",
                     body=f"{cert_type} · serial {serial} · valid {validity_days} days",
                     serial=serial)
        return serial

    @_serialized
    def issue_web_cert(self, sans, validity_days, passphrase, out_cert, out_key):
        """Issue/renew the certificate SSCA serves on its *own* web endpoint and
        write it to the stable paths out_cert/out_key. Recorded with source='web'
        so it's distinguishable from user certs. Returns the serial.

        SANs are hostnames and/or IPs (Caddy/browsers reach SSCA directly by one
        of these); the first is used as the CN.
        """
        sans = [s.strip() for s in (sans or []) if s.strip()]
        if not sans:
            raise CaError("Web-UI TLS needs at least one hostname or IP.")
        cn = sans[0]
        tokens = [(("IP:" if _looks_like_ip(s) else "DNS:") + s) for s in sans]
        serial = self.issue(common_name=cn, cert_type="server", sans=tokens,
                            validity_days=validity_days, dn=self.defaults,
                            passphrase=passphrase, key_spec="ecdsa-p256", source="web")
        key_src = os.path.join(self.layout.certs_dir, f"{cn}.key")
        cert_src = self.layout.cert_pem_for_serial(serial)
        os.makedirs(os.path.dirname(out_cert), exist_ok=True)
        # Write the FULL chain (leaf + intermediate + root when two-tier) so the
        # web endpoint serves a path clients can build. Single-tier → just the leaf.
        with open(out_cert, "wb") as out:
            with open(cert_src, "rb") as f:
                out.write(f.read().rstrip() + b"\n")
            if self.layout.is_two_tier():
                with open(self.layout.int_chain, "rb") as f:
                    out.write(f.read().rstrip() + b"\n")
        shutil.copyfile(key_src, out_key)
        os.chmod(out_key, 0o600)
        return serial

    # --------------------------------------------------------------- sign CSR
    @_serialized
    def sign_csr(self, csr_pem, cert_type="server", validity_days=None, passphrase=None,
                 source="acme"):
        """Sign a client-provided CSR (used by ACME). Returns (serial, cert_pem).

        The client holds the private key, so no key is generated or stored; the
        CSR's SANs are copied into the certificate (openssl.cnf copy_extensions).
        """
        L = self.layout
        self.write_openssl_conf()
        days = int(validity_days or self.defaults.get("default_validity_days", 825))
        stamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
        csr_file = os.path.join(L.certs_dir, f".acme-{stamp}.csr")
        crt_tmp = os.path.join(L.certs_dir, f".acme-{stamp}.crt")
        ext_file = os.path.join(L.configs_dir, f".acme-{stamp}.ext")
        if isinstance(csr_pem, bytes):
            csr_pem = csr_pem.decode("ascii")
        with open(csr_file, "w") as f:
            f.write(csr_pem)
        # ACME CSRs are SAN-only with an empty subject, so we emit the SAN as a
        # *critical* extension (RFC 5280 §4.1.2.6) rather than copying the
        # client's non-critical one — otherwise browsers reject the cert.
        os.makedirs(L.configs_dir, exist_ok=True)
        with open(ext_file, "w") as f:
            f.write(_acme_extfile_content(cert_type, _csr_san_tokens(csr_pem)))
        cert_pem_path = None
        try:
            r = _run(["openssl", "ca", "-config", L.openssl_conf, "-batch",
                      "-extfile", ext_file, "-extensions", "acme_ext",
                      "-days", str(days), "-notext", "-md", "sha256",
                      "-in", csr_file, "-out", crt_tmp, *_passin(passphrase)])
            if r.returncode != 0:
                raise CaError(_clean_ca_error(r.stderr))
            serial = self._serial_of(crt_tmp)
            cert_pem_path = L.cert_pem_for_serial(serial)
            src = cert_pem_path if os.path.exists(cert_pem_path) else crt_tmp
            details = parse_certificate(src) or {}
            sans = details.get("sans", [])
            cn = None
            if details.get("subject"):
                m = _re.search(r"CN\s*=\s*([^/,]+)", details["subject"])
                cn = m.group(1).strip() if m else None
            if not cn:
                dns = [s.split(":", 1)[1] for s in sans if s.upper().startswith("DNS:")]
                cn = dns[0] if dns else serial
            with open(src, "rb") as f:
                cert_bytes = f.read()
        finally:
            _safe_unlink(csr_file)
            _safe_unlink(crt_tmp)
            _safe_unlink(ext_file)

        self._record({
            "serial": serial,
            "common_name": cn,
            "cert_type": cert_type,
            "status": "valid",
            "subject": details.get("subject"),
            "sans": sans,
            "issued_at": details.get("not_before") or datetime.now(timezone.utc),
            "expires_at": details.get("not_after"),
            "cert_path": L.rel(cert_pem_path) if cert_pem_path and os.path.exists(cert_pem_path) else None,
            "key_path": None,
            "key_present": False,
            "source": source,
        }, f"Certificate {serial} for {cn} was signed via ACME")
        self._notify("cert_issued", f"Certificate issued (ACME): {cn}",
                     body=f"{cert_type} · serial {serial}", serial=serial)
        return serial, cert_bytes.decode("ascii")

    # ----------------------------------------------------------------- revoke
    @_serialized
    def revoke(self, serial, passphrase, regen_crl=True):
        L = self.layout
        self.write_openssl_conf()  # keep paths in sync with the current CA root
        rec = self.store.get(serial)
        if not rec:
            raise CaError("Certificate not found.")
        if rec["status"] == "revoked":
            raise CaError("Certificate is already revoked.")
        cert_pem = L.cert_pem_for_serial(serial)
        if not os.path.exists(cert_pem):
            raise CaError(f"Certificate file {os.path.basename(cert_pem)} is missing.")

        r = _run(["openssl", "ca", "-config", L.openssl_conf, "-revoke", cert_pem,
                  *_passin(passphrase)])
        if r.returncode != 0:
            raise CaError(_clean_ca_error(r.stderr))

        try:
            self.store.set_status(serial, "revoked", datetime.now(timezone.utc))
        except sqlite3.OperationalError as e:
            raise CaError(_db_write_error(f"Certificate {serial} was revoked in the CA", e))
        self._notify("cert_revoked", f"Certificate revoked: {rec['common_name']}",
                     body=f"serial {serial}", severity="warning", serial=serial)
        self._archive_cert_files(rec)
        if regen_crl:
            self.generate_crl(passphrase)

    # ------------------------------------------------------------------ renew
    @_serialized
    def renew(self, serial, passphrase, validity_days=None):
        """Issue a fresh cert with the same CN/type/SANs.

        For a valid cert the old one is revoked (and the CRL updated). For an
        already-expired cert there's nothing to revoke, so the old entry is
        archived to keep the list tidy.
        """
        rec = self.store.get(serial)
        if not rec:
            raise CaError("Certificate not found.")
        if rec["status"] == "revoked":
            raise CaError("Cannot renew a revoked certificate; issue a new one instead.")

        details = parse_certificate(self.layout.cert_pem_for_serial(serial)) or {}
        sans = details.get("sans") or ([s for s in (rec.get("sans") or "").split(",") if s])
        dn = _dn_from_subject(details.get("subject") or rec.get("subject") or "")
        days = validity_days or int(self.defaults.get("default_validity_days", 825))

        new_serial = self.issue(rec["common_name"], rec["cert_type"], sans, days, dn, passphrase)
        if rec["status"] == "valid":
            self.revoke(serial, passphrase, regen_crl=True)
        else:  # expired — nothing to revoke; archive the superseded entry
            self.store.archive(serial)
        return new_serial

    def delete_cert(self, serial):
        """Remove a certificate from the app: archive its files, drop + tombstone the row.

        Does not alter index.txt (the CA ledger). The on-disk private key/CSR/cert
        are moved to the revoked-certs directory (recoverable), not erased.
        """
        rec = self.store.get(serial)
        if not rec:
            raise CaError("Certificate not found.")
        self._archive_cert_files(rec)
        try:
            self.store.delete(serial)
        except sqlite3.OperationalError as e:
            raise CaError(_db_write_error(f"Certificate {serial}'s files were archived", e))
        self._notify("cert_deleted", f"Certificate deleted: {rec['common_name']}",
                     body=f"serial {serial} removed from the list", serial=None)

    def auto_delete_archived(self, days):
        """Delete archived certs whose archive is older than `days`. Returns count."""
        if not days or days < 0:
            return 0
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        deleted = 0
        for rec in self.store.archived_before(cutoff):
            try:
                self._archive_cert_files(rec)
                self.store.delete(rec["serial"])
                deleted += 1
            except Exception:  # noqa: BLE001
                pass
        if deleted:
            self._notify("auto_delete", f"Auto-deleted {deleted} archived certificate(s)",
                         body=f"Archived more than {days} day(s) ago.")
        return deleted

    # -------------------------------------------------------------------- CRL
    @_serialized
    def generate_crl(self, passphrase):
        L = self.layout
        self.write_openssl_conf()  # keep paths in sync with the current CA root
        os.makedirs(L.crl_dir, exist_ok=True)
        r = _run(["openssl", "ca", "-config", L.openssl_conf, "-gencrl",
                  "-out", L.crl, *_passin(passphrase)])
        if r.returncode != 0:
            raise CaError(_clean_ca_error(r.stderr))

    # ---------------------------------------------------------------- helpers
    def resync(self):
        """Refresh expired-status flags from the wall clock."""
        self.store.refresh_expiry_status()

    def _notify(self, *args, **kwargs):
        """Add a notification; never let notification failures break an operation.

        Returns True if a new notification was created, False otherwise.
        """
        try:
            return bool(self.store.add_notification(*args, **kwargs))
        except Exception:  # noqa: BLE001
            return False

    # ------------------------------------------------------- CA / CRL health
    def root_ca_info(self):
        """Subject, validity, fingerprint and days-left for the root CA cert."""
        L = self.layout
        details = parse_certificate(L.ca_cert) or {}
        not_after = details.get("not_after")
        days_left = None
        if not_after:
            days_left = (not_after - datetime.now(timezone.utc)).days
        return {
            "subject": details.get("subject"),
            "not_before": details.get("not_before"),
            "not_after": not_after,
            "days_left": days_left,
            "fingerprint": certificate_fingerprint(L.ca_cert),
            "encrypted": self.ca_key_encrypted(),
        }

    def crl_info(self):
        """nextUpdate + days-until-next-update for the CRL, or None if no CRL."""
        L = self.layout
        nxt = crl_next_update(L.crl)
        if not nxt:
            return {"exists": os.path.exists(L.crl), "next_update": None, "days_left": None}
        return {"exists": True, "next_update": nxt,
                "days_left": (nxt - datetime.now(timezone.utc)).days}

    def check_ca_expiry(self, warn_days):
        """Notify if the root CA is expiring/expired. Returns True if a notice was raised."""
        info = self.root_ca_info()
        dl, na = info["days_left"], info["not_after"]
        if dl is None or na is None:
            return False
        key = na.date().isoformat()
        if dl < 0:
            return bool(self._notify("ca_expired", "Root CA certificate has EXPIRED",
                        body="Renew/rebuild the CA — all issued certs are now untrusted.",
                        severity="error", dedup_key=f"ca_expired:{key}"))
        if dl <= warn_days:
            return bool(self._notify("ca_expiring", f"Root CA expires in {dl} day(s)",
                        body="Plan a CA rollover well before this date.",
                        severity="warning", dedup_key=f"ca_expiring:{key}"))
        return False

    def check_crl(self, warn_days, passphrase, regenerate=True):
        """Regenerate the CRL if it's stale (or missing) and we can; else notify.

        `passphrase` is the CA passphrase if available unattended (None when the
        CA key is unencrypted). Returns a short status string.
        """
        info = self.crl_info()
        dl = info["days_left"]
        stale = (not info["exists"]) or (dl is not None and dl <= warn_days)
        if not stale:
            return "fresh"
        can_sign = (not self.ca_key_encrypted()) or bool(passphrase)
        if regenerate and can_sign:
            try:
                self.generate_crl(passphrase)
                return "regenerated"
            except CaError as e:
                self._notify("crl_stale", "CRL is stale and could not be regenerated",
                             body=str(e), severity="error", dedup_key="crl_stale")
                return "error"
        self._notify("crl_stale", "CRL is stale — regenerate it",
                     body="The certificate revocation list is near or past its next-update time. "
                          "Unlock the CA and regenerate it so clients keep accepting certificates.",
                     severity="warning", dedup_key=f"crl_stale:{(info['next_update'] or '').__str__()[:10]}")
        return "stale"

    def scan_expiry_notifications(self, default_days):
        """Raise de-duplicated notifications for certs at/near expiry.

        A cert's own `notify_days` overrides `default_days`. Dedup keys keep it to
        one notification per cert per expiry date, so this is safe to call on
        every dashboard load. Returns the number of new notifications created.
        """
        now = datetime.now(timezone.utc)
        created = 0
        for c in self.store.all(status="valid") + self.store.all(status="expired"):
            exp = c.get("expires_at")
            if not exp:
                continue
            try:
                expdt = datetime.fromisoformat(exp)
            except ValueError:
                continue
            if expdt.tzinfo is None:
                expdt = expdt.replace(tzinfo=timezone.utc)
            days_left = (expdt - now).days
            lead = c["notify_days"] if c.get("notify_days") is not None else default_days
            cn, serial = c["common_name"], c["serial"]
            if days_left < 0:
                created += self.store.add_notification(
                    "expired", f"Certificate expired: {cn}",
                    body=f"Expired {abs(days_left)} day(s) ago (serial {serial}).",
                    severity="error", serial=serial, dedup_key=f"expired:{serial}")
            elif days_left <= lead:
                created += self.store.add_notification(
                    "expiring", f"Certificate expiring soon: {cn}",
                    body=f"Expires in {days_left} day(s) (serial {serial}).",
                    severity="warning", serial=serial,
                    dedup_key=f"expiring:{serial}:{exp[:10]}")
        return created

    def _record(self, record, context):
        """Write a mirror row, turning a read-only DB into a clear, actionable error."""
        try:
            self.store.upsert(record)
        except sqlite3.OperationalError as e:
            raise CaError(_db_write_error(context, e))

    def reconcile_from_index(self):
        """Ingest any index.txt entries missing from the SQLite mirror.

        Best-effort self-heal: if a certificate was signed (so it is in index.txt
        and on disk) but never recorded in the mirror — e.g. an earlier write
        failed — this picks it up so it shows in the list. Only unknown serials
        are parsed, so it is cheap after the first pass. Returns the count added.
        """
        L = self.layout
        if not os.path.exists(L.index):
            return 0
        known = self.store.known_serials()  # includes archived rows + deleted tombstones
        rows = parse_index(L.index)
        now = datetime.now(timezone.utc)
        search_dirs = [L.certs_dir, L.revoked_dir]
        added = 0
        for row in rows:
            serial = row["serial"]
            if serial in known:
                continue
            cert_pem = L.cert_pem_for_serial(serial)
            details = parse_certificate(cert_pem) or {}
            if row["raw_status"] == "R":
                status = "revoked"
            elif row["expiry"] and row["expiry"] < now:
                status = "expired"
            else:
                status = "valid"
            key_path = find_key_for_cn(row["common_name"], search_dirs)
            self.store.upsert({
                "serial": serial,
                "common_name": row["common_name"] or "(unknown)",
                "cert_type": details.get("cert_type", "unknown"),
                "status": status,
                "subject": details.get("subject") or row["subject"],
                "sans": details.get("sans", []),
                "issued_at": details.get("not_before"),
                "expires_at": row["expiry"],
                "revoked_at": row["revocation"],
                "cert_path": L.rel(cert_pem) if os.path.exists(cert_pem) else None,
                "key_path": L.rel(key_path) if key_path else None,
                "key_present": bool(key_path),
            })
            added += 1
        return added

    def _serial_of(self, cert_file):
        r = _run(["openssl", "x509", "-in", cert_file, "-noout", "-serial"])
        if r.returncode != 0:
            raise CaError("Could not read serial from new certificate.")
        return r.stdout.strip().split("=", 1)[1]

    def _archive_cert_files(self, rec):
        """Move a revoked cert's CN-named key/csr/crt out of the active certs dir."""
        L = self.layout
        os.makedirs(L.revoked_dir, exist_ok=True)
        cn = rec["common_name"]
        for name in (f"{cn}.key", f"{cn}.key.pem", f"{cn}.csr", f"{cn}.csr.pem",
                     f"{cn}.crt", f"{cn}.cert.pem"):
            src = os.path.join(L.certs_dir, name)
            if os.path.exists(src):
                try:
                    shutil.move(src, os.path.join(L.revoked_dir, name))
                except OSError:
                    pass


# --------------------------------------------------------------- module utils
import re as _re

# A common name that is safe as a filename and as an OpenSSL config value.
_CN_RE = _re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._*-]{0,252}[A-Za-z0-9])?$")

KEY_SPECS = {
    "rsa2048": "RSA 2048",
    "rsa4096": "RSA 4096",
    "ecdsa-p256": "ECDSA P-256",
}


def _validate_cn(common_name):
    cn = (common_name or "").strip()
    if not cn:
        raise CaError("Common Name is required.")
    if len(cn) > 253:
        raise CaError("Common Name is too long (max 253 characters).")
    if not _CN_RE.match(cn):
        raise CaError("Common Name contains invalid characters. Use letters, digits, dot, "
                      "hyphen, underscore or '*' (no spaces, slashes or other symbols).")
    return cn


def _genkey(key_spec, key_file):
    if key_spec == "rsa4096":
        return _run(["openssl", "genrsa", "-out", key_file, "4096"])
    if key_spec == "ecdsa-p256":
        return _run(["openssl", "ecparam", "-name", "prime256v1", "-genkey",
                     "-noout", "-out", key_file])
    # default
    return _run(["openssl", "genrsa", "-out", key_file, "2048"])


def _subject_string(dn):
    order = [("C", "country"), ("ST", "state"), ("L", "locality"),
             ("O", "organization"), ("OU", "organizational_unit"),
             ("CN", "common_name"), ("emailAddress", "email")]
    parts = []
    for key, field in order:
        val = dn.get(field) or dn.get(key)
        if val:
            parts.append(f"{key}={val}")
    return "/" + "/".join(parts)


def _write_req_conf(path, dn, common_name, sans):
    dn = dn or {}
    lines = ["[ req ]", "prompt = no", "default_md = sha256",
             "distinguished_name = dn", "req_extensions = v3_req", "", "[ dn ]"]
    for key, field in (("C", "country"), ("ST", "state"), ("L", "locality"),
                       ("O", "organization"), ("OU", "organizational_unit")):
        val = dn.get(field) or dn.get(key)
        if val:
            lines.append(f"{key} = {val}")
    lines.append(f"CN = {common_name}")
    lines += ["", "[ v3_req ]"]
    if sans:
        lines.append("subjectAltName = @alt_names")
        lines += ["", "[ alt_names ]"]
        dns_i = ip_i = 1
        for san in sans:
            san = san.strip()
            if san.upper().startswith("DNS:"):
                lines.append(f"DNS.{dns_i} = {san.split(':', 1)[1]}")
                dns_i += 1
            elif san.upper().startswith("IP:") or san.upper().startswith("IP ADDRESS:"):
                lines.append(f"IP.{ip_i} = {san.split(':', 1)[1]}")
                ip_i += 1
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def _dn_from_subject(subject):
    """Turn 'CN=foo,O=Bar' or '/CN=foo/O=Bar' into the dn dict issue() expects."""
    dn = {}
    if not subject:
        return dn
    seps = subject.replace("/", ",")
    field_map = {"C": "country", "ST": "state", "L": "locality", "O": "organization",
                 "OU": "organizational_unit", "CN": "common_name",
                 "emailAddress": "email", "EMAILADDRESS": "email"}
    for part in seps.split(","):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            k, v = k.strip(), v.strip()
            if k in field_map:
                dn[field_map[k]] = v
    return dn


def _clean_ca_error(stderr):
    stderr = (stderr or "").strip()
    low = stderr.lower()
    if "bad decrypt" in low or "bad password" in low or "wrong" in low and "pass" in low:
        return "CA passphrase is incorrect."
    if "unable to load ca private key" in low:
        return "Could not load CA private key (wrong passphrase, or key missing)."
    if "there is already a certificate" in low:
        return "OpenSSL refused: a certificate with this subject already exists."
    return f"OpenSSL error: {stderr.splitlines()[-1] if stderr else 'unknown error'}"


def _safe_unlink(path):
    try:
        os.remove(path)
    except OSError:
        pass


def _db_write_error(context, err):
    return (f"{context}, but the certificate list database could not be updated ({err}). "
            f"This usually means db/certificates.db is not writable by the account running the "
            f"service. Fix its ownership/permissions, then use Settings → Re-sync to update the "
            f"list.")
