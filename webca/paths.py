"""Filesystem layout for a SuperSimpleCA data root.

The web UI operates *in place* on the existing OpenSSL PKI files (ca/, certs/,
db/index.txt, serial, crlnumber, crl/, configs/openssl.cnf). OpenSSL's index.txt
remains the source of truth for the PKI; the SQLite database (db/certificates.db)
is a queryable mirror the UI reads and keeps in sync.
"""
import os


class Layout:
    def __init__(self, ca_root):
        self.root = os.path.abspath(ca_root)

    # --- directories ---
    @property
    def ca_dir(self):        return os.path.join(self.root, "ca")
    @property
    def certs_dir(self):     return os.path.join(self.root, "certs")
    @property
    def revoked_dir(self):   return os.path.join(self.certs_dir, "revokedcerts")
    @property
    def crl_dir(self):       return os.path.join(self.root, "crl")
    @property
    def db_dir(self):        return os.path.join(self.root, "db")
    @property
    def db_backup_dir(self): return os.path.join(self.db_dir, "backup")
    @property
    def configs_dir(self):   return os.path.join(self.root, "configs")

    # --- files ---
    @property
    def ca_key(self):        return os.path.join(self.ca_dir, "ca.key.pem")
    @property
    def ca_cert(self):       return os.path.join(self.ca_dir, "ca.cert.pem")
    @property
    def ca_p7b(self):        return os.path.join(self.ca_dir, "ca.cert.p7b")

    # --- two-tier: intermediate (subordinate) CA ---
    @property
    def int_dir(self):       return os.path.join(self.root, "intermediate")
    @property
    def int_key(self):       return os.path.join(self.int_dir, "intermediate.key.pem")
    @property
    def int_cert(self):      return os.path.join(self.int_dir, "intermediate.cert.pem")
    @property
    def int_csr(self):       return os.path.join(self.int_dir, "intermediate.csr.pem")
    @property
    def int_chain(self):     return os.path.join(self.int_dir, "chain.pem")  # intermediate + root

    def is_two_tier(self):
        """True once an intermediate CA has been created and signs new leaves."""
        return os.path.exists(self.int_cert) and os.path.exists(self.int_key)

    def root_key_present(self):
        """Whether the ROOT private key is still on this box (False = taken offline)."""
        return os.path.exists(self.ca_key)

    @property
    def signing_key(self):
        """The private key that signs LEAF certs: the intermediate when two-tier,
        otherwise the root. All operational signing/unlock state keys off this."""
        return self.int_key if self.is_two_tier() else self.ca_key

    @property
    def signing_cert(self):
        """The certificate matching signing_key (the issuer put into leaf chains)."""
        return self.int_cert if self.is_two_tier() else self.ca_cert
    @property
    def index(self):         return os.path.join(self.db_dir, "index.txt")
    @property
    def serial(self):        return os.path.join(self.db_dir, "serial")
    @property
    def crlnumber(self):     return os.path.join(self.db_dir, "crlnumber")
    @property
    def crl(self):           return os.path.join(self.crl_dir, "crl.pem")
    @property
    def openssl_conf(self):  return os.path.join(self.configs_dir, "openssl.cnf")
    @property
    def sqlite_db(self):     return os.path.join(self.db_dir, "certificates.db")
    @property
    def json_db(self):       return os.path.join(self.db_dir, "cert_database.json")

    def ensure_dirs(self):
        for d in (self.ca_dir, self.certs_dir, self.revoked_dir, self.crl_dir,
                  self.db_dir, self.db_backup_dir, self.configs_dir):
            os.makedirs(d, exist_ok=True)
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass

    def cert_pem_for_serial(self, serial):
        """Authoritative signed certificate written by `openssl ca` (new_certs_dir)."""
        return os.path.join(self.certs_dir, f"{serial}.pem")

    def is_ca_initialized(self):
        # The root cert is the trust anchor and always stays on disk. Being
        # *operable* needs a signing key: the intermediate (two-tier, where the
        # root key may be offline) or the root key itself (single-tier).
        if not os.path.exists(self.ca_cert):
            return False
        return self.is_two_tier() or os.path.exists(self.ca_key)

    def rel(self, path):
        """Path relative to the CA root, for storage in the DB."""
        return os.path.relpath(path, self.root)
