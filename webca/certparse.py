"""Parsing helpers for OpenSSL's index.txt and X.509 certificate files."""
import os
import re
import subprocess
from datetime import datetime, timezone


def _parse_openssl_time(value):
    """Parse an ASN.1 UTCTime/GeneralizedTime string like '251005181438Z'."""
    if not value:
        return None
    value = value.strip()
    for fmt in ("%y%m%d%H%M%SZ", "%Y%m%d%H%M%SZ"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def cn_from_subject(subject):
    """Extract the CN from a slash- or comma-formatted subject string."""
    if not subject:
        return None
    m = re.search(r"CN\s*=\s*([^/,]+)", subject)
    return m.group(1).strip() if m else None


def parse_index(index_path):
    """Parse index.txt into a list of dicts.

    Columns (tab separated): status, expiry, revocation, serial, filename, subject.
    status is V (valid), R (revoked), or E (expired).
    """
    rows = []
    if not os.path.exists(index_path):
        return rows
    with open(index_path, "r") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 6:
                continue
            status, expiry, revocation, serial, _filename, subject = parts[:6]
            rev_date = None
            if revocation:
                # revocation may carry a reason, e.g. "251005181445Z,keyCompromise"
                rev_date = _parse_openssl_time(revocation.split(",")[0])
            rows.append({
                "raw_status": status.strip(),
                "expiry": _parse_openssl_time(expiry),
                "revocation": rev_date,
                "serial": serial.strip(),
                "subject": subject.strip(),
                "common_name": cn_from_subject(subject),
            })
    return rows


def parse_certificate(cert_path):
    """Return details for a certificate file, or None if it cannot be read.

    Returns dict: subject, sans (list), not_before, not_after, cert_type
    (server/client/unknown, inferred from Extended Key Usage).
    """
    if not os.path.exists(cert_path):
        return None
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-text",
             "-nameopt", "RFC2253"],
            capture_output=True, text=True, check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

    subject = None
    sans = []
    not_before = not_after = None
    cert_type = "unknown"
    in_san = False
    in_eku = False

    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("Subject:") and "Public Key" not in stripped:
            subject = stripped.split("Subject:", 1)[1].strip()
        elif stripped.startswith("Not Before:"):
            not_before = _parse_x509_date(stripped.split("Not Before:", 1)[1].strip())
        elif stripped.startswith("Not After :"):
            not_after = _parse_x509_date(stripped.split("Not After :", 1)[1].strip())
        elif "X509v3 Subject Alternative Name" in stripped:
            in_san = True
            continue
        elif "X509v3 Extended Key Usage" in stripped:
            in_eku = True
            continue
        elif in_san:
            sans = [s.strip() for s in stripped.split(",") if s.strip()]
            in_san = False
        elif in_eku:
            low = stripped.lower()
            if "tls web server" in low or "serverauth" in low:
                cert_type = "server"
            elif "tls web client" in low or "clientauth" in low:
                cert_type = "client"
            in_eku = False

    return {
        "subject": subject,
        "sans": sans,
        "not_before": not_before,
        "not_after": not_after,
        "cert_type": cert_type,
    }


def _parse_x509_date(value):
    """Parse an openssl display date like 'Oct  5 18:14:38 2025 GMT'."""
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def certificate_fingerprint(cert_path, algo="sha256"):
    """Return the certificate's fingerprint (e.g. 'AA:BB:...'), or None."""
    if not os.path.exists(cert_path):
        return None
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", f"-fingerprint", f"-{algo}"],
            capture_output=True, text=True, check=True).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return out.split("=", 1)[1] if "=" in out else out


def crl_next_update(crl_path):
    """Return the CRL's nextUpdate as a timezone-aware datetime, or None."""
    if not os.path.exists(crl_path):
        return None
    try:
        out = subprocess.run(
            ["openssl", "crl", "-in", crl_path, "-noout", "-nextupdate"],
            capture_output=True, text=True, check=True).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    if "=" in out:
        return _parse_x509_date(out.split("=", 1)[1].strip())
    return None


def find_key_for_cn(common_name, search_dirs):
    """Locate a private key file for a CN across known naming conventions."""
    if not common_name:
        return None
    candidates = [f"{common_name}.key", f"{common_name}.key.pem"]
    for d in search_dirs:
        for name in candidates:
            p = os.path.join(d, name)
            if os.path.exists(p):
                return p
    return None
