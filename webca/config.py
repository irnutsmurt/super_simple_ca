"""Configuration loading and the app-secret / admin-credential helpers."""
import os
import secrets

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(HERE, "config.yaml")
INSTANCE_DIR = os.path.join(HERE, "instance")
FLASK_SECRET_PATH = os.path.join(INSTANCE_DIR, "flask_secret")
PERSIST_KEY_PATH = os.path.join(INSTANCE_DIR, "persist.key")

DEFAULTS = {
    # CA data root: the existing SuperSimpleCA directory (parent of webca/).
    "ca_root": os.path.dirname(HERE),
    "host": "0.0.0.0",
    "port": 8443,
    # TLS for the web UI itself (recommended on a LAN). Leave both null for HTTP.
    "tls_cert": None,
    "tls_key": None,
    # Web-UI TLS mode:
    #   http     — plain HTTP (or, for back-compat, HTTPS if tls_cert/tls_key are set)
    #   manual   — serve HTTPS with the tls_cert/tls_key files you provide
    #   managed  — SSCA issues a cert for its own endpoint from its CA and
    #              auto-renews it (no Caddy/ACME loop). Reach SSCA directly (point
    #              its DNS/`acme_ca` at SSCA, not through Caddy) for this to help.
    "web_tls": {
        "mode": "http",
        "sans": [],                  # hostnames/IPs SSCA is reached by, e.g. ["ca.example.com","192.168.1.10"]
        "validity_days": 825,
        "renew_before_days": 30,
    },
    # First-run guided setup (new installs only). `active` = the user chose the
    # walkthrough and hasn't finished it; `dismissed` = they opted out or finished.
    "setup": {
        "wizard_active": False,
        "wizard_dismissed": False,
    },
    "session_timeout_minutes": 60,
    "ca_unlock_timeout_minutes": 15,
    "require_login": True,
    # Set true when served over HTTPS (e.g. behind Caddy) so the session cookie
    # gets the Secure flag. Leave false for plain-HTTP/localhost access.
    "secure_cookies": False,
    # Failed-login lockout: after `max_fails` within `window` seconds, block that
    # IP for `lock` seconds.
    "login_throttle": {"max_fails": 5, "window_seconds": 300, "lock_seconds": 300},
    # What happens to the CA unlock when the service restarts:
    #   relogin — invalidate sessions; you sign in again (auto-unlock re-unlocks)
    #   keep    — stay signed in; unlock the CA when next needed
    #   persist — keep the CA unlocked across restarts (stores the passphrase at
    #             rest under a machine-local key; least secure)
    "on_restart": "relogin",
    # Empty list = allow any *private* LAN address. Non-empty = allow only these
    # (single IPs or CIDR ranges). Public/external addresses are never allowed.
    "ip_allowlist": [],
    "auth": {
        "password_hash": None,   # set by setup.py
    },
    "notifications": {
        "default_notify_days": 30,   # default lead time for expiry alerts
        "login_alerts": True,        # notify on failed sign-in attempts
        "ca_expiry_warn_days": 60,   # warn this many days before the root CA expires
        "crl_warn_days": 7,          # regenerate/warn this many days before the CRL lapses
    },
    "archive": {
        "auto_delete": False,        # auto-delete archived certs after a delay
        "delete_after_days": 90,
    },
    "acme": {
        "enabled": False,
        "external_url": "",          # e.g. https://ca.example.com — REQUIRED to enable
        "validity_days": 90,         # default issued-cert lifetime
        "max_validity_days": 397,    # cap on client-requested lifetimes
        "allowed_domains": [],       # e.g. ["example.com"]; empty = allow any (challenge still required)
        "http01_port": 80,           # RFC default; overridable for tests
        "order_ttl_hours": 24,
        "manage_in_ui": True,        # allow revoke/archive/delete of ACME certs from the web UI
        "eab_required": False,       # require External Account Binding to enroll (RFC 8555 §7.3.4)
        # When a client renews (new cert, same account + same identifiers), revoke
        # the cert it replaces. Off by default — standard ACME leaves the old cert
        # to expire on its own; enabling this keeps the cert list tidy.
        "revoke_superseded": False,
    },
    # Phase 4 — "publish a service": SSCA creates a Pi-hole DNS record + a Caddy
    # reverse-proxy route so Caddy auto-enrolls a cert from this CA. Credentials
    # (the Pi-hole app password) are stored encrypted at rest, NOT here.
    "publish": {
        "enabled": False,
        "target_ip": "",             # the Caddy box IP that service names resolve to
        "domain": "",                # default hostname suffix, e.g. example.com
        # One or more Pi-holes (e.g. a primary + secondary for redundancy). The DNS
        # record is written to ALL of them. Each: {base_url, verify_tls}; the app
        # password is stored encrypted at rest, keyed by base_url (not here).
        "piholes": [],
        "caddy": {
            "admin_url": "",         # e.g. http://192.168.1.20:2019
            "https_port": 443,       # the port Caddy serves HTTPS on (for route wiring)
        },
    },
    "cert_defaults": {
        "default_validity_days": 825,
        "key_length": 4096,
        "country": "US",
        "state": "State",
        "locality": "City",
        "organization": "Example Homelab",
        "organizational_unit": "Homelab",
        "common_name": "Example Homelab CA",
        "email": "admin@example.com",
    },
}


def _deep_merge(base, override):
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path=None):
    path = path or os.environ.get("SUPERSIMPLECA_CONFIG") or DEFAULT_CONFIG_PATH
    data = {}
    if os.path.exists(path):
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    cfg = _deep_merge(DEFAULTS, data)
    cfg["_path"] = path
    # ca_root may be relative to the config file's directory
    if not os.path.isabs(cfg["ca_root"]):
        cfg["ca_root"] = os.path.abspath(os.path.join(os.path.dirname(path), cfg["ca_root"]))
    return cfg


def save_config(cfg, path=None):
    path = path or cfg.get("_path") or DEFAULT_CONFIG_PATH
    out = {k: v for k, v in cfg.items() if not k.startswith("_")}
    with open(path, "w") as f:
        yaml.safe_dump(out, f, sort_keys=False, default_flow_style=False)
    os.chmod(path, 0o600)


def get_flask_secret():
    """Load a stable Flask secret key, generating one on first run."""
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    if os.path.exists(FLASK_SECRET_PATH):
        with open(FLASK_SECRET_PATH) as f:
            val = f.read().strip()
            if val:
                return val
    val = secrets.token_hex(32)
    with open(FLASK_SECRET_PATH, "w") as f:
        f.write(val)
    os.chmod(FLASK_SECRET_PATH, 0o600)
    return val
