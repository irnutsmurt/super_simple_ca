"""ACME server state: accounts, orders, authorizations, challenges, and nonces.

Persists the RFC 8555 resource state in the same SQLite database as the cert
mirror (its own tables, created idempotently). Nonces live in process memory —
single-use, short-lived; if the process restarts, clients simply fetch a fresh
one (badNonce is a normal, recoverable condition).

This module is standalone: it owns no web/request logic, only storage and the
allowed state transitions. IDs are opaque random tokens used to build resource
URLs in the ACME endpoints.
"""
import base64
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS acme_accounts (
    id          TEXT PRIMARY KEY,
    thumbprint  TEXT NOT NULL UNIQUE,
    jwk_json    TEXT NOT NULL,
    contact     TEXT,                         -- JSON array of strings
    status      TEXT NOT NULL DEFAULT 'valid',-- valid | deactivated | revoked
    eab_kid     TEXT,                         -- the EAB credential this account enrolled with
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS acme_orders (
    id               TEXT PRIMARY KEY,
    account_id       TEXT NOT NULL,
    status           TEXT NOT NULL,           -- pending|ready|processing|valid|invalid
    identifiers_json TEXT NOT NULL,
    not_before       TEXT,
    not_after        TEXT,
    expires          TEXT NOT NULL,
    cert_serial      TEXT,                     -- our CA serial for the issued cert
    cert_id          TEXT,                     -- opaque id for the cert download URL
    error_json       TEXT,
    created_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_acme_orders_account ON acme_orders(account_id);

CREATE TABLE IF NOT EXISTS acme_authorizations (
    id               TEXT PRIMARY KEY,
    order_id         TEXT NOT NULL,
    identifier_type  TEXT NOT NULL,
    identifier_value TEXT NOT NULL,
    status           TEXT NOT NULL,           -- pending|valid|invalid|expired|deactivated|revoked
    expires          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_acme_authz_order ON acme_authorizations(order_id);

CREATE TABLE IF NOT EXISTS acme_challenges (
    id           TEXT PRIMARY KEY,
    authz_id     TEXT NOT NULL,
    type         TEXT NOT NULL,               -- http-01
    token        TEXT NOT NULL,
    status       TEXT NOT NULL,               -- pending|processing|valid|invalid
    validated_at TEXT,
    error_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_acme_chall_authz ON acme_challenges(authz_id);

CREATE TABLE IF NOT EXISTS acme_eab_credentials (
    kid              TEXT PRIMARY KEY,    -- key identifier the client presents
    mac_key          TEXT NOT NULL,       -- base64url HMAC key (symmetric, stored raw)
    label            TEXT,                -- human note, e.g. "caddy on synology"
    status           TEXT NOT NULL DEFAULT 'active',  -- active | revoked
    http01_port      INTEGER,             -- port to fetch this client's http-01 challenge on (NULL = 80)
    created_at       TEXT NOT NULL,
    bound_account_id TEXT,                -- account that last enrolled with it
    used_at          TEXT                 -- when it was last used to enroll
);
"""


def _now():
    return datetime.now(timezone.utc)

def _iso(dt):
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).isoformat() if isinstance(dt, datetime) else dt

def new_id(prefix=""):
    return prefix + secrets.token_urlsafe(16)

def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# ------------------------------------------------------------------ nonces
class NonceStore:
    """In-memory single-use anti-replay nonces with a TTL."""

    def __init__(self, ttl_seconds=3600):
        self.ttl = ttl_seconds
        self._nonces = {}   # nonce -> expiry epoch

    def new(self):
        self._gc()
        n = secrets.token_urlsafe(24)
        self._nonces[n] = time.time() + self.ttl
        return n

    def consume(self, nonce):
        """Return True if the nonce was valid and unused (and invalidate it)."""
        exp = self._nonces.pop(nonce, None)
        return exp is not None and time.time() <= exp

    def _gc(self):
        if len(self._nonces) > 4096:
            now = time.time()
            self._nonces = {n: e for n, e in self._nonces.items() if e > now}


# ------------------------------------------------------------------ store
class AcmeStore:
    def __init__(self, db_path):
        self.db_path = db_path
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(SCHEMA)
            # Migrations for DBs created before these columns existed.
            acct_cols = [r[1] for r in conn.execute("PRAGMA table_info(acme_accounts)").fetchall()]
            if "eab_kid" not in acct_cols:
                conn.execute("ALTER TABLE acme_accounts ADD COLUMN eab_kid TEXT")
            eab_cols = [r[1] for r in conn.execute(
                "PRAGMA table_info(acme_eab_credentials)").fetchall()]
            if "http01_port" not in eab_cols:
                conn.execute("ALTER TABLE acme_eab_credentials ADD COLUMN http01_port INTEGER")

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    # --- accounts ---
    def create_account(self, thumbprint, jwk_json, contact=None, eab_kid=None):
        aid = new_id()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO acme_accounts(id,thumbprint,jwk_json,contact,status,eab_kid,created_at) "
                "VALUES(?,?,?,?, 'valid', ?, ?)",
                (aid, thumbprint, jwk_json, json.dumps(contact or []), eab_kid, _iso(_now())))
        return self.get_account(aid)

    def get_account(self, aid):
        return self._one("SELECT * FROM acme_accounts WHERE id=?", (aid,))

    def get_account_by_thumbprint(self, thumbprint):
        return self._one("SELECT * FROM acme_accounts WHERE thumbprint=?", (thumbprint,))

    def update_account_key(self, aid, thumbprint, jwk_json):
        """Rotate an account's key (RFC 8555 §7.3.5 keyChange)."""
        with self._conn() as conn:
            conn.execute("UPDATE acme_accounts SET thumbprint=?, jwk_json=? WHERE id=?",
                         (thumbprint, jwk_json, aid))
        return self.get_account(aid)

    def update_account(self, aid, contact=None, status=None):
        sets, params = [], []
        if contact is not None:
            sets.append("contact=?"); params.append(json.dumps(contact))
        if status is not None:
            sets.append("status=?"); params.append(status)
        if not sets:
            return self.get_account(aid)
        params.append(aid)
        with self._conn() as conn:
            conn.execute(f"UPDATE acme_accounts SET {','.join(sets)} WHERE id=?", params)
        return self.get_account(aid)

    # --- orders ---
    def create_order(self, account_id, identifiers, ttl_hours=24,
                     not_before=None, not_after=None):
        oid = new_id()
        expires = _now() + timedelta(hours=ttl_hours)
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO acme_orders(id,account_id,status,identifiers_json,not_before,"
                "not_after,expires,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (oid, account_id, "pending", json.dumps(identifiers),
                 _iso(not_before), _iso(not_after), _iso(expires), _iso(_now())))
        return self.get_order(oid)

    def get_order(self, oid):
        return self._one("SELECT * FROM acme_orders WHERE id=?", (oid,))

    def orders_for_account(self, account_id):
        return self._all("SELECT id FROM acme_orders WHERE account_id=? ORDER BY created_at DESC",
                         (account_id,))

    def certs_superseded_by(self, account_id, identifiers, exclude_order_id):
        """Cert serials from EARLIER orders of the same account whose identifier
        set is identical to `identifiers` — i.e. the certs a renewal replaces."""
        want = sorted((i.get("type"), (i.get("value") or "").lower()) for i in identifiers)
        serials = []
        rows = self._all("SELECT id, identifiers_json, cert_serial FROM acme_orders "
                         "WHERE account_id=? AND cert_serial IS NOT NULL AND id!=?",
                         (account_id, exclude_order_id))
        for r in rows:
            try:
                ids = json.loads(r["identifiers_json"])
            except Exception:  # noqa: BLE001
                continue
            have = sorted((i.get("type"), (i.get("value") or "").lower()) for i in ids)
            if have == want:
                serials.append(r["cert_serial"])
        return serials

    def set_order_status(self, oid, status, error=None):
        with self._conn() as conn:
            conn.execute("UPDATE acme_orders SET status=?, error_json=? WHERE id=?",
                         (status, json.dumps(error) if error is not None else None, oid))

    def set_order_certificate(self, oid, cert_serial, cert_id):
        with self._conn() as conn:
            conn.execute("UPDATE acme_orders SET status='valid', cert_serial=?, cert_id=? WHERE id=?",
                         (cert_serial, cert_id, oid))

    def order_by_cert_id(self, cert_id):
        return self._one("SELECT * FROM acme_orders WHERE cert_id=?", (cert_id,))

    def order_by_cert_serial(self, serial):
        return self._one("SELECT * FROM acme_orders WHERE cert_serial=?", (serial,))

    # --- authorizations ---
    def create_authorization(self, order_id, itype, ivalue, ttl_hours=24, status="pending"):
        azid = new_id()
        expires = _now() + timedelta(hours=ttl_hours)
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO acme_authorizations(id,order_id,identifier_type,identifier_value,"
                "status,expires) VALUES(?,?,?,?,?,?)",
                (azid, order_id, itype, ivalue, status, _iso(expires)))
        return self.get_authorization(azid)

    def get_authorization(self, azid):
        return self._one("SELECT * FROM acme_authorizations WHERE id=?", (azid,))

    def authorizations_for_order(self, order_id):
        return self._all("SELECT * FROM acme_authorizations WHERE order_id=?", (order_id,))

    def set_authorization_status(self, azid, status):
        with self._conn() as conn:
            conn.execute("UPDATE acme_authorizations SET status=? WHERE id=?", (status, azid))

    # --- challenges ---
    def create_challenge(self, authz_id, ctype, token, status="pending"):
        cid = new_id()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO acme_challenges(id,authz_id,type,token,status) VALUES(?,?,?,?,?)",
                (cid, authz_id, ctype, token, status))
        return self.get_challenge(cid)

    def get_challenge(self, cid):
        return self._one("SELECT * FROM acme_challenges WHERE id=?", (cid,))

    def challenges_for_authz(self, authz_id):
        return self._all("SELECT * FROM acme_challenges WHERE authz_id=?", (authz_id,))

    def set_challenge_status(self, cid, status, validated_at=None, error=None):
        with self._conn() as conn:
            conn.execute(
                "UPDATE acme_challenges SET status=?, validated_at=?, error_json=? WHERE id=?",
                (status, _iso(validated_at), json.dumps(error) if error is not None else None, cid))

    # --- state-transition helpers ---
    def authorizations_all_valid(self, order_id):
        rows = self.authorizations_for_order(order_id)
        return bool(rows) and all(r["status"] == "valid" for r in rows)

    def any_authorization_invalid(self, order_id):
        return any(r["status"] == "invalid" for r in self.authorizations_for_order(order_id))

    def maybe_advance_order(self, order_id):
        """pending -> ready when all authz valid; -> invalid if any authz invalid."""
        order = self.get_order(order_id)
        if not order or order["status"] not in ("pending",):
            return order
        if self.any_authorization_invalid(order_id):
            self.set_order_status(order_id, "invalid")
        elif self.authorizations_all_valid(order_id):
            self.set_order_status(order_id, "ready")
        return self.get_order(order_id)

    # --- EAB credentials (External Account Binding, RFC 8555 §7.3.4) ---
    def create_eab(self, label=None, key_len=32, http01_port=None):
        """Mint a new EAB credential: a short kid + a random base64url MAC key.
        `http01_port` is the port SSCA fetches this client's http-01 challenge on
        (None → the RFC default 80)."""
        kid = secrets.token_hex(8)
        mac_key = _b64u(secrets.token_bytes(key_len))
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO acme_eab_credentials(kid,mac_key,label,status,http01_port,created_at) "
                "VALUES(?,?,?, 'active', ?, ?)",
                (kid, mac_key, (label or None), http01_port, _iso(_now())))
        return self.get_eab(kid)

    def get_eab(self, kid):
        return self._one("SELECT * FROM acme_eab_credentials WHERE kid=?", (kid,))

    def list_eab(self):
        return self._all("SELECT * FROM acme_eab_credentials ORDER BY created_at DESC")

    def revoke_eab(self, kid):
        with self._conn() as conn:
            conn.execute("UPDATE acme_eab_credentials SET status='revoked' WHERE kid=?", (kid,))

    def set_eab_port(self, kid, http01_port):
        """Change an EAB credential's http-01 port (None → default 80). Takes
        effect on that client's next challenge — no re-enrolment needed."""
        with self._conn() as conn:
            conn.execute("UPDATE acme_eab_credentials SET http01_port=? WHERE kid=?",
                         (http01_port, kid))

    def delete_eab(self, kid):
        with self._conn() as conn:
            conn.execute("DELETE FROM acme_eab_credentials WHERE kid=?", (kid,))

    def bind_eab(self, kid, account_id):
        with self._conn() as conn:
            conn.execute(
                "UPDATE acme_eab_credentials SET bound_account_id=?, used_at=? WHERE kid=?",
                (account_id, _iso(_now()), kid))

    # --- helpers ---
    def _one(self, q, params):
        with self._conn() as conn:
            row = conn.execute(q, params).fetchone()
            return dict(row) if row else None

    def _all(self, q, params=()):
        with self._conn() as conn:
            return [dict(r) for r in conn.execute(q, params).fetchall()]
