"""SQLite metadata store — a queryable mirror of the OpenSSL PKI.

OpenSSL's index.txt stays authoritative for the CA itself; this table lets the
web UI list, filter and sort certificates quickly and hold app-level metadata
(discovered key paths, inferred type) that index.txt does not track.
"""
import os
import sqlite3
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS certificates (
    serial       TEXT PRIMARY KEY,
    common_name  TEXT NOT NULL,
    cert_type    TEXT NOT NULL DEFAULT 'unknown',
    status       TEXT NOT NULL,              -- valid | revoked | expired
    subject      TEXT,
    sans         TEXT,                        -- comma-separated
    issued_at    TEXT,                        -- ISO8601 UTC
    expires_at   TEXT,                        -- ISO8601 UTC
    revoked_at   TEXT,                        -- ISO8601 UTC or NULL
    cert_path    TEXT,                        -- relative to CA root
    key_path     TEXT,                        -- relative to CA root or NULL
    key_present  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cert_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_cert_cn ON certificates(common_name);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- Serials removed from the app; kept so reconcile_from_index won't resurrect them.
CREATE TABLE IF NOT EXISTS deleted_certs (
    serial     TEXT PRIMARY KEY,
    deleted_at TEXT
);

CREATE TABLE IF NOT EXISTS notifications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    type       TEXT NOT NULL,               -- expiring | expired | login_failed | cert_issued | cert_revoked
    severity   TEXT NOT NULL DEFAULT 'info', -- info | warning | error
    title      TEXT NOT NULL,
    body       TEXT,
    serial     TEXT,                         -- related certificate, if any
    dedup_key  TEXT,                         -- prevents duplicate auto-notifications
    created_at TEXT NOT NULL,
    read       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_notif_read ON notifications(read);

-- Phase 4: services SSCA has auto-published (Pi-hole DNS + Caddy route).
CREATE TABLE IF NOT EXISTS published_services (
    hostname    TEXT PRIMARY KEY,
    upstream    TEXT NOT NULL,               -- backend dial, e.g. 192.168.1.30:7474
    target_ip   TEXT NOT NULL,               -- DNS A-record target (the Caddy box IP)
    dns_ok      INTEGER NOT NULL DEFAULT 0,
    route_ok    INTEGER NOT NULL DEFAULT 0,
    status      TEXT NOT NULL DEFAULT 'pending', -- pending|published|error|partial
    error       TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT
);
"""


def _iso(dt):
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


class CertStore:
    def __init__(self, db_path):
        self.db_path = db_path
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._init()

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init(self):
        with self._conn() as conn:
            conn.executescript(SCHEMA)
            # Migration: add per-cert expiry notify lead time to existing DBs.
            cols = [r[1] for r in conn.execute("PRAGMA table_info(certificates)").fetchall()]
            if "notify_days" not in cols:
                conn.execute("ALTER TABLE certificates ADD COLUMN notify_days INTEGER")
            if "archived_at" not in cols:
                conn.execute("ALTER TABLE certificates ADD COLUMN archived_at TEXT")
            if "source" not in cols:
                conn.execute("ALTER TABLE certificates ADD COLUMN source TEXT DEFAULT 'ui'")
            # Collapse duplicate de-dup notifications from any DB created before the
            # unique index existed (this is what made read notifications reappear).
            # Preserve read state: if any copy was read, the survivor is read.
            conn.execute(
                "UPDATE notifications SET read=1 WHERE dedup_key IS NOT NULL AND dedup_key IN "
                "(SELECT dedup_key FROM notifications WHERE read=1 AND dedup_key IS NOT NULL)")
            conn.execute(
                "DELETE FROM notifications WHERE dedup_key IS NOT NULL AND id NOT IN "
                "(SELECT MIN(id) FROM notifications WHERE dedup_key IS NOT NULL GROUP BY dedup_key)")
            try:
                conn.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_notif_dedup "
                    "ON notifications(dedup_key) WHERE dedup_key IS NOT NULL")
            except sqlite3.OperationalError:
                pass  # app-level dedup below is the real guard

    def upsert(self, rec):
        cols = ("serial", "common_name", "cert_type", "status", "subject", "sans",
                "issued_at", "expires_at", "revoked_at", "cert_path", "key_path",
                "key_present", "source")
        vals = (
            rec["serial"], rec["common_name"], rec.get("cert_type", "unknown"),
            rec["status"], rec.get("subject"),
            ",".join(rec.get("sans", [])) if isinstance(rec.get("sans"), list) else rec.get("sans"),
            _iso(rec.get("issued_at")), _iso(rec.get("expires_at")),
            _iso(rec.get("revoked_at")), rec.get("cert_path"), rec.get("key_path"),
            1 if rec.get("key_present") else 0, rec.get("source", "ui"),
        )
        placeholders = ",".join("?" * len(cols))
        updates = ",".join(f"{c}=excluded.{c}" for c in cols if c != "serial")
        with self._conn() as conn:
            conn.execute(
                f"INSERT INTO certificates ({','.join(cols)}) VALUES ({placeholders}) "
                f"ON CONFLICT(serial) DO UPDATE SET {updates}",
                vals,
            )

    def set_status(self, serial, status, revoked_at=None):
        with self._conn() as conn:
            conn.execute(
                "UPDATE certificates SET status=?, revoked_at=? WHERE serial=?",
                (status, _iso(revoked_at), serial),
            )

    def get(self, serial):
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM certificates WHERE serial=?", (serial,)).fetchone()
            return dict(row) if row else None

    def all(self, status=None, search=None, order="expires_at"):
        allowed_order = {"expires_at", "issued_at", "common_name", "status", "serial"}
        if order not in allowed_order:
            order = "expires_at"
        q = "SELECT * FROM certificates"
        clauses, params = [], []
        # Archived certs are hidden everywhere except the explicit 'archived' view.
        if status == "archived":
            clauses.append("archived_at IS NOT NULL")
        else:
            clauses.append("archived_at IS NULL")
            if status and status != "all":
                clauses.append("status = ?")
                params.append(status)
        if search:
            clauses.append("(common_name LIKE ? OR subject LIKE ? OR sans LIKE ?)")
            like = f"%{search}%"
            params += [like, like, like]
        q += " WHERE " + " AND ".join(clauses)
        q += f" ORDER BY {order} ASC"
        with self._conn() as conn:
            return [dict(r) for r in conn.execute(q, params).fetchall()]

    def find_active_by_cn(self, common_name):
        """Return a non-archived, valid certificate with this CN, or None."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM certificates WHERE common_name=? AND status='valid' "
                "AND archived_at IS NULL ORDER BY expires_at DESC LIMIT 1",
                (common_name,)).fetchone()
            return dict(row) if row else None

    def find_valid_by_host(self, host):
        """A valid cert whose CN or SAN matches `host` (used to detect that an
        ACME client has enrolled a just-published service)."""
        host = (host or "").lower()
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM certificates WHERE status='valid' AND "
                "(LOWER(common_name)=? OR LOWER(sans) LIKE ?) "
                "ORDER BY issued_at DESC LIMIT 1",
                (host, f"%{host}%")).fetchone()
            return dict(row) if row else None

    def counts(self):
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) c FROM certificates "
                "WHERE archived_at IS NULL GROUP BY status").fetchall()
            archived = conn.execute(
                "SELECT COUNT(*) c FROM certificates WHERE archived_at IS NOT NULL"
            ).fetchone()["c"]
        out = {"valid": 0, "revoked": 0, "expired": 0, "total": 0, "archived": archived}
        for r in rows:
            out[r["status"]] = r["c"]
            out["total"] += r["c"]
        return out

    # ------------------------------------------------------------ archive/delete
    def archive(self, serial):
        with self._conn() as conn:
            conn.execute("UPDATE certificates SET archived_at=? WHERE serial=?",
                         (datetime.now(timezone.utc).isoformat(), serial))

    def unarchive(self, serial):
        with self._conn() as conn:
            conn.execute("UPDATE certificates SET archived_at=NULL WHERE serial=?", (serial,))

    def delete(self, serial):
        """Remove the row and tombstone the serial so reconcile won't re-add it."""
        with self._conn() as conn:
            conn.execute("INSERT OR REPLACE INTO deleted_certs(serial, deleted_at) VALUES(?,?)",
                         (serial, datetime.now(timezone.utc).isoformat()))
            conn.execute("DELETE FROM certificates WHERE serial=?", (serial,))

    def known_serials(self):
        """Every serial the app already knows about (live rows + tombstones)."""
        with self._conn() as conn:
            live = {r[0] for r in conn.execute("SELECT serial FROM certificates")}
            gone = {r[0] for r in conn.execute("SELECT serial FROM deleted_certs")}
        return live | gone

    def archived_before(self, cutoff_iso):
        with self._conn() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM certificates WHERE archived_at IS NOT NULL AND archived_at < ?",
                (cutoff_iso,)).fetchall()]

    def refresh_expiry_status(self):
        """Flip valid -> expired for certs whose expiry has passed (not revoked)."""
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            conn.execute(
                "UPDATE certificates SET status='expired' "
                "WHERE status='valid' AND expires_at IS NOT NULL AND expires_at < ?",
                (now,),
            )

    def set_notify_days(self, serial, days):
        with self._conn() as conn:
            conn.execute("UPDATE certificates SET notify_days=? WHERE serial=?", (days, serial))

    # ------------------------------------------------------------ notifications
    def add_notification(self, ntype, title, body=None, severity="info",
                         serial=None, dedup_key=None):
        """Insert a notification. With a dedup_key, a duplicate is ignored.

        Returns True if a new row was created, False if de-duplicated.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            if dedup_key:
                # App-level dedup — do not rely solely on a unique index that an
                # older database might be missing.
                exists = conn.execute(
                    "SELECT 1 FROM notifications WHERE dedup_key=? LIMIT 1", (dedup_key,)
                ).fetchone()
                if exists:
                    return False
                conn.execute(
                    "INSERT INTO notifications"
                    "(type,severity,title,body,serial,dedup_key,created_at,read) "
                    "VALUES(?,?,?,?,?,?,?,0)",
                    (ntype, severity, title, body, serial, dedup_key, now))
                return True
            conn.execute(
                "INSERT INTO notifications(type,severity,title,body,serial,created_at,read) "
                "VALUES(?,?,?,?,?,?,0)",
                (ntype, severity, title, body, serial, now))
            return True

    def notifications(self, limit=50, unread_only=False):
        q = "SELECT * FROM notifications"
        if unread_only:
            q += " WHERE read=0"
        q += " ORDER BY created_at DESC, id DESC LIMIT ?"
        with self._conn() as conn:
            return [dict(r) for r in conn.execute(q, (limit,)).fetchall()]

    def unread_count(self):
        with self._conn() as conn:
            return conn.execute("SELECT COUNT(*) c FROM notifications WHERE read=0").fetchone()["c"]

    def mark_notification_read(self, nid):
        with self._conn() as conn:
            conn.execute("UPDATE notifications SET read=1 WHERE id=?", (nid,))

    def mark_all_notifications_read(self):
        with self._conn() as conn:
            conn.execute("UPDATE notifications SET read=1 WHERE read=0")

    def clear_notifications(self):
        with self._conn() as conn:
            conn.execute("DELETE FROM notifications")

    def get_meta(self, key, default=None):
        with self._conn() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            return row["value"] if row else default

    def set_meta(self, key, value):
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO meta(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    # --------------------------------------------------- published services (Phase 4)
    def upsert_published_service(self, hostname, **fields):
        """Insert or update a published-service row. Unknown/None fields keep
        their previous value; created_at is set once, updated_at always bumps."""
        now = _iso(datetime.now(timezone.utc))
        cols = ("upstream", "target_ip", "dns_ok", "route_ok", "status", "error")
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM published_services WHERE hostname=?", (hostname,)).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO published_services"
                    "(hostname,upstream,target_ip,dns_ok,route_ok,status,error,created_at,updated_at)"
                    " VALUES(?,?,?,?,?,?,?,?,?)",
                    (hostname, fields.get("upstream", ""), fields.get("target_ip", ""),
                     int(fields.get("dns_ok", 0)), int(fields.get("route_ok", 0)),
                     fields.get("status", "pending"), fields.get("error"), now, now))
            else:
                sets, params = [], []
                for c in cols:
                    if c in fields:
                        sets.append(f"{c}=?"); params.append(fields[c])
                sets.append("updated_at=?"); params.append(now)
                params.append(hostname)
                conn.execute(
                    f"UPDATE published_services SET {','.join(sets)} WHERE hostname=?", params)
        return self.get_published_service(hostname)

    def get_published_service(self, hostname):
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM published_services WHERE hostname=?", (hostname,)).fetchone()
            return dict(row) if row else None

    def list_published_services(self):
        with self._conn() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM published_services ORDER BY created_at DESC").fetchall()]

    def delete_published_service(self, hostname):
        with self._conn() as conn:
            conn.execute("DELETE FROM published_services WHERE hostname=?", (hostname,))
