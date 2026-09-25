#!/usr/bin/env python3
"""Build the SQLite mirror (db/certificates.db) from an existing SuperSimpleCA.

Design principle: OpenSSL's index.txt is the source of truth for which
certificates exist and their valid/revoked state. For each entry we anchor on
the authoritative signed copy certs/<serial>.pem, parse it for dates/SANs/type,
and locate the matching private key on disk across the several naming
conventions this CA has used over time. The old JSON database is used only as a
fallback for the "issued" date.

Safe to re-run: it makes a fresh timestamped backup and rebuilds the mirror
(the mirror is derived data; the PKI files are never modified).
"""
import argparse
import json
import os
import sys
import tarfile
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paths import Layout
from certparse import parse_index, parse_certificate, find_key_for_cn
from store import CertStore


def backup(layout, dest_dir):
    os.makedirs(dest_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    archive = os.path.join(dest_dir, f"ca-backup-{stamp}.tar.gz")
    print(f"[*] Backing up CA to {archive} ...")
    with tarfile.open(archive, "w:gz") as tar:
        for item in ("ca", "certs", "crl", "db", "configs"):
            p = os.path.join(layout.root, item)
            if os.path.exists(p):
                tar.add(p, arcname=item, filter=_skip_wal)
    print("[*] Backup complete.")
    return archive


def _skip_wal(tarinfo):
    # Don't capture SQLite WAL side-files mid-write.
    if tarinfo.name.endswith((".db-wal", ".db-shm")):
        return None
    return tarinfo


def load_json_issued(layout):
    """serial -> issued ISO date, from the legacy JSON db if present."""
    issued = {}
    if os.path.exists(layout.json_db):
        try:
            with open(layout.json_db) as f:
                data = json.load(f)
            for serial, rec in data.items():
                if rec.get("issued"):
                    issued[serial] = rec["issued"]
        except (ValueError, OSError):
            pass
    return issued


def migrate(ca_root, backup_dir):
    layout = Layout(ca_root)
    if not layout.is_ca_initialized():
        print(f"[!] No CA found under {layout.root} (missing ca/ca.key.pem or ca.cert.pem).")
        return 1
    if not os.path.exists(layout.index):
        print(f"[!] No index.txt found at {layout.index}; nothing to migrate.")
        return 1

    backup(layout, backup_dir)
    layout.ensure_dirs()

    issued_map = load_json_issued(layout)
    rows = parse_index(layout.index)
    store = CertStore(layout.sqlite_db)

    now = datetime.now(timezone.utc)
    search_dirs = [layout.certs_dir, layout.revoked_dir]

    stats = {"valid": 0, "revoked": 0, "expired": 0, "no_cert_file": 0, "no_key": 0}
    print(f"[*] Migrating {len(rows)} index.txt entries ...")

    for row in rows:
        serial = row["serial"]
        cn = row["common_name"] or "(unknown)"
        cert_path = layout.cert_pem_for_serial(serial)
        details = parse_certificate(cert_path)

        if row["raw_status"] == "R":
            status = "revoked"
        elif row["expiry"] and row["expiry"] < now:
            status = "expired"
        else:
            status = "valid"

        issued_at = None
        sans, cert_type, subject = [], "unknown", row["subject"]
        if details:
            issued_at = details["not_before"]
            sans = details["sans"]
            cert_type = details["cert_type"]
            subject = details["subject"] or subject
        else:
            stats["no_cert_file"] += 1
        if issued_at is None:
            issued_at = issued_map.get(serial)

        key_path = find_key_for_cn(row["common_name"], search_dirs)
        if key_path is None and status == "valid":
            stats["no_key"] += 1

        store.upsert({
            "serial": serial,
            "common_name": cn,
            "cert_type": cert_type,
            "status": status,
            "subject": subject,
            "sans": sans,
            "issued_at": issued_at,
            "expires_at": row["expiry"],
            "revoked_at": row["revocation"],
            "cert_path": layout.rel(cert_path) if os.path.exists(cert_path) else None,
            "key_path": layout.rel(key_path) if key_path else None,
            "key_present": bool(key_path),
        })
        stats[status] = stats.get(status, 0) + 1

    store.set_meta("migrated_at", now.isoformat())
    store.set_meta("source", "index.txt")

    print("\n=== Migration summary ===")
    print(f"  Valid:   {stats['valid']}")
    print(f"  Revoked: {stats['revoked']}")
    print(f"  Expired: {stats['expired']}")
    if stats["no_cert_file"]:
        print(f"  [warn] {stats['no_cert_file']} entries had no certs/<serial>.pem on disk")
    if stats["no_key"]:
        print(f"  [warn] {stats['no_key']} VALID certs had no private key found on disk "
              f"(they can still be viewed/revoked/renewed; downloads of the key won't be available)")
    print(f"\n[*] SQLite mirror written to {layout.sqlite_db}")
    return 0


def main():
    default_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description="Migrate SuperSimpleCA JSON/index to SQLite mirror")
    ap.add_argument("--ca-root", default=default_root,
                    help=f"CA data root (default: {default_root})")
    ap.add_argument("--backup-dir", default=None,
                    help="Where to write the tar.gz backup (default: <ca-root>/backup)")
    args = ap.parse_args()
    backup_dir = args.backup_dir or os.path.join(args.ca_root, "backup")
    sys.exit(migrate(args.ca_root, backup_dir))


if __name__ == "__main__":
    main()
