#!/usr/bin/env python3
"""Unattended maintenance tick for SuperSimpleCA.

Run periodically (e.g. from a systemd timer) as the service account:

    /opt/supersimpleca/webca/.venv/bin/python /opt/supersimpleca/webca/tick.py

It does everything the dashboard does on load, but without anyone visiting:
  • reconcile the mirror from index.txt
  • refresh expired status + raise expiry notifications
  • auto-delete archived certs (if enabled)
  • warn as the root CA approaches expiry
  • regenerate the CRL before it goes stale (when it can sign unattended:
    an unencrypted CA key, or the "persist across restart" passphrase), else
    raise a notification to unlock and regenerate.

Reuses the web app's wiring so configuration and paths are identical.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as webapp  # noqa: E402  (imports load config/ops, no server is started)


def main():
    ops = webapp.ops
    cfg = webapp.cfg
    if not ops.layout.is_ca_initialized():
        print("[tick] no CA initialized; nothing to do.")
        return 0

    notif = cfg.get("notifications", {})
    summary = []

    try:
        added = ops.reconcile_from_index()
        summary.append(f"reconciled +{added}")
    except Exception as e:  # noqa: BLE001
        summary.append(f"reconcile failed: {e}")

    try:
        ops.resync()
        n = ops.scan_expiry_notifications(webapp._default_notify_days())
        summary.append(f"expiry notices +{n}")
    except Exception as e:  # noqa: BLE001
        summary.append(f"expiry scan failed: {e}")

    arch = cfg.get("archive", {})
    if arch.get("auto_delete"):
        try:
            d = ops.auto_delete_archived(int(arch.get("delete_after_days", 90)))
            summary.append(f"auto-deleted {d}")
        except Exception as e:  # noqa: BLE001
            summary.append(f"auto-delete failed: {e}")

    try:
        ops.check_ca_expiry(int(notif.get("ca_expiry_warn_days", 60)))
        info = ops.root_ca_info()
        summary.append(f"CA {info['days_left']}d left")
    except Exception as e:  # noqa: BLE001
        summary.append(f"CA check failed: {e}")

    # CRL: use a passphrase only if one is available without a human — an
    # unencrypted key, or the persisted (machine-wrapped) passphrase.
    try:
        pw = None
        if ops.ca_key_encrypted():
            pw = webapp._load_persisted_passphrase()
        status = ops.check_crl(int(notif.get("crl_warn_days", 7)), pw)
        summary.append(f"CRL {status}")
    except Exception as e:  # noqa: BLE001
        summary.append(f"CRL check failed: {e}")

    print("[tick] " + "; ".join(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
