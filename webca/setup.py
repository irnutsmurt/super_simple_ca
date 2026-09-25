#!/usr/bin/env python3
"""First-run setup: create config.yaml and set the web-UI admin password.

    python3 setup.py

Re-running lets you reset the password; existing config values are preserved.
"""
import getpass
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import config as configmod
from werkzeug.security import generate_password_hash


def main():
    cfg = configmod.load_config()
    print("SuperSimpleCA web UI setup")
    print("-" * 40)
    print(f"CA data root: {cfg['ca_root']}")
    if not os.path.exists(os.path.join(cfg["ca_root"], "ca", "ca.cert.pem")):
        print("  (note) no CA found there yet — you can initialize one from the web UI.")

    while True:
        p1 = getpass.getpass("Set web-UI admin password: ")
        if len(p1) < 6:
            print("  Please use at least 6 characters.")
            continue
        p2 = getpass.getpass("Confirm password: ")
        if p1 != p2:
            print("  Passwords do not match, try again.")
            continue
        break

    cfg.setdefault("auth", {})["password_hash"] = generate_password_hash(p1)
    configmod.save_config(cfg)
    configmod.get_flask_secret()  # generate the Flask secret now

    print("\nSaved config to", cfg["_path"])
    print("A Flask session secret was generated in ./instance/")

    _offer_service_install()

    print("\nNext:")
    print("  1. (once) python3 migrate_to_sqlite.py     # build the SQLite mirror")
    print("  2.        python3 app.py                    # start the web UI (or use the service)")
    print(f"\nThen browse to  http://<this-host>:{cfg['port']}/")


def _offer_service_install():
    """Optionally hand off to install.sh to create the account + systemd service."""
    installer = os.path.join(HERE, "install.sh")
    if not os.path.exists(installer):
        return
    ans = input("\nInstall this as a systemd service now (creates a service account,\n"
                "  sets ownership/permissions, installs the unit; needs sudo)? [y/N] ").strip().lower()
    if ans not in ("y", "yes"):
        print("  Skipped. You can run it later with:  sudo ./install.sh")
        return
    cmd = ["bash", installer] if os.geteuid() == 0 else ["sudo", "bash", installer]
    try:
        subprocess.call(cmd)
    except KeyboardInterrupt:
        print("\n  Service install cancelled.")


if __name__ == "__main__":
    main()
