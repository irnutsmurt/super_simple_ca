# SuperSimpleCA

**A self-hosted certificate authority for your homelab — with a web UI and a built-in ACME server.**

SuperSimpleCA started life as a single menu-driven script (`super_simple_ca.py`) that wraps
OpenSSL to run a private CA. It has since grown a full **web dashboard** and an **ACME server
(RFC 8555)**, so clients like Caddy, Traefik, Proxmox, certbot and acme.sh can request and
**auto-renew** certificates from it — no manual issuing, no copying PEM files around.

Use whichever fits you:

| | What it is | Best for |
|---|---|---|
| **CLI** (`super_simple_ca.py`) | Menu-driven / command-line OpenSSL CA manager | Quick start, scripting, headless boxes |
| **Web UI** (`webca/`) | Flask dashboard: issue / renew / revoke / download, notifications, publishing | Day-to-day management from a browser |
| **ACME server** (part of `webca/`) | RFC 8555 endpoint with http-01 + optional EAB | Hands-off auto-renewal for your services |

> **Status: `v0.9.0` (pre-1.0).** Fully usable in a homelab, but interfaces may still shift
> before 1.0. Feedback and issues welcome.

---

## Quick start — CLI

```bash
git clone https://github.com/irnutsmurt/super_simple_ca.git
cd super_simple_ca
chmod +x super_simple_ca.py

# Interactive menu
./super_simple_ca.py

# …or command line
./super_simple_ca.py init
./super_simple_ca.py create --type server --common-name service.example.com --validity-days 365
./super_simple_ca.py revoke --serial 1002
```

Requires **Python 3.6+** and **OpenSSL** on your PATH (the script offers to install OpenSSL on
Linux/macOS if it's missing). All state lives in this directory: `ca/`, `certs/`, `db/`, `crl/`,
and `configs/openssl.cnf`.

## Quick start — Web UI

The web UI operates **in place** on the same PKI the CLI creates (`index.txt` stays the source
of truth; a SQLite mirror is added for fast listing).

```bash
cd webca
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt

./.venv/bin/python setup.py             # config + admin password (offers to install as a service)
./.venv/bin/python migrate_to_sqlite.py # build the SQLite mirror from your existing CA (backs up first)
./.venv/bin/python app.py               # or ./run.sh
```

Then browse to `http://<host>:8443/`. A **first-run wizard** walks new installs through creating
the CA. **Full web documentation lives in [`webca/README.md`](webca/README.md).**

---

## Highlights

- **Passphrase-protected CA** — the key can be encrypted; the passphrase is entered in the
  browser and held only in server memory for the session, never written to disk.
- **Two-tier CA** — keep an offline, passphrase-protected **root** and an online **intermediate**
  that does all unattended ACME signing. Clients keep trusting the same root; the intermediate
  rides along in the chain. Migration from a single-tier CA is guided and preserves your root.
- **ACME server (RFC 8555)** — http-01 challenge, non-wildcard names, optional **External Account
  Binding (EAB)** to control who may enrol. Point Caddy/Proxmox/etc. at
  `https://<external_url>/acme/directory` and they auto-renew.
- **Service publishing** — optionally push issued certs to Caddy (admin API) or Pi-hole.
- **Notifications** — expiry warnings, failed-login alerts, and issue/revoke events in a top-bar bell.
- **Hardened by default** — single admin login, LAN-only access, IP allowlist, CSRF on every
  state-changing POST, login throttling, security headers + hardened cookies, CSP/HSTS over HTTPS.
- **Managed HTTPS** — the CA can issue and **auto-renew** its own web/ACME TLS cert.
- **Unattended upkeep** — `tick.py` (systemd timer) handles expiry alerts, auto-delete, and CRL
  refresh without a human.

## Security model (short version)

- ACME issues certificates without a human, so the signing key must be usable **unattended** —
  either unencrypted, or via the intermediate in a **two-tier** setup (recommended), or with
  "keep unlocked across restarts" enabled. A locked CA fails issuance with a clear error.
- The web UI is **LAN-only** and refuses public source IPs. It uses `remote_addr` directly (no
  `X-Forwarded-For` trust) — run it without a reverse proxy, or do IP restriction in the proxy
  (e.g. Caddy `remote_ip`) and let the proxy terminate TLS.
- The unlock vault is **in-process** — run a **single worker** (the built-in `app.py` uses
  `threaded=True`, one process). Don't put it behind multi-process gunicorn as-is.

See [`webca/README.md`](webca/README.md) for the full security model, ACME setup (including the
"don't route ACME through the same Caddy that depends on it" gotcha), EAB, and deployment.

## Roadmap

- **Container image** — an official Docker image published to GitHub Container Registry (GHCR) via
  GitHub Actions, for folks who prefer to run it as a container.
- Additional ACME challenge types.

## License

MIT — see [`LICENSE`](LICENSE).

---

*Issues and pull requests welcome. This is a homelab project; use it at your own risk and keep
offline backups of your root key.*
