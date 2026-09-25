# SuperSimpleCA

**A self-hosted certificate authority for your homelab, with a web UI and a built-in ACME server.**

SuperSimpleCA started life as a single menu-driven script (`super_simple_ca.py`) that wraps
OpenSSL to run a private CA. It has since grown a full **web dashboard** and an **ACME server
(RFC 8555)**, so clients like Caddy, Traefik, Proxmox, certbot and acme.sh can request and
**auto-renew** certificates from it. No manual issuing, no copying PEM files around.

Use whichever fits you:

| | What it is | Best for |
|---|---|---|
| **CLI** (`super_simple_ca.py`) | Menu-driven / command-line OpenSSL CA manager | Quick start, scripting, headless boxes |
| **Web UI** (`webca/`) | Flask dashboard: issue / renew / revoke / download, notifications, publishing | Day-to-day management from a browser |
| **ACME server** (part of `webca/`) | RFC 8555 endpoint with http-01 and optional EAB | Hands-off auto-renewal for your services |

The web UI operates **in place** on the same PKI the CLI creates (`ca/`, `certs/`, `db/index.txt`,
`serial`, `crl/`, `configs/openssl.cnf`). OpenSSL's `index.txt` stays the source of truth; a SQLite
mirror (`db/certificates.db`) is added for fast, filterable listing in the UI.

> **Status: `v0.9.0` (pre-1.0).** Fully usable in a homelab, but interfaces may still shift
> before 1.0. Feedback and issues welcome.

---

## Quick start: CLI

```bash
git clone https://github.com/irnutsmurt/super_simple_ca.git
cd super_simple_ca
chmod +x super_simple_ca.py

# Interactive menu
./super_simple_ca.py

# ...or command line
./super_simple_ca.py init
./super_simple_ca.py create --type server --common-name service.example.com --validity-days 365
./super_simple_ca.py revoke --serial 1002
```

Requires **Python 3.6+** and **OpenSSL** on your PATH (the script offers to install OpenSSL on
Linux/macOS if it is missing). All state lives in this directory: `ca/`, `certs/`, `db/`, `crl/`,
and `configs/openssl.cnf`.

## Quick start: Web UI

All web-UI commands run from the `webca/` directory:

```bash
cd webca
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt

# 1. Create config + set the web-UI admin password
./.venv/bin/python setup.py

# 2. Build the SQLite mirror from your existing CA (backs up first)
./.venv/bin/python migrate_to_sqlite.py

# 3. Run it
./.venv/bin/python app.py     # or: ./run.sh
```

Then browse to `http://<host>:8443/`. A **first-run wizard** walks new installs through creating
the CA.

## Quick start: Docker

A container image is published to the GitHub Container Registry. All state (config, CA keys,
certificates, database, secrets) lives on the `/data` volume, so back that volume up.

```bash
docker run -d --name supersimpleca \
  -e SSCA_ADMIN_PASSWORD='change-me-on-first-run' \
  -v ssca_data:/data \
  -p 8443:8443 \
  ghcr.io/irnutsmurt/super_simple_ca:latest
```

Or with Compose (see `docker-compose.yml`):

```bash
docker compose up -d
```

Then browse to `http://<host>:8443/` and sign in with the password you set.

**First-run environment variables** (only needed the first time; the app writes them into
`/data/config.yaml`, after which you can remove them):

| Variable | Purpose |
|----------|---------|
| `SSCA_ADMIN_PASSWORD` | **Required on first run.** Sets the web-UI admin password (stored hashed). |
| `SSCA_SECURE_COOKIES` | `true` when serving over HTTPS or behind a proxy. |
| `SSCA_WEB_SANS` | Space/comma-separated names/IPs for SSCA-managed TLS, e.g. `ca.example.com 192.168.1.10`. |
| `SSCA_HOST` / `SSCA_PORT` | Override the listen address/port (default `0.0.0.0:8443`). |

The container runs a single, non-root process (the CA-unlock vault is in memory, so do not scale it
to multiple replicas). Notes:

- **Importing an existing CA:** mount your existing CA directory as `/data` and build the SQLite
  mirror once with `docker exec supersimpleca python migrate_to_sqlite.py`.
- **ACME http-01** is answered by your ACME *client* (e.g. Caddy), not this container, so no extra
  port is needed here beyond the web/ACME endpoint.

## Highlights

- **Passphrase-protected CA.** The key can be encrypted; the passphrase is entered in the
  browser and held only in server memory for the session, never written to disk.
- **Two-tier CA.** Keep an offline, passphrase-protected **root** and an online **intermediate**
  that does all unattended ACME signing. Clients keep trusting the same root; the intermediate
  rides along in the chain. Migration from a single-tier CA is guided and preserves your root.
- **ACME server (RFC 8555).** http-01 challenge, non-wildcard names, optional **External Account
  Binding (EAB)** to control who may enrol.
- **Service publishing.** Optionally push issued certs to Caddy (admin API) or Pi-hole.
- **Notifications.** Expiry warnings, failed-login alerts, and issue/revoke events in a top-bar bell.
- **Hardened by default.** Single admin login, LAN-only access, IP allowlist, CSRF on every
  state-changing POST, login throttling, security headers, hardened cookies, and CSP/HSTS over HTTPS.
- **Managed HTTPS.** The CA can issue and **auto-renew** its own web/ACME TLS cert.
- **Unattended upkeep.** `tick.py` (systemd timer) handles expiry alerts, auto-delete, and CRL refresh.

---

## Security model

- **Web login**: single admin password (hashed with Werkzeug/PBKDF2, stored in `config.yaml`).
  Set/reset it with `setup.py`.
- **LAN-only**: external/public source IPs are always refused. Optionally list specific private IPs
  or CIDR ranges in `ip_allowlist`; non-private entries are ignored with a warning. `remote_addr` is
  used directly (no `X-Forwarded-For` trust), so run without a reverse proxy, or add proxy handling
  before trusting it.
- **Single worker**: the CA-unlock passphrase lives in a per-process, in-memory vault keyed by a
  random session token; it never touches disk or the cookie and expires after
  `ca_unlock_timeout_minutes` of idle time. Because the vault is in-process, run **one process**
  (the built-in `app.py` uses `threaded=True`). Don't put it behind multi-process gunicorn without
  moving the vault to a shared store.
- **CA passphrase**: when the CA key is encrypted, signing/revoking/renewing require an in-browser
  *unlock*.
- **Restart behavior**: Settings → *When the service restarts* (config `on_restart`) controls what
  happens to the CA unlock across a restart: `relogin` (default) invalidates sessions so signing in
  again re-unlocks the CA; `keep` leaves you signed in to re-unlock when needed; `persist` keeps the
  CA unlocked with no interaction by storing the passphrase at rest under a machine-local key in
  `instance/persist.key` (least secure, anyone who can read the app's files can recover it).
  Changing/removing the CA passphrase clears the persisted copy.
- **CA auto-unlock (optional)**: Settings → *CA auto-unlock* lets you store the CA passphrase
  encrypted with a key derived (scrypt) from your **login password**, so signing in unlocks the CA
  automatically and you never retype it. Only the wrapped blob + a random salt are stored (in
  `certificates.db`); they are useless without the login password, which is never stored in
  cleartext. The tradeoff: security now rests on login-password strength, so **use a strong one** (a
  stolen DB/backup could be brute-forced offline if it is weak). Changing the login password re-wraps
  automatically; changing/removing the CA passphrase disables auto-unlock (re-enable it afterwards).
  This is strictly better than storing the passphrase in plaintext, which is intentionally *not* offered.
- **HTTPS**: Settings → *Web-UI TLS* offers three modes: **http**, **manual** (`tls_cert`/`tls_key`
  files you provide and renew), or **SSCA-managed**, where the CA issues a cert for its own endpoint
  and **auto-renews** it (writing `instance/web.crt`/`web.key` and restarting itself to reload).
  Managed mode is the clean way to serve the UI over HTTPS *and* expose the ACME directory over TLS
  without the bootstrap loop below: reach SSCA directly and it keeps its own cert renewed with no
  manual work. Managed mode needs the CA initialized and signable unattended (same as ACME). Changing
  the mode takes effect on the next restart (TLS is bound at startup).
- **CSRF** tokens protect every state-changing POST. **Login throttling** locks an IP after repeated
  failures (`login_throttle`). **Security headers** (`X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`) and hardened session cookies (`HttpOnly`, `SameSite=Lax`, and `Secure` when
  `secure_cookies: true`) are set on every response.

## Notifications and alerts

A bell in the top bar collects notifications: certificates approaching expiry, expired certificates,
failed sign-in attempts, and cert issued/revoked events. Each certificate can set its own expiry lead
time on its detail page, otherwise the global default (Settings → Notifications,
`notifications.default_notify_days`) applies. Expiry is scanned on dashboard load (de-duplicated, so
it's cheap). The unread badge refreshes live, and every form submit / navigation shows a top progress
bar so long actions (key generation, signing) give visible feedback.

## Archiving and deleting certificates

- **Archive** hides a certificate from your lists without touching the CA (reversible with
  *Unarchive*). Archived certs live under the *Archived* tab.
- **Delete** removes it from the app: the row is dropped and tombstoned (so the self-healing
  reconcile won't re-add it) and the on-disk key/CSR/cert files move to `certs/revokedcerts/`. It does
  **not** rewrite `index.txt` (the CA ledger), and it does **not** revoke; a still-valid cert stays
  trusted until you revoke it.
- **Auto-delete** (Settings → Maintenance → Archived certificates) deletes archived certs after a
  configurable number of days.
- **Renew** is available on expired certs too (it re-issues and archives the old expired entry; for a
  valid cert it revokes the old one as before).

## ACME server (RFC 8555)

SuperSimpleCA can act as an ACME certificate authority, so clients like **Caddy**, Traefik, certbot
or acme.sh request and **auto-renew** certificates from it with no manual issuing. Phase 1 supports
the **http-01** challenge for non-wildcard names.

**Enable it** in Settings → ACME (or `config.yaml`):

- `enabled: true`
- `external_url`, the HTTPS address clients use, e.g. `https://ca.example.com`
- `allowed_domains`, restrict issuance (e.g. `["example.com"]`); empty = any
- `validity_days` / `max_validity_days`, `http01_port` (80), `manage_in_ui`

**Prerequisite: unattended signing.** ACME issues without a human, so the CA key must be usable
unattended: either **unencrypted**, via the intermediate in a **two-tier** setup (recommended), or
with **"keep unlocked across restarts"** enabled (Settings → CA key). A locked CA returns a clear
error and issuance fails.

**Reachability.** For http-01 the server fetches
`http://<name>/.well-known/acme-challenge/<token>` from the client, so your internal DNS must resolve
the name to the client and the client must serve that path on `http01_port` (Caddy does this
automatically). Serve the ACME endpoint itself over HTTPS (via Caddy) with a cert clients trust
(issued by this CA, since your root is already installed).

**Point Caddy at it** (global options):

```caddy
{
    acme_ca https://ca.example.com/acme/directory
}
service.example.com {
    reverse_proxy 127.0.0.1:8096
}
```

Caddy registers an account, answers http-01, and renews automatically. ACME-issued certs appear in
the dashboard tagged **ACME** (the client holds the key, so they're renewed by the client, not from
this UI; `manage_in_ui` controls whether you can still revoke/archive/delete them here).

Directory: `https://<external_url>/acme/directory`.

> **Important: don't route ACME through the same Caddy that depends on it.**
> If this CA's web UI is itself reverse-proxied by the Caddy that enrols against it
> (e.g. `acme_ca https://ca.example.com/...` where `ca.example.com` is a Caddy site),
> you create a bootstrap loop: Caddy needs to reach the CA to renew certs, but reaching the CA goes
> *through Caddy* and depends on Caddy already being up with a valid cert. A restart or an expired
> cert can deadlock it.
>
> Point Caddy at SSCA **directly by IP**, bypassing the proxy, and set SSCA's `external_url` to match
> (the directory advertises absolute URLs built from it, so both sides must be the direct address or
> you loop right back through the hostname):
>
> ```caddy
> {
>     acme_ca http://192.168.1.10:8081/acme/directory   # SSCA's own host:port, not the Caddy vhost
> }
> ```
> and in Settings → ACME set `external_url` to `http://192.168.1.10:8081`. Plain HTTP on a trusted
> LAN is fine here, since ACME messages are JWS-signed, so integrity and authentication don't depend
> on TLS. You can still keep a nice `ca.example.com` vhost for *browser* access to the dashboard; only
> the machine-to-machine ACME endpoint needs the direct address.

**Restricting who can enrol (EAB).** By default any client that can reach the ACME endpoint (subject
to the IP allowlist and `allowed_domains`) can obtain certs. To require a per-client credential,
enable **External Account Binding** (Settings → ACME → *Require External Account Binding*). Generate a
credential there (you get a **key ID** and **MAC key**) and paste it into the client. Revoke it to cut
that client off (already-issued certs keep working until they expire). In Caddy:

```caddy
{
    acme_ca https://ca.example.com/acme/directory
    acme_eab {
        key_id  <key-id-from-settings>
        mac_key <mac-key-from-settings>
    }
}
```

EAB gates *who may request* certificates; it does not change the CA-key-at-rest requirement (the CA
still signs unattended, unencrypted or via the intermediate/persist mode).

## Unattended maintenance (tick.py)

Expiry alerts, auto-delete, root-CA expiry warnings and CRL refresh normally run when the dashboard
is loaded. `tick.py` runs the same upkeep unattended:

```bash
./.venv/bin/python tick.py
```

`install.sh` installs a systemd timer (`<service>-tick.timer`, every ~6h) that runs it as the service
account. The CRL is regenerated automatically only when it can sign without a human (an unencrypted CA
key, or the "persist across restart" passphrase); otherwise `tick.py` raises a notification to unlock
and regenerate. The **CA** tab shows the root cert's validity/fingerprint and CRL freshness.

## Deploying updates

Use `deploy.sh` to push code to the server without disturbing its runtime state:

```bash
./deploy.sh user@host:/opt/supersimpleca/webca            # rsync + restart
./deploy.sh user@host:/opt/supersimpleca/webca --dry-run  # preview
```

It excludes `.venv/`, `instance/`, `config.yaml` and the SQLite db/backups, then restarts the service
over SSH.

## Deploying as a service (systemd + Caddy)

`install.sh` sets the app up as a hardened systemd service under a dedicated, no-login system account:

```bash
sudo ./install.sh            # create account, venv, fix ownership, install unit
# or run setup.py first; it offers to run install.sh for you when done.
sudo ./install.sh uninstall  # stop, disable and remove the service
```

It detects its own directory and the CA data root (from `config.yaml`'s `ca_root`, else the parent
dir), `chown`s the CA tree to the service account, tightens permissions, and writes
`/etc/systemd/system/supersimpleca.service`. Override with `SERVICE_NAME=`, `SERVICE_USER=`,
`CA_ROOT=` env vars. A copied-but-broken `.venv` (wrong host/arch) is detected and rebuilt.

**TLS via Caddy.** Set `host: 127.0.0.1` in `config.yaml` and let Caddy terminate HTTPS and
reverse-proxy to it. **Important:** behind a proxy the app sees every request as coming from
`127.0.0.1`, so its `ip_allowlist` can't identify real clients; do LAN/IP restriction in Caddy instead:

```caddy
ca.example.lan {
    @lan remote_ip 192.168.1.0/24
    handle @lan { reverse_proxy 127.0.0.1:8443 }
    respond 403
}
```

```
systemctl status supersimpleca      # check
journalctl -u supersimpleca -f      # logs
```

## Configuration

See `webca/config.example.yaml`. Key options: `host`, `port`, `tls_cert`/`tls_key`, `ip_allowlist`,
`session_timeout_minutes`, `ca_unlock_timeout_minutes`, and `cert_defaults`.

## Repository layout

| Path | Purpose |
|------|---------|
| `super_simple_ca.py` | The standalone CLI CA manager |
| `configs/openssl.cnf` | OpenSSL CA configuration template |
| `webca/app.py` | Flask app and routes |
| `webca/ca_ops.py` | OpenSSL operations (init/issue/revoke/renew/CRL, passphrase mgmt) |
| `webca/acme*.py` | ACME server (directory, orders, challenges, validation) |
| `webca/store.py` | SQLite mirror |
| `webca/certparse.py` | index.txt and X.509 parsing |
| `webca/paths.py` | CA directory layout |
| `webca/auth.py` | login, IP allowlist, CA-unlock vault |
| `webca/config.py` | config + secrets |
| `webca/publish.py`, `caddyadmin.py`, `pihole.py` | service publishing |
| `webca/migrate_to_sqlite.py` | one-time (re-runnable) mirror build, with backup |
| `webca/setup.py` | first-run config + admin password (offers to run `install.sh`) |
| `webca/install.sh` | create service account, fix perms, install systemd unit |

## Notes on your data

The migration treats `index.txt` as authoritative: each entry is anchored on the signed copy
`certs/<serial>.pem`, parsed for dates/SANs/type, and matched to its private key across the naming
conventions this CA has used (`<cn>.key`, `<cn>.key.pem`). Entries whose expiry has passed are shown
as **expired** (not lumped in with valid). If a valid cert's private key can't be found on disk, it
still lists/views/revokes/renews; only the key download is unavailable.

To rebuild the mirror later (e.g. after CLI changes), use **Settings → Re-sync** or re-run
`migrate_to_sqlite.py`. Both take a fresh backup first.

## Roadmap

- Additional ACME challenge types (e.g. dns-01, wildcard support).
- A step-by-step wiki aimed at users who are new to PKI.

## License

MIT. See [`LICENSE`](LICENSE).

---

*Issues and pull requests welcome. This is a homelab project; use it at your own risk and keep
offline backups of your root key.*
