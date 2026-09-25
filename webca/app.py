#!/usr/bin/env python3
"""SuperSimpleCA web UI — a Flask front-end for the OpenSSL certificate authority.

Run with:  python3 app.py   (after running setup.py once)
The CA passphrase is entered in the browser and held only in server memory for
the session; it is never written to disk. See auth.py for details.
"""
import io
import ipaddress
import os
import re
import subprocess
import sys

from flask import (Flask, render_template, request, redirect, url_for, flash,
                   session, send_file, abort, Response, jsonify)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import acme
import acme_store as acme_store_mod
import pihole
import caddyadmin
import publish as publishmod
import auth
import ca_ops
import config as configmod
import crypto
from ca_ops import CaOps, CaError

cfg = configmod.load_config()
ops = CaOps(cfg["ca_root"], defaults=cfg["cert_defaults"])
ALLOWLIST_NETS, ALLOWLIST_REJECTED = auth.parse_allowlist(cfg.get("ip_allowlist"))

# The openssl.cnf holds absolute paths; regenerate it so it always matches the
# current CA root (e.g. after the CA directory is moved to a new location).
if ops.layout.is_ca_initialized():
    try:
        ops.write_openssl_conf()
    except OSError as _e:
        print(f"[warning] could not regenerate openssl.cnf: {_e}", file=sys.stderr)


# --------------------------------------------- persist-across-restart storage
PERSIST_BLOB = "persist_blob"

def _machine_key():
    """Load (or create) the machine-local key that wraps the persisted passphrase."""
    path = configmod.PERSIST_KEY_PATH
    os.makedirs(configmod.INSTANCE_DIR, exist_ok=True)
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read().strip()
    key = crypto.new_machine_key()
    with open(path, "wb") as f:
        f.write(key)
    os.chmod(path, 0o600)
    return key

def _load_persisted_passphrase():
    blob = ops.store.get_meta(PERSIST_BLOB)
    if not blob or not os.path.exists(configmod.PERSIST_KEY_PATH):
        return None
    return crypto.machine_unwrap(_machine_key(), blob)

def _persist_passphrase(ca_pass):
    ops.store.set_meta(PERSIST_BLOB, crypto.machine_wrap(_machine_key(), ca_pass))

def _persist_enabled():
    return bool(ops.store.get_meta(PERSIST_BLOB))

def _clear_persisted_passphrase():
    ops.store.set_meta(PERSIST_BLOB, None)
    try:
        os.remove(configmod.PERSIST_KEY_PATH)
    except OSError:
        pass
    auth.clear_global_passphrase()


# --------------------------------------------- Phase 4: service auto-publish
def _pihole_pw_key(base_url):
    return f"publish_pw::{base_url}"

def _pihole_password(base_url):
    blob = ops.store.get_meta(_pihole_pw_key(base_url))
    return crypto.machine_unwrap(_machine_key(), blob) if blob else None

def _set_pihole_password(base_url, pw):
    ops.store.set_meta(_pihole_pw_key(base_url),
                       crypto.machine_wrap(_machine_key(), pw) if pw else None)

def _publish_cfg():
    return cfg.get("publish", {}) or {}

def _pihole_list():
    return _publish_cfg().get("piholes") or []

def _piholes():
    out = []
    for p in _pihole_list():
        url = p.get("base_url")
        if url:
            out.append(pihole.PiholeClient(url, _pihole_password(url),
                                           verify_tls=bool(p.get("verify_tls", False))))
    return out

def _piholes_status():
    """[(base_url, verify_tls, pw_set), ...] for the settings UI."""
    return [(p.get("base_url", ""), bool(p.get("verify_tls")),
             bool(_pihole_password(p.get("base_url", "")))) for p in _pihole_list()]

def _make_caddy():
    cd = _publish_cfg().get("caddy", {}) or {}
    return caddyadmin.CaddyClient(cd.get("admin_url", ""), https_port=cd.get("https_port", 443))

def _revoke_cert_for_host(host):
    """Revoke the ACME certificate issued for a published host (used on
    unpublish). Returns the serial, or None if there's no ACME cert. Raises if
    the CA can't sign unattended or revocation fails."""
    cert = ops.store.find_valid_by_host(host)
    if not cert or (cert.get("source") or "") != "acme":
        return None
    pw = _acme_ca_passphrase()
    if ops.ca_key_encrypted() and pw is None:
        raise RuntimeError("the CA key is locked (needs an unencrypted key or persist mode).")
    ops.revoke(cert["serial"], pw)
    return cert["serial"]

def _make_publisher():
    return publishmod.Publisher(ops.store, _piholes(), _make_caddy(),
                                cert_revoker=_revoke_cert_for_host)

def _publish_ready():
    p = _publish_cfg()
    has_pihole = any(ph.get("base_url") and _pihole_password(ph["base_url"])
                     for ph in _pihole_list())
    return bool(p.get("enabled") and p.get("target_ip") and has_pihole
                and (p.get("caddy") or {}).get("admin_url"))


app = Flask(__name__)
app.secret_key = configmod.get_flask_secret()
app.permanent_session_lifetime = __import__("datetime").timedelta(
    minutes=cfg["session_timeout_minutes"])
# Mark the session cookie Secure whenever the UI is served over HTTPS — either
# SSCA serves its own TLS (managed/manual web_tls) or it sits behind a TLS proxy
# (set secure_cookies=true for that case). Prevents the cookie leaking over HTTP.
_serving_https = (cfg.get("web_tls", {}).get("mode") in ("managed", "manual")
                  or bool(cfg.get("tls_cert")))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(cfg.get("secure_cookies")) or _serving_https,
)

# ACME server (RFC 8555): JWS-authenticated API blueprint. Reachable on the LAN
# (IP allowlist still applies) but exempt from the web-UI login + CSRF.
ACME_STORE = acme_store_mod.AcmeStore(ops.layout.sqlite_db)
ACME_NONCES = acme_store_mod.NonceStore(ttl_seconds=3600)

def _acme_ca_passphrase():
    """CA passphrase available to unattended ACME signing, or None.

    None when the CA key is unencrypted (signable as-is) or when it's locked
    (acme.py distinguishes these via ops.ca_key_encrypted()).
    """
    if not ops.ca_key_encrypted():
        return None
    return _load_persisted_passphrase()

app.register_blueprint(
    acme.create_acme_blueprint(cfg, ACME_STORE, ACME_NONCES, ops,
                               passphrase_provider=_acme_ca_passphrase),
    url_prefix="/acme")

if (cfg.get("acme", {}).get("enabled") and ops.layout.is_ca_initialized()
        and ops.ca_key_encrypted() and not _persist_enabled()):
    print("[warning] ACME is enabled but the CA key is locked; issuance will fail until you use "
          "an unencrypted key or enable persist-across-restart.", file=sys.stderr)

# A new random token each time the process starts. With on_restart="relogin",
# sessions stamped with an older token are treated as logged out — so a restart
# forces a fresh sign-in (which, with auto-unlock, re-unlocks the CA).
import secrets as _secrets  # noqa: E402
INSTANCE_TOKEN = _secrets.token_hex(8)

# With on_restart="persist", load the machine-key-wrapped CA passphrase now so
# the CA is unlocked for everyone immediately after a restart.
if cfg.get("on_restart") == "persist" and ops.layout.is_ca_initialized() and ops.ca_key_encrypted():
    _p = _load_persisted_passphrase()
    if _p and ops.verify_passphrase(_p):
        auth.set_global_passphrase(_p)
        print("[*] CA passphrase restored from persisted store.", file=sys.stderr)
    elif _p:
        print("[warning] persisted CA passphrase no longer valid; ignoring.", file=sys.stderr)


# --------------------------------------------- Web-UI TLS (self-managed cert)
WEB_CERT_PATH = os.path.join(configmod.INSTANCE_DIR, "web.crt")
WEB_KEY_PATH = os.path.join(configmod.INSTANCE_DIR, "web.key")

def _web_cfg():
    return cfg.get("web_tls", {}) or {}

def _web_cert_fresh():
    """True if the managed web cert exists, covers the configured SANs, and is
    not within the renew window."""
    if not (os.path.exists(WEB_CERT_PATH) and os.path.exists(WEB_KEY_PATH)):
        return False
    try:
        from cryptography import x509 as _x
        import datetime as _dt
        cert = _x.load_pem_x509_certificate(open(WEB_CERT_PATH, "rb").read())
        renew = int(_web_cfg().get("renew_before_days", 30))
        if cert.not_valid_after_utc <= _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=renew):
            return False
        want = {s.strip().lower() for s in (_web_cfg().get("sans") or []) if s.strip()}
        san = cert.extensions.get_extension_for_class(_x.SubjectAlternativeName).value
        have = {n.lower() for n in san.get_values_for_type(_x.DNSName)}
        have |= {str(i) for i in san.get_values_for_type(_x.IPAddress)}
        return bool(want) and want.issubset(have)
    except Exception:  # noqa: BLE001
        return False

def _ensure_web_cert():
    """Issue/renew the managed web cert if needed. Returns (cert, key) paths, or
    None if it can't (CA not initialized / locked and no existing cert)."""
    if _web_cert_fresh():
        return (WEB_CERT_PATH, WEB_KEY_PATH)
    have = os.path.exists(WEB_CERT_PATH) and os.path.exists(WEB_KEY_PATH)
    if not ops.layout.is_ca_initialized():
        print("[web-tls] CA not initialized; cannot issue the web cert.", file=sys.stderr)
        return (WEB_CERT_PATH, WEB_KEY_PATH) if have else None
    pw = _acme_ca_passphrase()
    if ops.ca_key_encrypted() and pw is None:
        print("[web-tls] CA key is locked; keeping the existing web cert.", file=sys.stderr)
        return (WEB_CERT_PATH, WEB_KEY_PATH) if have else None
    try:
        serial = ops.issue_web_cert(_web_cfg().get("sans") or [],
                                    int(_web_cfg().get("validity_days", 825)),
                                    pw, WEB_CERT_PATH, WEB_KEY_PATH)
        print(f"[web-tls] issued/renewed web endpoint cert (serial {serial}).", file=sys.stderr)
        return (WEB_CERT_PATH, WEB_KEY_PATH)
    except Exception as e:  # noqa: BLE001
        print(f"[web-tls] could not issue web cert: {e}", file=sys.stderr)
        return (WEB_CERT_PATH, WEB_KEY_PATH) if have else None

def _web_tls_context():
    """ssl_context tuple for app.run(), or None for plain HTTP."""
    mode = _web_cfg().get("mode", "http")
    if mode == "managed":
        return _ensure_web_cert()
    if cfg.get("tls_cert") and cfg.get("tls_key"):   # manual, or legacy config
        return (cfg["tls_cert"], cfg["tls_key"])
    if mode == "manual":
        print("[web-tls] manual mode but tls_cert/tls_key are not set; serving HTTP.", file=sys.stderr)
    return None

def _start_web_cert_maintainer():
    """Background renew + self-restart so the managed web cert never lapses."""
    import threading
    import time as _time

    def loop():
        try:
            loaded = os.path.getmtime(WEB_CERT_PATH)
        except OSError:
            loaded = 0
        while True:
            _time.sleep(3600)
            try:
                if not _web_cert_fresh():
                    _ensure_web_cert()
                cur = os.path.getmtime(WEB_CERT_PATH) if os.path.exists(WEB_CERT_PATH) else 0
                if cur and cur != loaded:
                    print("[web-tls] web cert renewed — restarting to reload TLS.", file=sys.stderr)
                    os.execv(sys.executable, [sys.executable] + sys.argv)
            except Exception as e:  # noqa: BLE001
                print(f"[web-tls] maintainer error: {e}", file=sys.stderr)
    threading.Thread(target=loop, daemon=True).start()


# ------------------------------------------------------------- request gating
@app.before_request
def _gate():
    if request.endpoint == "static":
        return
    ok, reason = auth.ip_permitted(ALLOWLIST_NETS)
    if not ok:
        app.logger.warning("Blocked request from %s: %s", request.remote_addr, reason)
        return render_template("denied.html", reason=reason), 403
    # ACME endpoints authenticate via JWS, not the web session: skip login + CSRF
    # for them (they remain behind the IP allowlist checked above).
    if request.blueprint == "acme":
        return
    # Force re-login after a restart when configured to do so.
    if (cfg.get("on_restart") == "relogin" and auth.is_logged_in()
            and session.get("inst") != INSTANCE_TOKEN):
        auth.do_logout()
    # CSRF: validate on all state-changing requests (bypassed under app.testing).
    if (not app.testing and request.method in ("POST", "PUT", "PATCH", "DELETE")
            and not auth.csrf_valid()):
        return render_template("denied.html",
                               reason="Request rejected (invalid or missing CSRF token). "
                                      "Reload the page and try again."), 400
    open_endpoints = {"login", "static"}
    if cfg["require_login"] and not auth.is_logged_in() and request.endpoint not in open_endpoints:
        return redirect(url_for("login", next=request.path))


@app.after_request
def _security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers.setdefault("Cache-Control", "no-store")
    # Self-contained app (no CDNs). 'unsafe-inline' is needed for the inline
    # <style>/<script> blocks and style="" attributes in the templates; data:
    # covers inline favicon/images. frame-ancestors backs up X-Frame-Options.
    resp.headers.setdefault("Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'; form-action 'self'")
    # HSTS only over real HTTPS (SSCA-served TLS, or a proxy that sets X-Forwarded-Proto).
    if request.is_secure:
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return resp


@app.context_processor
def _inject():
    unread, recent = 0, []
    if auth.is_logged_in() and os.path.exists(ops.layout.sqlite_db):
        try:
            unread = ops.store.unread_count()
            recent = ops.store.notifications(limit=8)
        except Exception:  # noqa: BLE001
            pass
    return {
        "ca_initialized": ops.layout.is_ca_initialized(),
        "ca_encrypted": ops.ca_key_encrypted() if ops.layout.is_ca_initialized() else False,
        "ca_unlocked": auth.is_unlocked(),
        "counts": ops.store.counts() if os.path.exists(ops.layout.sqlite_db) else
                  {"valid": 0, "revoked": 0, "expired": 0, "total": 0},
        "notif_unread": unread,
        "notif_recent": recent,
        "csrf_token": auth.csrf_token(),
    }


# --------------------------------------------------------------------- auth
@app.route("/login", methods=["GET", "POST"])
def login():
    if not cfg["require_login"]:
        auth.do_login()
        return redirect(url_for("dashboard"))
    thr = cfg.get("login_throttle", {})
    ip = request.remote_addr or "?"
    if request.method == "POST":
        wait = auth.login_blocked(ip, thr.get("max_fails", 5),
                                  thr.get("window_seconds", 300), thr.get("lock_seconds", 300))
        if wait:
            flash(f"Too many failed attempts. Try again in {wait} seconds.", "error")
            return render_template("login.html", configured=bool(cfg["auth"].get("password_hash")))
        pw = request.form.get("password", "")
        if auth.verify_password(cfg["auth"].get("password_hash"), pw):
            auth.clear_login_failures(ip)
            auth.do_login()
            session["inst"] = INSTANCE_TOKEN
            if _try_autounlock(pw):
                flash("Signed in — CA auto-unlocked.", "ok")
            nxt = request.args.get("next") or url_for("dashboard")
            return redirect(nxt)
        locked_until = auth.record_login_failure(
            ip, thr.get("max_fails", 5), thr.get("window_seconds", 300), thr.get("lock_seconds", 300))
        if cfg.get("notifications", {}).get("login_alerts", True):
            try:
                ops.store.add_notification(
                    "login_failed", "Failed sign-in attempt",
                    body=f"From {ip}" + (" — account temporarily locked" if locked_until else ""),
                    severity="warning")
            except Exception:  # noqa: BLE001
                pass
        flash("Incorrect password.", "error")
    configured = bool(cfg["auth"].get("password_hash"))
    return render_template("login.html", configured=configured)


@app.route("/logout")
def logout():
    auth.do_logout()
    flash("Logged out.", "ok")
    return redirect(url_for("login"))


# ------------------------------------------------------------------ dashboard
@app.route("/")
@auth.login_required
def dashboard():
    if _wizard_active() or _wizard_should_offer():
        return redirect(url_for("setup_wizard"))
    if not ops.layout.is_ca_initialized():
        return redirect(url_for("init_ca"))
    # Best-effort: reflect the CA's real state and pick up anything signed but not
    # yet mirrored. Never let a read-only/locked DB break the listing itself.
    reconcile_warn = None
    try:
        ops.resync()
        added = ops.reconcile_from_index()
        if added:
            flash(f"Added {added} certificate(s) found in the CA but missing from the list.", "ok")
        ops.scan_expiry_notifications(_default_notify_days())
        arch = cfg.get("archive", {})
        if arch.get("auto_delete"):
            ops.auto_delete_archived(int(arch.get("delete_after_days", 90)))
    except Exception as e:  # noqa: BLE001
        reconcile_warn = str(e)
    status = request.args.get("status", "valid")
    search = request.args.get("q", "").strip()
    order = request.args.get("order", "expires_at")
    certs = ops.store.all(status=status, search=search or None, order=order)
    default_lead = _default_notify_days()
    expiring_soon = 0
    for c in certs:
        c["days_left"] = _days_left(c.get("expires_at"))
        lead = c["notify_days"] if c.get("notify_days") is not None else default_lead
        if c["status"] == "valid" and c["days_left"] is not None and 0 <= c["days_left"] <= lead:
            expiring_soon += 1
    return render_template("dashboard.html", certs=certs, status=status,
                           search=search, order=order, reconcile_warn=reconcile_warn,
                           expiring_soon=expiring_soon, default_lead=default_lead)


# ---------------------------------------------------------------- CA unlock
@app.route("/unlock", methods=["GET", "POST"])
@auth.login_required
def unlock():
    if not ops.ca_key_encrypted():
        flash("The CA key is not passphrase-protected; no unlock needed.", "ok")
        return redirect(url_for("dashboard"))
    autounlock = _autounlock_enabled()
    nxt = request.args.get("next") or url_for("dashboard")
    if request.method == "POST":
        # When auto-unlock is enrolled, unlocking via the login password recovers
        # the CA passphrase — so the CA passphrase never has to be typed, even
        # after a restart wiped the in-memory unlock.
        login_pw = request.form.get("login_password", "")
        if autounlock and login_pw:
            if not auth.verify_password(cfg["auth"].get("password_hash"), login_pw):
                flash("Login password is incorrect.", "error")
            else:
                ca_pass = crypto.unwrap(
                    login_pw, crypto.salt_from_hex(ops.store.get_meta(AUTOUNLOCK_SALT)),
                    ops.store.get_meta(AUTOUNLOCK_BLOB))
                if ca_pass and ops.verify_passphrase(ca_pass):
                    auth.store_passphrase(ca_pass, cfg["session_timeout_minutes"])
                    flash("CA unlocked.", "ok")
                    return redirect(nxt)
                flash("Auto-unlock couldn't recover the CA passphrase (your login password may "
                      "have changed since it was set up). Enter the CA passphrase below to "
                      "re-enable it.", "error")
        else:
            pw = request.form.get("passphrase", "")
            if ops.verify_passphrase(pw):
                auth.store_passphrase(pw, cfg["ca_unlock_timeout_minutes"])
                flash("CA unlocked for this session.", "ok")
                return redirect(nxt)
            flash("Incorrect CA passphrase.", "error")
    return render_template("unlock.html", autounlock=autounlock)


@app.route("/lock", methods=["POST"])
@auth.login_required
def lock():
    auth.clear_passphrase()
    flash("CA locked.", "ok")
    return redirect(request.referrer or url_for("dashboard"))


# --------------------------------------------------------------- CA init
@app.route("/init", methods=["GET", "POST"], endpoint="init_ca")
@auth.login_required
def init_ca():
    if _wizard_active():
        return redirect(url_for("setup_wizard"))
    if ops.layout.is_ca_initialized():
        flash("CA is already initialized.", "ok")
        return redirect(url_for("dashboard"))
    d = cfg["cert_defaults"]
    if request.method == "POST":
        dn = {k: request.form.get(k, "").strip() for k in
              ("country", "state", "locality", "organization",
               "organizational_unit", "common_name", "email")}
        use_pass = request.form.get("use_passphrase") == "on"
        p1 = request.form.get("passphrase", "")
        p2 = request.form.get("passphrase_confirm", "")
        if use_pass and p1 != p2:
            flash("Passphrases do not match.", "error")
            return render_template("init.html", d=d, form=request.form)
        if use_pass and not p1:
            flash("Passphrase cannot be empty.", "error")
            return render_template("init.html", d=d, form=request.form)
        try:
            ops.init_ca(dn, passphrase=p1 if use_pass else None,
                        key_bits=int(d.get("key_length", 4096)))
        except CaError as e:
            flash(str(e), "error")
            return render_template("init.html", d=d, form=request.form)
        if use_pass:
            auth.store_passphrase(p1, cfg["ca_unlock_timeout_minutes"])
        flash("Certificate Authority initialized.", "ok")
        return redirect(url_for("dashboard"))
    return render_template("init.html", d=d, form={})


# ------------------------------------------------------ guided setup (new installs)
def _setup_cfg():
    return cfg.setdefault("setup", {"wizard_active": False, "wizard_dismissed": False})

def _wizard_active():
    return bool(_setup_cfg().get("wizard_active"))

def _wizard_should_offer():
    """Offer the intro only on a brand-new install that hasn't chosen yet."""
    s = _setup_cfg()
    return (not ops.layout.is_ca_initialized()
            and not s.get("wizard_dismissed") and not s.get("wizard_active"))

def _wizard_step():
    """Current step, derived from CA state. After the intermediate exists, a single
    'wrapup' page hosts the optional root-offline + web-cert actions."""
    L = ops.layout
    if not L.is_ca_initialized():
        return "root"
    if not L.is_two_tier():
        return "intermediate"
    return "wrapup"

@app.route("/setup")
@auth.login_required
def setup_wizard():
    if not _wizard_active():
        if _wizard_should_offer():
            return render_template("setup.html", step="intro")
        return redirect(url_for("dashboard"))
    step = _wizard_step()
    ctx = {"d": cfg["cert_defaults"], "root_key_path": ops.layout.ca_key,
           "two_tier": ops.two_tier_status(), "web_tls": _web_cfg(),
           "listen": f"{cfg.get('host', '0.0.0.0')}:{cfg.get('port', 8443)}"}
    return render_template("setup.html", step=step, **ctx)

@app.route("/setup/start", methods=["POST"])
@auth.login_required
def setup_start():
    s = _setup_cfg(); s["wizard_active"] = True; s["wizard_dismissed"] = False
    configmod.save_config(cfg)
    return redirect(url_for("setup_wizard"))

@app.route("/setup/skip", methods=["POST"])
@auth.login_required
def setup_skip():
    s = _setup_cfg(); s["wizard_active"] = False; s["wizard_dismissed"] = True
    configmod.save_config(cfg)
    return redirect(url_for("init_ca"))

@app.route("/setup/finish", methods=["POST"])
@auth.login_required
def setup_finish():
    s = _setup_cfg(); s["wizard_active"] = False; s["wizard_dismissed"] = True
    configmod.save_config(cfg)
    flash("Setup complete. You can manage everything from here on in Settings.", "ok")
    return redirect(url_for("dashboard"))

@app.route("/setup/root", methods=["POST"])
@auth.login_required
def setup_root():
    if not _wizard_active():
        return redirect(url_for("dashboard"))
    if ops.layout.is_ca_initialized():
        return redirect(url_for("setup_wizard"))
    d = cfg["cert_defaults"]
    dn = {k: request.form.get(k, "").strip() for k in
          ("country", "state", "locality", "organization",
           "organizational_unit", "common_name", "email")}
    if not dn["common_name"]:
        flash("Give the root CA a name (common name).", "error")
        return redirect(url_for("setup_wizard"))
    p1 = request.form.get("passphrase", ""); p2 = request.form.get("passphrase_confirm", "")
    if not p1:
        flash("The walkthrough protects the root with a passphrase — it's required.", "error")
        return redirect(url_for("setup_wizard"))
    if p1 != p2:
        flash("Passphrases do not match.", "error")
        return redirect(url_for("setup_wizard"))
    try:
        ops.init_ca(dn, passphrase=p1, key_bits=int(d.get("key_length", 4096)))
    except CaError as e:
        flash(str(e), "error")
        return redirect(url_for("setup_wizard"))
    auth.store_passphrase(p1, cfg["ca_unlock_timeout_minutes"])
    flash("Root CA created and encrypted with your passphrase.", "ok")
    return redirect(url_for("setup_wizard"))

@app.route("/setup/intermediate", methods=["POST"])
@auth.login_required
def setup_intermediate():
    if not _wizard_active():
        return redirect(url_for("dashboard"))
    if ops.layout.is_two_tier():
        return redirect(url_for("setup_wizard"))
    cn = request.form.get("cn", "").strip()
    if not cn:
        flash("The intermediate needs a common name.", "error")
        return redirect(url_for("setup_wizard"))
    try:
        days = int(request.form.get("validity_days", "").strip())
        if not (1 <= days <= 7300):
            raise ValueError
    except ValueError:
        flash("Intermediate validity must be a whole number of days (1–7300).", "error")
        return redirect(url_for("setup_wizard"))
    dcfg = cfg["cert_defaults"]
    dn = {"common_name": cn,
          "organization": dcfg.get("organization", ""),
          "organizational_unit": dcfg.get("organizational_unit", ""),
          "country": dcfg.get("country", ""), "state": dcfg.get("state", ""),
          "locality": dcfg.get("locality", "")}
    try:
        ops.create_intermediate(dn, days, root_passphrase=request.form.get("root_passphrase", ""),
                                int_passphrase=None)
    except CaError as e:
        flash(str(e), "error")
        return redirect(url_for("setup_wizard"))
    auth.clear_passphrase()   # signing is now the (unencrypted) intermediate
    flash("Intermediate created — new certificates are issued by it and ACME signs unattended.", "ok")
    return redirect(url_for("setup_wizard"))

@app.route("/setup/remove-root", methods=["POST"])
@auth.login_required
def setup_remove_root():
    if not _wizard_active():
        return redirect(url_for("dashboard"))
    if request.form.get("confirm", "").strip() != "REMOVE":
        flash("Type REMOVE to confirm taking the root key offline.", "error")
        return redirect(url_for("setup_wizard"))
    try:
        ops.remove_root_key()
        flash("Root private key deleted from this server. Keep your offline copy safe.", "ok")
    except CaError as e:
        flash(str(e), "error")
    return redirect(url_for("setup_wizard"))

@app.route("/setup/webcert", methods=["POST"])
@auth.login_required
def setup_webcert():
    if not _wizard_active():
        return redirect(url_for("dashboard"))
    sans = [s.strip() for s in re.split(r"[,\s]+", request.form.get("sans", "").strip()) if s.strip()]
    if not sans:
        flash("Enter at least one hostname or IP that SSCA is reached by.", "error")
        return redirect(url_for("setup_wizard"))
    w = cfg.setdefault("web_tls", {})
    w["mode"] = "managed"; w["sans"] = sans
    w.setdefault("validity_days", 825); w.setdefault("renew_before_days", 30)
    configmod.save_config(cfg)
    _ensure_web_cert()
    if _web_cert_fresh():
        flash("SSCA web certificate issued. Restart the service to serve HTTPS with it.", "ok")
    else:
        flash("Saved, but the certificate couldn't be issued yet — check the CA is unlocked.", "error")
    return redirect(url_for("setup_wizard"))


# ---------------------------------------------------------------- issue cert
@app.route("/issue", methods=["GET", "POST"])
@auth.login_required
def issue():
    d = cfg["cert_defaults"]
    if request.method == "POST":
        pw = _require_unlock()
        if pw is _REDIRECT:
            return redirect(url_for("unlock", next=url_for("issue")))
        cn = request.form.get("common_name", "").strip()
        cert_type = request.form.get("cert_type", "server")
        key_spec = request.form.get("key_spec", "rsa2048")
        sans = _normalize_sans(request.form.get("sans", ""))
        try:
            validity = int(request.form.get("validity_days") or d["default_validity_days"])
        except ValueError:
            validity = d["default_validity_days"]
        dn = {k: request.form.get(k, "").strip() for k in
              ("country", "state", "locality", "organization", "organizational_unit", "email")}
        # Warn before clobbering an existing valid cert with the same CN.
        existing = ops.store.find_active_by_cn(cn) if cn else None
        if existing and request.form.get("confirm_duplicate") != "yes":
            flash(f"A valid certificate for “{cn}” already exists (serial {existing['serial']}). "
                  f"Issuing again replaces its key/cert files on disk. Confirm below to proceed.",
                  "error")
            return render_template("issue.html", d=d, form=request.form,
                                   key_specs=ca_ops.KEY_SPECS, duplicate=existing)
        try:
            serial = ops.issue(cn, cert_type, sans, validity, dn, pw, key_spec=key_spec)
        except CaError as e:
            flash(str(e), "error")
            return render_template("issue.html", d=d, form=request.form,
                                   key_specs=ca_ops.KEY_SPECS)
        flash(f"Issued {cert_type} certificate for {cn} (serial {serial}).", "ok")
        return redirect(url_for("cert_detail", serial=serial))
    return render_template("issue.html", d=d, form={}, key_specs=ca_ops.KEY_SPECS)


# --------------------------------------------------------------- cert detail
@app.route("/cert/<serial>")
@auth.login_required
def cert_detail(serial):
    rec = ops.store.get(serial)
    if not rec:
        abort(404)
    rec["days_left"] = _days_left(rec.get("expires_at"))
    cert_pem = ops.layout.cert_pem_for_serial(serial)
    text = _openssl_text(cert_pem)
    from certparse import certificate_fingerprint
    fingerprint = certificate_fingerprint(cert_pem)
    return render_template("cert_detail.html", c=rec, text=text, fingerprint=fingerprint,
                           default_lead=_default_notify_days(),
                           acme_manage=cfg.get("acme", {}).get("manage_in_ui", True))


@app.route("/cert/<serial>/revoke", methods=["POST"])
@auth.login_required
def revoke(serial):
    if _acme_managed_blocked(ops.store.get(serial)):
        flash("This certificate is managed via ACME; UI management is disabled in ACME settings.", "error")
        return redirect(url_for("cert_detail", serial=serial))
    pw = _require_unlock()
    if pw is _REDIRECT:
        return redirect(url_for("unlock", next=url_for("cert_detail", serial=serial)))
    try:
        ops.revoke(serial, pw)
        flash(f"Certificate {serial} revoked and CRL updated.", "ok")
    except CaError as e:
        flash(str(e), "error")
    return redirect(url_for("cert_detail", serial=serial))


@app.route("/cert/<serial>/archive", methods=["POST"])
@auth.login_required
def archive_cert(serial):
    rec = ops.store.get(serial)
    if not rec:
        abort(404)
    if _acme_managed_blocked(rec):
        flash("This certificate is managed via ACME; UI management is disabled in ACME settings.", "error")
        return redirect(url_for("cert_detail", serial=serial))
    try:
        ops.store.archive(serial)
        flash(f"Archived {rec['common_name']}. It's hidden from your lists but still in the CA.", "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"Could not archive: {e}", "error")
    return redirect(request.form.get("next") or url_for("dashboard"))


@app.route("/cert/<serial>/unarchive", methods=["POST"])
@auth.login_required
def unarchive_cert(serial):
    rec = ops.store.get(serial)
    if not rec:
        abort(404)
    if _acme_managed_blocked(rec):
        flash("This certificate is managed via ACME; UI management is disabled in ACME settings.", "error")
        return redirect(url_for("cert_detail", serial=serial))
    try:
        ops.store.unarchive(serial)
        flash("Certificate restored to your lists.", "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"Could not unarchive: {e}", "error")
    return redirect(request.referrer or url_for("cert_detail", serial=serial))


@app.route("/cert/<serial>/delete", methods=["POST"])
@auth.login_required
def delete_cert(serial):
    rec = ops.store.get(serial)
    if not rec:
        abort(404)
    if _acme_managed_blocked(rec):
        flash("This certificate is managed via ACME; UI management is disabled in ACME settings.", "error")
        return redirect(url_for("cert_detail", serial=serial))
    try:
        ops.delete_cert(serial)
        flash(f"Deleted {rec['common_name']} from the app. Its files were moved to the "
              f"revoked-certs folder; the CA ledger (index.txt) is unchanged.", "ok")
    except CaError as e:
        flash(str(e), "error")
        return redirect(url_for("cert_detail", serial=serial))
    return redirect(url_for("dashboard"))


@app.route("/cert/<serial>/renew", methods=["POST"])
@auth.login_required
def renew(serial):
    rec = ops.store.get(serial)
    if rec and rec.get("source") == "acme":
        flash("ACME certificates renew automatically via the client; renew it there, not here.", "error")
        return redirect(url_for("cert_detail", serial=serial))
    pw = _require_unlock()
    if pw is _REDIRECT:
        return redirect(url_for("unlock", next=url_for("cert_detail", serial=serial)))
    try:
        new_serial = ops.renew(serial, pw)
        flash(f"Renewed: new serial {new_serial}; old certificate revoked.", "ok")
        return redirect(url_for("cert_detail", serial=new_serial))
    except CaError as e:
        flash(str(e), "error")
        return redirect(url_for("cert_detail", serial=serial))


# ------------------------------------------------------------------ downloads
@app.route("/cert/<serial>/download/<what>")
@auth.login_required
def download(serial, what):
    rec = ops.store.get(serial)
    if not rec:
        abort(404)
    L = ops.layout
    cn = rec["common_name"]
    cert_pem = L.cert_pem_for_serial(serial)
    if what == "cert":
        return _send(cert_pem, f"{cn}.crt", "application/x-pem-file")
    if what == "key":
        if not rec.get("key_path"):
            flash("No private key on file for this certificate.", "error")
            return redirect(url_for("cert_detail", serial=serial))
        return _send(os.path.join(L.root, rec["key_path"]), f"{cn}.key", "application/x-pem-file")
    if what == "chain":
        if not os.path.exists(cert_pem):
            abort(404)
        issuer = L.int_chain if L.is_two_tier() else L.ca_cert
        data = _read(cert_pem) + b"\n" + _read(issuer)
        return _send_bytes(data, f"{cn}.fullchain.pem", "application/x-pem-file")
    if what == "bundle":
        # cert + key together (only if key available)
        if not rec.get("key_path"):
            flash("No private key on file to bundle.", "error")
            return redirect(url_for("cert_detail", serial=serial))
        data = _read(os.path.join(L.root, rec["key_path"])) + b"\n" + _read(cert_pem)
        return _send_bytes(data, f"{cn}.pem", "application/x-pem-file")
    abort(404)


@app.route("/ca/download/<what>")
@auth.login_required
def ca_download(what):
    L = ops.layout
    mapping = {
        "cert": (L.ca_cert, "ca.cert.pem", "application/x-pem-file"),
        "p7b": (L.ca_p7b, "ca.cert.p7b", "application/x-pkcs7-certificates"),
        "crl": (L.crl, "crl.pem", "application/pkix-crl"),
        "intermediate": (L.int_cert, "intermediate.cert.pem", "application/x-pem-file"),
        "chain": (L.int_chain, "chain.pem", "application/x-pem-file"),
    }
    if what not in mapping:
        abort(404)
    path, name, mime = mapping[what]
    if not os.path.exists(path):
        flash(f"{name} does not exist yet.", "error")
        return redirect(url_for("dashboard"))
    return _send(path, name, mime)


@app.route("/crl/regen", methods=["POST"])
@auth.login_required
def crl_regen():
    pw = _require_unlock()
    if pw is _REDIRECT:
        return redirect(url_for("unlock", next=url_for("dashboard")))
    try:
        ops.generate_crl(pw)
        flash("CRL regenerated.", "ok")
    except CaError as e:
        flash(str(e), "error")
    return redirect(request.referrer or url_for("dashboard"))


# --------------------------------------------------------------- notifications
@app.route("/notifications")
@auth.login_required
def notifications():
    items = ops.store.notifications(limit=100)
    return render_template("notifications.html", items=items)


@app.route("/notifications/read-all", methods=["POST"])
@auth.login_required
def notifications_read_all():
    ops.store.mark_all_notifications_read()
    if request.form.get("ajax"):
        return {"ok": True}
    return redirect(request.referrer or url_for("notifications"))


@app.route("/notifications/read/<int:nid>", methods=["POST"])
@auth.login_required
def notification_read(nid):
    ops.store.mark_notification_read(nid)
    if request.form.get("ajax"):
        return {"ok": True}
    return redirect(request.referrer or url_for("notifications"))


@app.route("/notifications/clear", methods=["POST"])
@auth.login_required
def notifications_clear():
    ops.store.clear_notifications()
    flash("Notifications cleared.", "ok")
    return redirect(url_for("notifications"))


@app.route("/notifications/unread")
@auth.login_required
def notifications_unread():
    try:
        return {"unread": ops.store.unread_count()}
    except Exception:  # noqa: BLE001
        return {"unread": 0}


@app.route("/cert/<serial>/notify", methods=["POST"])
@auth.login_required
def set_notify(serial):
    if not ops.store.get(serial):
        abort(404)
    raw = request.form.get("notify_days", "").strip()
    if raw == "":
        ops.store.set_notify_days(serial, None)
        flash("Using the default expiry notification lead time.", "ok")
    else:
        try:
            days = int(raw)
            if days < 0:
                raise ValueError
            ops.store.set_notify_days(serial, days)
            flash(f"Will notify {days} day(s) before expiry.", "ok")
        except ValueError:
            flash("Enter a whole number of days (or leave blank for the default).", "error")
    return redirect(url_for("cert_detail", serial=serial))


# ------------------------------------------------------------------ settings
@app.route("/settings", methods=["GET"])
@auth.login_required
def settings():
    return render_template("settings.html", cfg=cfg, rejected=ALLOWLIST_REJECTED,
                           allowlist=cfg.get("ip_allowlist") or [],
                           autounlock_enabled=_autounlock_enabled(),
                           on_restart=cfg.get("on_restart", "relogin"),
                           ca_currently_unlocked=auth.is_unlocked(),
                           default_notify_days=_default_notify_days(),
                           login_alerts=cfg.get("notifications", {}).get("login_alerts", True),
                           archive_cfg=cfg.get("archive", {}),
                           acme_cfg=cfg.get("acme", {}),
                           acme_signable=_acme_signable(),
                           two_tier=ops.two_tier_status(),
                           root_ca=ops.root_ca_info(),
                           root_key_path=ops.layout.ca_key,
                           eab_creds=ACME_STORE.list_eab(),
                           eab_reveal=session.pop("eab_reveal", None),
                           publish_cfg=_publish_cfg(),
                           piholes_status=_piholes_status(),
                           publish_ready=_publish_ready(),
                           web_tls=_web_cfg(),
                           login_pw_set=bool(cfg["auth"].get("password_hash")))


@app.route("/settings/allowlist", methods=["POST"])
@auth.login_required
def change_allowlist():
    global ALLOWLIST_NETS, ALLOWLIST_REJECTED
    raw = request.form.get("ip_allowlist", "").strip()
    entries = [e.strip() for e in re.split(r"[,\s]+", raw) if e.strip()]
    nets, rejected = auth.parse_allowlist(entries)
    # Self-lockout guard: refuse a list that would block the requester's own IP.
    ok, _reason = auth.ip_permitted(nets)
    if not ok:
        flash(f"That allowlist would block your own address ({request.remote_addr}). "
              "Add it, or clear the list to allow any private address.", "error")
        return redirect(url_for("settings") + "#access")
    rejected_entries = {e for e, _ in rejected}
    cfg["ip_allowlist"] = [e for e in entries if e not in rejected_entries]   # keep only valid
    configmod.save_config(cfg)
    ALLOWLIST_NETS, ALLOWLIST_REJECTED = nets, rejected   # apply immediately
    msg = "LAN allowlist saved and applied."
    if rejected:
        msg += " Ignored non-private/invalid: " + ", ".join(e for e, _ in rejected) + "."
    flash(msg, "ok")
    return redirect(url_for("settings") + "#access")


@app.route("/settings/server", methods=["POST"])
@auth.login_required
def change_server():
    host = request.form.get("host", "").strip()
    try:
        port = int(request.form.get("port", cfg.get("port", 8443)))
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        flash("Port must be a whole number between 1 and 65535.", "error")
        return redirect(url_for("settings") + "#access")
    if host:
        cfg["host"] = host
    cfg["port"] = port
    configmod.save_config(cfg)
    flash(f"Listen address saved ({cfg.get('host', '0.0.0.0')}:{port}). Restart the service to apply — "
          "and update Caddy's acme_ca and SSCA's ACME External URL to match the new port.", "ok")
    return redirect(url_for("settings") + "#access")


@app.route("/settings/web-tls", methods=["POST"])
@auth.login_required
def change_web_tls():
    w = cfg.setdefault("web_tls", {})
    mode = request.form.get("mode", "http")
    w["mode"] = mode if mode in ("http", "manual", "managed") else "http"
    raw = request.form.get("sans", "").strip()
    w["sans"] = [s.strip() for s in re.split(r"[,\s]+", raw) if s.strip()]
    for key, default in (("validity_days", 825), ("renew_before_days", 30)):
        try:
            w[key] = max(1, int(request.form.get(key, default)))
        except ValueError:
            w[key] = default
    configmod.save_config(cfg)
    if w["mode"] == "managed" and not w["sans"]:
        flash("Managed TLS needs at least one hostname or IP — the address(es) SSCA is reached by.",
              "error")
    elif w["mode"] == "managed":
        _ensure_web_cert()   # pre-issue so it's ready
        if not _web_cert_fresh():
            flash("Saved, but couldn't issue the cert yet (is the CA initialized and unlocked/"
                  "unencrypted?). It'll be issued once that's sorted. Restart to serve HTTPS.", "error")
        else:
            flash("Web-UI TLS set to SSCA-managed and the cert is ready. "
                  "Restart the service to serve HTTPS with it.", "ok")
    else:
        flash(f"Web-UI TLS set to '{w['mode']}'. Restart the service to apply.", "ok")
    return redirect(url_for("settings") + "#access")


def _acme_signable():
    """True if the CA can sign unattended (unencrypted key or persist enabled)."""
    if not ops.layout.is_ca_initialized():
        return False
    return (not ops.ca_key_encrypted()) or _persist_enabled()


@app.route("/settings/acme", methods=["POST"])
@auth.login_required
def change_acme():
    a = cfg.setdefault("acme", {})
    enabled = request.form.get("enabled") == "on"
    external_url = request.form.get("external_url", "").strip().rstrip("/")
    if enabled and not (external_url.startswith("http://") or external_url.startswith("https://")):
        flash("To enable ACME, set an external URL starting with http:// or https:// "
              "(the address clients will use, e.g. https://ca.example.com).", "error")
        return redirect(url_for("settings"))
    a["enabled"] = enabled
    a["external_url"] = external_url
    a["manage_in_ui"] = request.form.get("manage_in_ui") == "on"
    a["eab_required"] = request.form.get("eab_required") == "on"
    a["revoke_superseded"] = request.form.get("revoke_superseded") == "on"
    for key, default in (("validity_days", 90), ("max_validity_days", 397), ("http01_port", 80)):
        try:
            v = int(request.form.get(key, default))
            if v < 1:
                raise ValueError
            a[key] = v
        except ValueError:
            flash(f"{key.replace('_', ' ')} must be a positive whole number.", "error")
            return redirect(url_for("settings"))
    raw = request.form.get("allowed_domains", "").strip()
    a["allowed_domains"] = [d.strip().lower() for d in re.split(r"[,\s]+", raw) if d.strip()]
    configmod.save_config(cfg)
    if enabled and not _acme_signable():
        flash("ACME is enabled, but the CA key is locked — issuance will fail until you use an "
              "unencrypted key or enable 'keep unlocked across restarts'.", "error")
    else:
        flash("ACME settings saved." + ("" if enabled else " (ACME is disabled.)"), "ok")
    return redirect(url_for("settings"))


@app.route("/settings/acme/eab/new", methods=["POST"])
@auth.login_required
def acme_eab_new():
    label = request.form.get("label", "").strip() or None
    raw = request.form.get("http01_port", "").strip()
    port = None
    if raw:
        try:
            port = int(raw)
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            flash("http-01 port must be a whole number 1–65535 (or blank for the default 80).", "error")
            return redirect(url_for("settings") + "#acme")
    cred = ACME_STORE.create_eab(label=label, http01_port=port)
    # One-time reveal: carry the fresh secret through the redirect so it renders
    # exactly once. The MAC key is never shown in the table afterwards — if it
    # isn't captured now, the client must be re-enrolled with a new credential.
    session["eab_reveal"] = {"kid": cred["kid"], "mac_key": cred["mac_key"],
                             "label": label or "", "port": port or 80}
    flash(f"EAB credential created — key ID {cred['kid']} (http-01 port {port or 80}). "
          "Copy the MAC key now; it won't be shown again.", "ok")
    return redirect(url_for("settings") + "#acme")


@app.route("/settings/acme/eab/<kid>/port", methods=["POST"])
@auth.login_required
def acme_eab_port(kid):
    if not ACME_STORE.get_eab(kid):
        abort(404)
    raw = request.form.get("http01_port", "").strip()
    port = None
    if raw:
        try:
            port = int(raw)
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            flash("http-01 port must be a whole number 1–65535 (or blank for 80).", "error")
            return redirect(url_for("settings") + "#acme")
    ACME_STORE.set_eab_port(kid, port)
    flash(f"EAB {kid} http-01 port set to {port or 80}. Applies to its next challenge.", "ok")
    return redirect(url_for("settings") + "#acme")


@app.route("/settings/acme/eab/<kid>/revoke", methods=["POST"])
@auth.login_required
def acme_eab_revoke(kid):
    if not ACME_STORE.get_eab(kid):
        abort(404)
    ACME_STORE.revoke_eab(kid)
    flash(f"EAB credential {kid} revoked — it can no longer enroll new accounts.", "ok")
    return redirect(url_for("settings") + "#acme")


@app.route("/settings/acme/eab/<kid>/delete", methods=["POST"])
@auth.login_required
def acme_eab_delete(kid):
    if not ACME_STORE.get_eab(kid):
        abort(404)
    ACME_STORE.delete_eab(kid)
    flash(f"EAB credential {kid} deleted.", "ok")
    return redirect(url_for("settings") + "#acme")


# ----------------------------------------------- service auto-publish (Phase 4)
@app.route("/publish")
@auth.login_required
def publish_page():
    return render_template("publish.html", cfg=cfg,
                           services=ops.store.list_published_services(),
                           publish_cfg=_publish_cfg(), publish_ready=_publish_ready())


@app.route("/publish/new", methods=["POST"])
@auth.login_required
def publish_new():
    if not _publish_ready():
        flash("Configure and enable service publishing in Settings first.", "error")
        return redirect(url_for("settings") + "#publish")
    name = request.form.get("name", "").strip().lower().strip(".")
    upstream = request.form.get("upstream", "").strip()
    domain = (_publish_cfg().get("domain") or "").strip(".")
    hostname = name if "." in name else (f"{name}.{domain}" if domain else name)
    target_ip = request.form.get("target_ip", "").strip() or _publish_cfg().get("target_ip", "")
    if not name or not upstream:
        flash("Service name and backend (host:port) are both required.", "error")
        return redirect(url_for("publish_page"))
    try:
        _make_publisher().publish(hostname, upstream, target_ip)
        flash(f"Published {hostname} → {upstream}. Caddy will obtain its certificate shortly.", "ok")
    except publishmod.PublishError as e:
        flash(str(e), "error")
    return redirect(url_for("publish_page"))


@app.route("/publish/stream", methods=["POST"])
@auth.login_required
def publish_stream():
    """Stream the publish as newline-delimited JSON step events (live UI)."""
    if not _publish_ready():
        return jsonify(ok=False,
                       message="Configure and enable service publishing in Settings first."), 400
    name = request.form.get("name", "").strip().lower().strip(".")
    upstream = request.form.get("upstream", "").strip()
    domain = (_publish_cfg().get("domain") or "").strip(".")
    hostname = name if "." in name else (f"{name}.{domain}" if domain else name)
    target_ip = request.form.get("target_ip", "").strip() or _publish_cfg().get("target_ip", "")
    if not name or not upstream:
        return jsonify(ok=False, message="Service name and backend (host:port) are required."), 400
    pub = _make_publisher()

    def gen():
        import json as _json
        try:
            for ev in pub.publish_events(hostname, upstream, target_ip):
                yield _json.dumps(ev) + "\n"
        except Exception as e:  # noqa: BLE001
            yield _json.dumps({"step": "done", "status": "error", "message": str(e)}) + "\n"
    return Response(gen(), mimetype="application/x-ndjson")


@app.route("/publish/<hostname>/unpublish/stream", methods=["POST"])
@auth.login_required
def unpublish_stream(hostname):
    """Stream the unpublish (route + DNS + revoke) as NDJSON step events."""
    pub = _make_publisher()

    def gen():
        import json as _json
        try:
            for ev in pub.unpublish_events(hostname):
                yield _json.dumps(ev) + "\n"
        except Exception as e:  # noqa: BLE001
            yield _json.dumps({"step": "done", "status": "error", "message": str(e)}) + "\n"
    return Response(gen(), mimetype="application/x-ndjson")


@app.route("/publish/<hostname>/unpublish", methods=["POST"])
@auth.login_required
def publish_unpublish(hostname):
    try:
        _make_publisher().unpublish(hostname)
        flash(f"Unpublished {hostname}.", "ok")
    except publishmod.PublishError as e:
        flash(str(e), "error")
    return redirect(url_for("publish_page"))


@app.route("/settings/publish", methods=["POST"])
@auth.login_required
def change_publish():
    p = cfg.setdefault("publish", {})
    p["enabled"] = request.form.get("enabled") == "on"
    p["target_ip"] = request.form.get("target_ip", "").strip()
    p["domain"] = request.form.get("domain", "").strip().strip(".")
    cd = p.setdefault("caddy", {})
    cd["admin_url"] = request.form.get("caddy_admin_url", "").strip().rstrip("/")
    try:
        cd["https_port"] = int(request.form.get("caddy_https_port", 443))
    except ValueError:
        cd["https_port"] = 443
    configmod.save_config(cfg)
    flash("Service-publishing settings saved.", "ok")
    return redirect(url_for("settings") + "#publish")


@app.route("/settings/publish/pihole/add", methods=["POST"])
@auth.login_required
def add_pihole():
    base_url = request.form.get("base_url", "").strip().rstrip("/")
    if not (base_url.startswith("http://") or base_url.startswith("https://")):
        flash("Enter the Pi-hole base URL (http:// or https://).", "error")
        return redirect(url_for("settings") + "#publish")
    p = cfg.setdefault("publish", {})
    lst = p.setdefault("piholes", [])
    verify = request.form.get("verify_tls") == "on"
    existing = next((x for x in lst if x.get("base_url") == base_url), None)
    if existing:
        existing["verify_tls"] = verify
    else:
        lst.append({"base_url": base_url, "verify_tls": verify})
    configmod.save_config(cfg)
    if request.form.get("password"):
        _set_pihole_password(base_url, request.form["password"])
    flash(f"Pi-hole {base_url} saved.", "ok")
    return redirect(url_for("settings") + "#publish")


@app.route("/settings/publish/pihole/remove", methods=["POST"])
@auth.login_required
def remove_pihole():
    base_url = request.form.get("base_url", "").strip().rstrip("/")
    p = cfg.setdefault("publish", {})
    p["piholes"] = [x for x in (p.get("piholes") or []) if x.get("base_url") != base_url]
    configmod.save_config(cfg)
    _set_pihole_password(base_url, None)
    flash(f"Pi-hole {base_url} removed.", "ok")
    return redirect(url_for("settings") + "#publish")


@app.route("/settings/publish/test-pihole", methods=["POST"])
@auth.login_required
def test_pihole_one():
    """AJAX: test one Pi-hole using the values in the form (before saving). Falls
    back to the stored password when the form field is blank (row 'Test')."""
    base_url = request.form.get("base_url", "").strip().rstrip("/")
    if not base_url:
        return jsonify(ok=False, message="Enter a Pi-hole base URL first.")
    pw = request.form.get("password") or _pihole_password(base_url)
    if not pw:
        return jsonify(ok=False, message="No password entered or stored for this Pi-hole.")
    verify = request.form.get("verify_tls") in ("on", "true", "1")
    try:
        return jsonify(ok=True, message=pihole.PiholeClient(base_url, pw, verify_tls=verify).test())
    except Exception as e:  # noqa: BLE001
        return jsonify(ok=False, message=str(e))


@app.route("/settings/publish/test-caddy", methods=["POST"])
@auth.login_required
def test_caddy_one():
    """AJAX: test the Caddy admin API using the value in the form (before saving)."""
    admin_url = request.form.get("admin_url", "").strip().rstrip("/")
    if not admin_url:
        return jsonify(ok=False, message="Enter the Caddy admin URL first.")
    try:
        port = int(request.form.get("https_port", 443))
    except ValueError:
        port = 443
    try:
        return jsonify(ok=True, message=caddyadmin.CaddyClient(admin_url, https_port=port).test())
    except Exception as e:  # noqa: BLE001
        return jsonify(ok=False, message=str(e))


@app.route("/settings/archive", methods=["POST"])
@auth.login_required
def change_archive():
    cfg.setdefault("archive", {})
    cfg["archive"]["auto_delete"] = request.form.get("auto_delete") == "on"
    raw = request.form.get("delete_after_days", "").strip()
    try:
        days = int(raw)
        if days < 1:
            raise ValueError
        cfg["archive"]["delete_after_days"] = days
    except ValueError:
        flash("Delete-after days must be a whole number of 1 or more.", "error")
        return redirect(url_for("settings"))
    configmod.save_config(cfg)
    flash("Archive settings saved.", "ok")
    return redirect(url_for("settings"))


@app.route("/settings/notifications", methods=["POST"])
@auth.login_required
def change_notifications():
    cfg.setdefault("notifications", {})
    raw = request.form.get("default_notify_days", "").strip()
    try:
        days = int(raw)
        if days < 0:
            raise ValueError
        cfg["notifications"]["default_notify_days"] = days
    except ValueError:
        flash("Default notify days must be a non-negative whole number.", "error")
        return redirect(url_for("settings"))
    cfg["notifications"]["login_alerts"] = request.form.get("login_alerts") == "on"
    configmod.save_config(cfg)
    flash("Notification settings saved.", "ok")
    return redirect(url_for("settings"))


@app.route("/settings/on-restart", methods=["POST"])
@auth.login_required
def change_on_restart():
    mode = request.form.get("mode", "relogin")
    if mode not in ("relogin", "keep", "persist"):
        flash("Unknown option.", "error")
        return redirect(url_for("settings"))
    if mode == "persist":
        if not ops.ca_key_encrypted():
            flash("The CA key has no passphrase, so there's nothing to persist.", "error")
            return redirect(url_for("settings"))
        ca_pass = auth.get_passphrase()
        if not ca_pass:
            flash("Unlock the CA first, then choose 'keep unlocked across restarts'.", "error")
            return redirect(url_for("settings"))
        _persist_passphrase(ca_pass)
        auth.set_global_passphrase(ca_pass)
    else:
        # Leaving persist: drop the at-rest copy and its machine key.
        if _persist_enabled():
            _clear_persisted_passphrase()
    cfg["on_restart"] = mode
    configmod.save_config(cfg)
    labels = {"relogin": "Require sign-in again after a restart",
              "keep": "Stay signed in; unlock when needed",
              "persist": "Keep the CA unlocked across restarts"}
    flash(f"Restart behavior set to: {labels[mode]}.", "ok")
    return redirect(url_for("settings"))


@app.route("/settings/ca-passphrase", methods=["POST"])
@auth.login_required
def change_ca_passphrase():
    action = request.form.get("action")
    current = request.form.get("current", "")
    new1 = request.form.get("new", "")
    new2 = request.form.get("new_confirm", "")
    try:
        if action == "remove":
            ops.remove_ca_key_passphrase(current)
            auth.clear_passphrase()
            flash("CA passphrase removed. The CA key is now unencrypted.", "ok")
        else:
            if new1 != new2:
                flash("New passphrases do not match.", "error")
                return redirect(url_for("settings"))
            if not new1:
                flash("New passphrase cannot be empty.", "error")
                return redirect(url_for("settings"))
            ops.encrypt_ca_key(new1, current_passphrase=current if ops.ca_key_encrypted() else None)
            auth.store_passphrase(new1, cfg["ca_unlock_timeout_minutes"])
            flash("CA passphrase updated.", "ok")
        # The stored auto-unlock / persist copies wrap the OLD passphrase; invalidate them.
        if _autounlock_enabled():
            _disable_autounlock()
            flash("Auto-unlock was disabled because the CA passphrase changed — re-enable it "
                  "in Settings to resume one-password sign-in.", "ok")
        if _persist_enabled():
            _clear_persisted_passphrase()
            cfg["on_restart"] = "relogin"
            configmod.save_config(cfg)
            flash("'Keep unlocked across restarts' was turned off because the CA passphrase "
                  "changed — re-enable it in Settings if you still want it.", "ok")
    except CaError as e:
        flash(str(e), "error")
    return redirect(url_for("settings"))


@app.route("/settings/two-tier/create", methods=["POST"])
@auth.login_required
def two_tier_create():
    if ops.layout.is_two_tier():
        flash("An intermediate CA already exists.", "error")
        return redirect(url_for("settings") + "#cakey")
    if not ops.layout.root_key_present():
        flash("The root key is offline — restore it to create an intermediate.", "error")
        return redirect(url_for("settings") + "#cakey")
    cn = request.form.get("cn", "").strip()
    if not cn:
        flash("The intermediate needs a common name.", "error")
        return redirect(url_for("settings") + "#cakey")
    try:
        days = int(request.form.get("validity_days", "").strip())
        if not (1 <= days <= 7300):
            raise ValueError
    except ValueError:
        flash("Intermediate validity must be a whole number of days (1–7300).", "error")
        return redirect(url_for("settings") + "#cakey")
    root_cur = request.form.get("root_current", "")
    root_new = request.form.get("root_new", "")
    int_pass = request.form.get("int_passphrase", "") or None
    # Not two-tier yet, so the signing key IS the root here.
    root_encrypted = ops.ca_key_encrypted()
    if root_new:
        if root_new != request.form.get("root_new_confirm", ""):
            flash("Root passphrases do not match.", "error")
            return redirect(url_for("settings") + "#cakey")
    elif not root_encrypted:
        flash("Set a passphrase for the root key — protecting it is the whole point of "
              "taking it offline.", "error")
        return redirect(url_for("settings") + "#cakey")
    dn = {"common_name": cn,
          "organization": request.form.get("o", "").strip(),
          "organizational_unit": request.form.get("ou", "").strip(),
          "country": request.form.get("c", "").strip(),
          "state": request.form.get("st", "").strip(),
          "locality": request.form.get("l", "").strip()}
    try:
        # 1. make sure the root ends up encrypted with the chosen passphrase
        if root_new:
            ops.encrypt_ca_key(root_new, current_passphrase=root_cur if root_encrypted else None)
            sign_pass = root_new
        else:
            sign_pass = root_cur  # already encrypted; reuse it to sign
        # 2. root signs the intermediate; operational signing flips to it
        ops.create_intermediate(dn, days, root_passphrase=sign_pass, int_passphrase=int_pass)
    except CaError as e:
        flash(str(e), "error")
        return redirect(url_for("settings") + "#cakey")
    # Signing is now the intermediate; any stored root-passphrase unlocks are stale.
    auth.clear_passphrase()
    if _autounlock_enabled():
        _disable_autounlock()
    if _persist_enabled():
        _clear_persisted_passphrase()
        cfg["on_restart"] = "relogin"
        configmod.save_config(cfg)
    flash("Two-tier CA created. New certificates are issued by the intermediate and ACME "
          "signs unattended. Now take the root key offline below.", "ok")
    return redirect(url_for("settings") + "#cakey")


@app.route("/settings/two-tier/export-root")
@auth.login_required
def two_tier_export_root():
    try:
        data = ops.read_root_key()
    except CaError as e:
        flash(str(e), "error")
        return redirect(url_for("settings") + "#cakey")
    return _send_bytes(data, "ca.key.pem", "application/x-pem-file")


@app.route("/settings/two-tier/remove-root", methods=["POST"])
@auth.login_required
def two_tier_remove_root():
    if request.form.get("confirm", "").strip() != "REMOVE":
        flash("Type REMOVE to confirm taking the root key offline.", "error")
        return redirect(url_for("settings") + "#cakey")
    try:
        ops.remove_root_key()
        flash("Root private key deleted from this server. Keep your offline copy safe — "
              "it's the only way to rotate the intermediate or issue a new one.", "ok")
    except CaError as e:
        flash(str(e), "error")
    return redirect(url_for("settings") + "#cakey")


@app.route("/settings/autounlock", methods=["POST"])
@auth.login_required
def autounlock():
    action = request.form.get("action")
    if action == "disable":
        _disable_autounlock()
        flash("Auto-unlock disabled. You'll enter the CA passphrase per session again.", "ok")
        return redirect(url_for("settings"))
    if not ops.ca_key_encrypted():
        flash("The CA key has no passphrase, so there is nothing to auto-unlock.", "error")
        return redirect(url_for("settings"))
    login_pw = request.form.get("login_password", "")
    ca_pass = request.form.get("ca_passphrase", "")
    if not auth.verify_password(cfg["auth"].get("password_hash"), login_pw):
        flash("Your web-UI login password is incorrect.", "error")
        return redirect(url_for("settings"))
    if not ops.verify_passphrase(ca_pass):
        flash("That CA passphrase is incorrect.", "error")
        return redirect(url_for("settings"))
    _enroll_autounlock(login_pw, ca_pass)
    auth.store_passphrase(ca_pass, cfg["session_timeout_minutes"])
    flash("Auto-unlock enabled. From now on, signing in unlocks the CA automatically.", "ok")
    return redirect(url_for("settings"))


@app.route("/settings/login-password", methods=["POST"])
@auth.login_required
def change_login_password():
    current = request.form.get("current", "")
    new1 = request.form.get("new", "")
    new2 = request.form.get("new_confirm", "")
    if not auth.verify_password(cfg["auth"].get("password_hash"), current):
        flash("Current login password is incorrect.", "error")
        return redirect(url_for("settings"))
    if not new1 or new1 != new2:
        flash("New login passwords are empty or do not match.", "error")
        return redirect(url_for("settings"))
    # If auto-unlock is enrolled, recover the CA passphrase with the old login
    # password so we can re-wrap it under the new one.
    ca_pass = None
    if _autounlock_enabled():
        salt_hex = ops.store.get_meta(AUTOUNLOCK_SALT)
        ca_pass = crypto.unwrap(current, crypto.salt_from_hex(salt_hex),
                                ops.store.get_meta(AUTOUNLOCK_BLOB))
    from werkzeug.security import generate_password_hash
    cfg["auth"]["password_hash"] = generate_password_hash(new1)
    configmod.save_config(cfg)
    if ca_pass is not None:
        _enroll_autounlock(new1, ca_pass)
    flash("Login password updated." + (" Auto-unlock re-wrapped." if ca_pass else ""), "ok")
    return redirect(url_for("settings"))


@app.route("/settings/resync", methods=["POST"])
@auth.login_required
def resync():
    from migrate_to_sqlite import migrate
    try:
        migrate(cfg["ca_root"], os.path.join(cfg["ca_root"], "backup"))
        flash("Mirror re-synced from index.txt (backup taken).", "ok")
    except Exception as e:  # noqa: BLE001
        flash(f"Resync failed: {e}", "error")
    return redirect(url_for("settings"))


@app.route("/install")
@auth.login_required
def install_help():
    return render_template("install.html")


@app.route("/ca")
@auth.login_required
def ca_info():
    if not ops.layout.is_ca_initialized():
        return redirect(url_for("init_ca"))
    return render_template("ca_info.html", ca=ops.root_ca_info(), crl=ops.crl_info(),
                           crl_warn=int(cfg.get("notifications", {}).get("crl_warn_days", 7)),
                           ca_warn=int(cfg.get("notifications", {}).get("ca_expiry_warn_days", 60)))


# --------------------------------------------------------------------- utils
_REDIRECT = object()

AUTOUNLOCK_SALT = "autounlock_salt"
AUTOUNLOCK_BLOB = "autounlock_blob"

def _autounlock_enabled():
    return bool(ops.store.get_meta(AUTOUNLOCK_SALT) and ops.store.get_meta(AUTOUNLOCK_BLOB))

def _try_autounlock(login_password):
    """If auto-unlock is enrolled, unwrap the CA passphrase and load it. Best-effort."""
    if not (ops.layout.is_ca_initialized() and ops.ca_key_encrypted()):
        return False
    salt_hex = ops.store.get_meta(AUTOUNLOCK_SALT)
    blob = ops.store.get_meta(AUTOUNLOCK_BLOB)
    if not (salt_hex and blob):
        return False
    ca_pass = crypto.unwrap(login_password, crypto.salt_from_hex(salt_hex), blob)
    if ca_pass and ops.verify_passphrase(ca_pass):
        auth.store_passphrase(ca_pass, cfg["session_timeout_minutes"])
        return True
    return False

def _enroll_autounlock(login_password, ca_passphrase):
    salt = crypto.new_salt()
    blob = crypto.wrap(login_password, salt, ca_passphrase)
    ops.store.set_meta(AUTOUNLOCK_SALT, crypto.salt_to_hex(salt))
    ops.store.set_meta(AUTOUNLOCK_BLOB, blob)

def _disable_autounlock():
    ops.store.set_meta(AUTOUNLOCK_SALT, None)
    ops.store.set_meta(AUTOUNLOCK_BLOB, None)


def _require_unlock():
    """Return the CA passphrase, None (unencrypted CA), or _REDIRECT sentinel."""
    if not ops.ca_key_encrypted():
        return None
    pw = auth.get_passphrase()
    if pw is None:
        return _REDIRECT
    return pw


def _acme_managed_blocked(rec):
    """True if this is an ACME cert and UI management is disabled."""
    return bool(rec and rec.get("source") == "acme"
                and not cfg.get("acme", {}).get("manage_in_ui", True))


def _default_notify_days():
    try:
        return int(cfg.get("notifications", {}).get("default_notify_days", 30))
    except (TypeError, ValueError):
        return 30


def _normalize_sans(raw):
    out = []
    for tok in re.split(r"[,\s]+", raw or ""):
        tok = tok.strip()
        if not tok:
            continue
        if tok.upper().startswith(("DNS:", "IP:")):
            out.append(tok)
            continue
        try:
            ipaddress.ip_address(tok)
            out.append(f"IP:{tok}")
        except ValueError:
            out.append(f"DNS:{tok}")
    return out


def _days_left(expires_iso):
    if not expires_iso:
        return None
    from datetime import datetime, timezone
    try:
        exp = datetime.fromisoformat(expires_iso)
    except ValueError:
        return None
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    return (exp - datetime.now(timezone.utc)).days


def _openssl_text(cert_path):
    if not os.path.exists(cert_path):
        return "(certificate file not found on disk)"
    r = subprocess.run(["openssl", "x509", "-in", cert_path, "-noout", "-text"],
                       capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else r.stderr


def _read(path):
    with open(path, "rb") as f:
        return f.read()

def _send(path, download_name, mime):
    return send_file(path, as_attachment=True, download_name=download_name, mimetype=mime)

def _send_bytes(data, download_name, mime):
    return send_file(io.BytesIO(data), as_attachment=True,
                     download_name=download_name, mimetype=mime)


if __name__ == "__main__":
    ssl_context = _web_tls_context()
    if _web_cfg().get("mode") == "managed" and ssl_context:
        _start_web_cert_maintainer()   # auto-renew + self-restart to reload
    if ALLOWLIST_REJECTED:
        for entry, why in ALLOWLIST_REJECTED:
            print(f"[config warning] ip_allowlist entry '{entry}': {why}")
    scheme = "https" if ssl_context else "http"
    print(f"[*] Serving {scheme} on {cfg['host']}:{cfg['port']}", file=sys.stderr)
    # threaded=True keeps the in-memory unlock vault shared across requests;
    # do not run this with multiple worker processes.
    app.run(host=cfg["host"], port=cfg["port"], ssl_context=ssl_context, threaded=True)
