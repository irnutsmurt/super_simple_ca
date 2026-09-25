"""Access control: login, private-only IP allowlist, and the CA-unlock vault.

The CA passphrase is held only in this process's memory (the vault below), keyed
by a random token stored in the user's signed session cookie. It is never
written to disk and never placed in the cookie itself, and it expires after a
configurable idle timeout.
"""
import ipaddress
import secrets
import time
from functools import wraps

from flask import session, request, redirect, url_for, flash

from werkzeug.security import check_password_hash

# token -> (passphrase, expires_at_epoch)
_VAULT = {}

# Process-global CA passphrase, used only by the "persist across restart" option.
# Loaded at startup from a machine-key-wrapped blob; applies to every session.
_GLOBAL = {"passphrase": None}


def set_global_passphrase(passphrase):
    _GLOBAL["passphrase"] = passphrase

def clear_global_passphrase():
    _GLOBAL["passphrase"] = None


# ---------------------------------------------------------------- IP allowlist
def parse_allowlist(entries):
    """Parse allowlist entries into networks, keeping only private ones."""
    nets, rejected = [], []
    for entry in entries or []:
        entry = str(entry).strip()
        if not entry:
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            rejected.append((entry, "not a valid IP or CIDR"))
            continue
        if not _is_private_net(net):
            rejected.append((entry, "not a private/LAN range — refused"))
            continue
        nets.append(net)
    return nets, rejected


def _is_private_net(net):
    return net.is_private or net.is_loopback or net.is_link_local


def _client_ip():
    # We bind directly on the LAN (no reverse proxy assumed), so remote_addr is
    # the real peer. We deliberately do NOT trust X-Forwarded-For here.
    return request.remote_addr or ""


def ip_permitted(allowlist_nets):
    """Return (ok, reason). Public source IPs are always refused."""
    raw = _client_ip()
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return False, f"unrecognized client address '{raw}'"
    if not (ip.is_private or ip.is_loopback or ip.is_link_local):
        return False, f"external address {raw} is not allowed"
    if allowlist_nets:
        if not any(ip in net for net in allowlist_nets):
            return False, f"{raw} is not in the configured LAN allowlist"
    return True, None


# --------------------------------------------------------------------- login
def is_logged_in():
    return bool(session.get("logged_in"))

def do_login():
    session["logged_in"] = True
    session.permanent = True

def do_logout():
    token = session.get("unlock_token")
    if token:
        _VAULT.pop(token, None)
    session.clear()

def verify_password(password_hash, password):
    if not password_hash:
        return False
    return check_password_hash(password_hash, password)


# ---------------------------------------------------------------- CA unlock vault
def store_passphrase(passphrase, timeout_minutes):
    import secrets as _secrets
    token = _secrets.token_urlsafe(24)
    _VAULT[token] = (passphrase, time.time() + timeout_minutes * 60)
    session["unlock_token"] = token

def get_passphrase():
    """Return the live CA passphrase, or None if locked/expired.

    Checks the per-session vault first, then the process-global passphrase (set
    by the persist-across-restart option).
    """
    token = session.get("unlock_token")
    if token:
        entry = _VAULT.get(token)
        if entry:
            passphrase, expires = entry
            if time.time() <= expires:
                return passphrase
            _VAULT.pop(token, None)
            session.pop("unlock_token", None)
    return _GLOBAL["passphrase"]

def clear_passphrase():
    token = session.pop("unlock_token", None)
    if token:
        _VAULT.pop(token, None)

def is_unlocked():
    return get_passphrase() is not None


# ---------------------------------------------------------------- CSRF
def csrf_token():
    """Return the session CSRF token, creating one on first use."""
    tok = session.get("csrf_token")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
    return tok

def csrf_valid():
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    good = session.get("csrf_token")
    return bool(good) and bool(sent) and secrets.compare_digest(sent, good)


# ------------------------------------------------------------- login throttle
# ip -> (fail_count, first_fail_epoch, locked_until_epoch)
_FAILS = {}

def login_blocked(ip, max_fails, window_s, lock_s):
    entry = _FAILS.get(ip)
    if not entry:
        return 0
    count, first, locked_until = entry
    now = time.time()
    if locked_until and now < locked_until:
        return int(locked_until - now)
    if locked_until and now >= locked_until:
        _FAILS.pop(ip, None)
        return 0
    if now - first > window_s:
        _FAILS.pop(ip, None)
    return 0

def record_login_failure(ip, max_fails, window_s, lock_s):
    now = time.time()
    count, first, _ = _FAILS.get(ip, (0, now, 0))
    if now - first > window_s:
        count, first = 0, now
    count += 1
    locked_until = now + lock_s if count >= max_fails else 0
    _FAILS[ip] = (count, first, locked_until)
    return locked_until

def clear_login_failures(ip):
    _FAILS.pop(ip, None)


# ---------------------------------------------------------------- decorators
def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if not is_logged_in():
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped
