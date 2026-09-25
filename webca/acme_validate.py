"""http-01 challenge validation for the ACME server (RFC 8555 §8.3).

The server proves the client controls an identifier by fetching
    http://<identifier>:<port>/.well-known/acme-challenge/<token>
and checking the body equals the key authorization. Runs in a background thread
so the challenge POST returns immediately (status "processing"); the client
polls the authorization/order until it becomes valid or invalid.
"""
import threading
import urllib.request
from datetime import datetime, timezone

ERROR_NS = "urn:ietf:params:acme:error:"


def start_http01(store, challenge_id, http01_port, timeout=8, attempts=3, delay=2):
    """Kick off validation for a challenge in a daemon thread."""
    t = threading.Thread(
        target=_run, args=(store, challenge_id, http01_port, timeout, attempts, delay),
        daemon=True)
    t.start()
    return t


def _run(store, challenge_id, http01_port, timeout, attempts, delay):
    import time
    ch = store.get_challenge(challenge_id)
    if not ch:
        return
    az = store.get_authorization(ch["authz_id"])
    order = store.get_order(az["order_id"])
    account = store.get_account(order["account_id"])
    if not (az and order and account):
        return
    key_auth = f"{ch['token']}.{account['thumbprint']}"
    url = (f"http://{az['identifier_value']}:{http01_port}"
           f"/.well-known/acme-challenge/{ch['token']}")

    err = None
    for i in range(attempts):
        ok, err = _probe(url, key_auth, timeout)
        if ok:
            store.set_challenge_status(challenge_id, "valid",
                                       validated_at=datetime.now(timezone.utc))
            store.set_authorization_status(az["id"], "valid")
            store.maybe_advance_order(order["id"])
            return
        if i < attempts - 1:
            time.sleep(delay)

    store.set_challenge_status(challenge_id, "invalid",
                               error={"type": ERROR_NS + err[0], "detail": err[1]})
    store.set_authorization_status(az["id"], "invalid")
    store.maybe_advance_order(order["id"])


def _probe(url, expected, timeout):
    """Return (ok, error) where error is (acme_type, detail)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SuperSimpleCA-ACME/1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status // 100 != 2:
                return False, ("connection", f"HTTP {resp.status} from {url}")
            body = resp.read(8192).decode("utf-8", "replace").strip()
    except Exception as e:  # noqa: BLE001
        return False, ("connection", f"Could not fetch {url}: {e}")
    if body != expected.strip():
        return False, ("incorrectResponse",
                       "The challenge response did not match the expected key authorization.")
    return True, None
