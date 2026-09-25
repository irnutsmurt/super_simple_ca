"""Pi-hole v6 REST API client — just enough to manage local DNS A records.

Used by the service auto-publish feature to point a service hostname at the
Caddy box. Pi-hole v6 auth is session-based: POST the app password to
``/api/auth`` to get a SID, then send it as the ``X-FTL-SID`` header. Custom
local DNS entries live in the ``dns.hosts`` config array as ``"<ip> <hostname>"``
strings; array items are added/removed by PUT/DELETE on the item's path.

Only the standard library is used (urllib) so there's no extra dependency. TLS
verification can be turned off because a LAN Pi-hole usually has a self-signed
cert or serves plain HTTP.
"""
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request


class PiholeError(Exception):
    pass


class PiholeClient:
    def __init__(self, base_url, password, verify_tls=True, timeout=10):
        self.base = (base_url or "").rstrip("/")
        self.password = password
        self.timeout = timeout
        self._sid = None
        self._ctx = None
        if self.base.startswith("https") and not verify_tls:
            self._ctx = ssl.create_default_context()
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    # ------------------------------------------------------------------ http
    def _req(self, method, path, body=None, auth=True):
        if not self.base:
            raise PiholeError("Pi-hole base URL is not configured.")
        url = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if auth and self._sid:
            req.add_header("X-FTL-SID", self._sid)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                doc = json.loads(raw)
            except Exception:  # noqa: BLE001
                doc = {"error": raw.decode("utf-8", "replace")}
            return e.code, doc
        except urllib.error.URLError as e:
            raise PiholeError(f"Cannot reach Pi-hole at {url}: {e.reason}")

    # ------------------------------------------------------------------ auth
    def login(self):
        st, doc = self._req("POST", "/api/auth", {"password": self.password}, auth=False)
        sess = (doc or {}).get("session") or {}
        if st == 200 and sess.get("valid"):
            self._sid = sess.get("sid")
            return True
        raise PiholeError("Pi-hole authentication failed — check the app password.")

    def logout(self):
        if self._sid:
            try:
                self._req("DELETE", "/api/auth")
            finally:
                self._sid = None

    def _ensure(self):
        if not self._sid:
            self.login()

    # ---------------------------------------------------------------- records
    @staticmethod
    def _extract_hosts(doc):
        """Pull the hosts array out of whatever shape the API returns."""
        d = doc or {}
        for path in (("config", "dns", "hosts"), ("dns", "hosts"), ("hosts",)):
            cur = d
            ok = True
            for k in path:
                if isinstance(cur, dict) and k in cur:
                    cur = cur[k]
                else:
                    ok = False
                    break
            if ok and isinstance(cur, list):
                return cur
        return []

    def list_hosts(self):
        self._ensure()
        st, doc = self._req("GET", "/api/config/dns/hosts")
        if st != 200:
            raise PiholeError(f"Could not read Pi-hole DNS hosts (HTTP {st}).")
        return self._extract_hosts(doc)

    def find(self, hostname):
        """Return the host entries whose name matches `hostname`."""
        return [h for h in self.list_hosts()
                if isinstance(h, str) and h.split()[-1:] == [hostname]]

    def add_a_record(self, hostname, ip):
        self._ensure()
        item = f"{ip} {hostname}"
        enc = urllib.parse.quote(item, safe="")
        st, doc = self._req("PUT", f"/api/config/dns/hosts/{enc}")
        if st not in (200, 201):
            raise PiholeError(f"Could not add DNS record '{item}' (HTTP {st}): {doc}")
        return item

    def delete_a_record(self, hostname, ip):
        self._ensure()
        item = f"{ip} {hostname}"
        enc = urllib.parse.quote(item, safe="")
        st, doc = self._req("DELETE", f"/api/config/dns/hosts/{enc}")
        if st not in (200, 204):
            raise PiholeError(f"Could not delete DNS record '{item}' (HTTP {st}): {doc}")

    # ----------------------------------------------------------------- probe
    def test(self):
        """Login + list, returning a short human status. Raises PiholeError."""
        self.login()
        hosts = self.list_hosts()
        self.logout()
        return f"Connected to Pi-hole; {len(hosts)} local DNS record(s) present."
