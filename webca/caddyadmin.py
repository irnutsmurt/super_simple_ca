"""Caddy Admin API client — manage reverse-proxy routes for auto-published services.

SSCA adds/removes `@id`-tagged routes on Caddy's HTTPS server so Caddy reverse-
proxies a hostname to a backend and auto-provisions its TLS cert via the ACME
issuer already configured in Caddy's global options. Every route SSCA creates is
tagged ``ssca-<hostname>`` so it can find, replace, and remove exactly its own
routes without disturbing hand-written Caddyfile config.

Admin-API changes are in-memory (they don't survive a `caddy reload --config
Caddyfile`), so SSCA is the source of truth and re-applies its routes via a
reconcile pass (see tick.py / M4). Standard library only.
"""
import json
import urllib.error
import urllib.request

ID_PREFIX = "ssca-"


class CaddyError(Exception):
    pass


class CaddyClient:
    def __init__(self, admin_url, https_port=443, timeout=10):
        self.base = (admin_url or "").rstrip("/")
        self.https_port = int(https_port or 443)
        self.timeout = timeout

    # ------------------------------------------------------------------ http
    def _req(self, method, path, body=None):
        if not self.base:
            raise CaddyError("Caddy admin URL is not configured.")
        url = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                doc = json.loads(raw)
            except Exception:  # noqa: BLE001
                doc = {"error": raw.decode("utf-8", "replace")}
            return e.code, doc
        except urllib.error.URLError as e:
            raise CaddyError(f"Cannot reach Caddy admin at {url}: {e.reason}")

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def route_id(hostname):
        return ID_PREFIX + hostname

    def _servers(self):
        st, doc = self._req("GET", "/config/apps/http/servers")
        if st != 200 or not isinstance(doc, dict):
            raise CaddyError(f"Could not read Caddy servers (HTTP {st}).")
        return doc

    def _https_server_name(self):
        """Name of Caddy's HTTPS server. Detection order: the configured listen
        port; else a server that terminates TLS; else the conventional :443;
        else the first. (In Docker the internal listen is usually :443 even when
        the host maps it to another port like 8443, so we don't rely on the port
        alone.)"""
        servers = self._servers()
        needle = f":{self.https_port}"
        for name, srv in servers.items():
            if any(str(l).endswith(needle) for l in (srv.get("listen") or [])):
                return name
        for name, srv in servers.items():
            if srv.get("tls_connection_policies"):
                return name
        for name, srv in servers.items():
            if any(str(l).endswith(":443") for l in (srv.get("listen") or [])):
                return name
        if servers:
            return next(iter(servers))
        raise CaddyError("Caddy has no HTTP servers configured.")

    # ---------------------------------------------------------------- routes
    def route_exists(self, hostname):
        st, _ = self._req("GET", f"/id/{self.route_id(hostname)}")
        return st == 200

    def add_route(self, hostname, upstream):
        """Create (or replace) a reverse-proxy route for hostname -> upstream.

        `upstream` is a Caddy dial address, e.g. "192.168.1.30:7474".
        """
        srv = self._https_server_name()
        self.delete_route(hostname, ignore_missing=True)  # idempotent replace
        route = {
            "@id": self.route_id(hostname),
            "match": [{"host": [hostname]}],
            "handle": [{
                "handler": "subroute",
                "routes": [{
                    "handle": [{
                        "handler": "reverse_proxy",
                        "upstreams": [{"dial": upstream}],
                    }],
                }],
            }],
            "terminal": True,
        }
        st, doc = self._req("POST", f"/config/apps/http/servers/{srv}/routes", route)
        if st != 200:
            raise CaddyError(f"Failed to add route for {hostname} (HTTP {st}): {doc}")
        return srv

    def delete_route(self, hostname, ignore_missing=False):
        if not self.route_exists(hostname):
            if ignore_missing:
                return False
            raise CaddyError(f"No SSCA-managed route for {hostname}.")
        st, doc = self._req("DELETE", f"/id/{self.route_id(hostname)}")
        if st not in (200, 204):
            raise CaddyError(f"Failed to delete route for {hostname} (HTTP {st}): {doc}")
        return True

    def list_managed(self):
        """Hostnames of all SSCA-managed routes currently in Caddy."""
        out = []
        for srv in self._servers().values():
            for rt in (srv.get("routes") or []):
                rid = rt.get("@id", "")
                if isinstance(rid, str) and rid.startswith(ID_PREFIX):
                    out.append(rid[len(ID_PREFIX):])
        return out

    # ----------------------------------------------------------------- probe
    def test(self):
        srv = self._https_server_name()
        n = len(self.list_managed())
        return (f"Connected to Caddy admin; HTTPS server '{srv}' on :{self.https_port}, "
                f"{n} SSCA-managed route(s).")
