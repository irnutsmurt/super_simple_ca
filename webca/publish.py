"""Service auto-publish orchestration (Phase 4).

One action makes a service reachable over HTTPS with a cert auto-issued by this
CA. Steps run in a fixed order with rollback:

  1. Pi-hole DNS A record  (so Caddy's ACME http-01 challenge resolves), then
  2. Caddy reverse-proxy route (which triggers Caddy to obtain the cert).

If the Caddy step fails, the DNS record is rolled back so a failed publish leaves
nothing behind. Unpublish reverses the order (remove the route, then the record).
The published_services table is the source of truth so a reconcile pass (M4) can
re-apply routes after Caddy restarts.
"""
from datetime import datetime, timezone


class PublishError(Exception):
    pass


def _now():
    return datetime.now(timezone.utc).isoformat()


class Publisher:
    def __init__(self, store, piholes, caddy, cert_revoker=None):
        self.store = store
        # `piholes` is a list of PiholeClient (a primary + secondary, say). The
        # DNS record is written to every one; on unpublish it's removed from all.
        self.piholes = list(piholes or [])
        self.caddy = caddy
        # Optional callable(hostname) -> serial|None that revokes the ACME cert
        # issued for a service (used on unpublish). Raises on failure.
        self.cert_revoker = cert_revoker

    def _dns_delete_all(self, hostname, ip):
        """Best-effort delete from every Pi-hole; returns a list of errors."""
        errs = []
        for ph in self.piholes:
            try:
                ph.delete_a_record(hostname, ip)
            except Exception as e:  # noqa: BLE001
                errs.append(f"{getattr(ph, 'base', 'a Pi-hole')}: {e}")
        return errs

    def publish_events(self, hostname, upstream, target_ip, cert_wait=60, cert_poll=2.0):
        """Generator that performs the publish, yielding {step,status,message}
        dicts as each step runs (for a live UI). `status` is running|ok|warn|error;
        an 'error' event ends the run. Rollback semantics match publish()."""
        import time
        hostname = (hostname or "").strip().lower()
        upstream = (upstream or "").strip()
        target_ip = (target_ip or "").strip()
        if not hostname or not upstream or not target_ip:
            yield {"step": "validate", "status": "error",
                   "message": "hostname, backend and target IP are all required."}
            return
        if not self.piholes:
            yield {"step": "validate", "status": "error", "message": "No Pi-hole is configured."}
            return

        self.store.upsert_published_service(
            hostname, upstream=upstream, target_ip=target_ip,
            status="pending", dns_ok=0, route_ok=0, error=None)

        # 1. DNS on every Pi-hole (roll the done ones back if any fails).
        done = []
        for i, ph in enumerate(self.piholes, 1):
            label = getattr(ph, "base", f"Pi-hole {i}")
            yield {"step": f"dns-{i}", "status": "running",
                   "message": f"Sending {hostname} → {target_ip} to Pi-hole {i} ({label})…"}
            try:
                ph.add_a_record(hostname, target_ip)
                done.append(ph)
                yield {"step": f"dns-{i}", "status": "ok", "message": f"Added on Pi-hole {i}."}
            except Exception as e:  # noqa: BLE001
                for d in done:
                    try:
                        d.delete_a_record(hostname, target_ip)
                    except Exception:  # noqa: BLE001
                        pass
                self.store.upsert_published_service(
                    hostname, status="error", error=f"DNS failed on {label}: {e}")
                yield {"step": f"dns-{i}", "status": "error",
                       "message": f"Pi-hole {i} failed: {e} — rolled back any earlier records."}
                return
        self.store.upsert_published_service(hostname, dns_ok=1)

        # 2. Caddy route (rolls DNS back on failure).
        yield {"step": "route", "status": "running",
               "message": f"Adding Caddy reverse-proxy route ({hostname} → {upstream})…"}
        try:
            self.caddy.add_route(hostname, upstream)
            yield {"step": "route", "status": "ok", "message": "Caddy route added."}
        except Exception as e:  # noqa: BLE001
            self._dns_delete_all(hostname, target_ip)
            self.store.upsert_published_service(
                hostname, status="error", dns_ok=0,
                error=f"Caddy route failed (DNS rolled back): {e}")
            yield {"step": "route", "status": "error",
                   "message": f"Caddy route failed: {e} — DNS records rolled back."}
            return
        self.store.upsert_published_service(hostname, route_ok=1, status="published", error=None)

        # 3. Wait for Caddy to obtain the cert.
        yield {"step": "cert", "status": "running",
               "message": "Waiting for Caddy to obtain the certificate…"}
        waited = 0.0
        while waited < cert_wait:
            cert = self.store.find_valid_by_host(hostname)
            if cert:
                yield {"step": "cert", "status": "ok",
                       "message": f"Certificate issued ✓ (serial {cert['serial']})."}
                yield {"step": "done", "status": "ok",
                       "message": f"{hostname} is published and live."}
                return
            time.sleep(cert_poll)
            waited += cert_poll
        yield {"step": "cert", "status": "warn",
               "message": (f"DNS and route are set, but no certificate after {int(cert_wait)}s. "
                           "Caddy may still be enrolling — check the Certificates page shortly.")}
        yield {"step": "done", "status": "ok",
               "message": f"{hostname} published (certificate pending)."}

    def publish(self, hostname, upstream, target_ip):
        """Blocking publish (no cert wait); raises PublishError on failure."""
        for ev in self.publish_events(hostname, upstream, target_ip, cert_wait=0):
            if ev.get("status") == "error":
                raise PublishError(ev["message"])
        return self.store.get_published_service(hostname)

    def unpublish_events(self, hostname, revoke=True):
        """Generator: remove the Caddy route, the DNS record from every Pi-hole,
        and (optionally) revoke the issued certificate — yielding a
        {step,status,message} per step. Best-effort: continues through all steps
        collecting errors; the row is forgotten only if nothing failed, else kept
        as 'partial'. (Revocation failures are warnings, not hard errors.)"""
        hostname = (hostname or "").strip().lower()
        rec = self.store.get_published_service(hostname)
        target_ip = (rec or {}).get("target_ip")
        errors = []

        yield {"step": "route", "status": "running", "message": "Removing the Caddy route…"}
        try:
            existed = self.caddy.delete_route(hostname, ignore_missing=True)
            yield {"step": "route", "status": "ok",
                   "message": "Caddy route removed." if existed else "No Caddy route (already gone)."}
        except Exception as e:  # noqa: BLE001
            errors.append(f"Caddy route: {e}")
            yield {"step": "route", "status": "error", "message": f"Caddy route removal failed: {e}"}

        for i, ph in enumerate(self.piholes, 1):
            label = getattr(ph, "base", f"Pi-hole {i}")
            yield {"step": f"dns-{i}", "status": "running",
                   "message": f"Removing {hostname} from Pi-hole {i} ({label})…"}
            try:
                if target_ip:
                    ph.delete_a_record(hostname, target_ip)
                yield {"step": f"dns-{i}", "status": "ok", "message": f"Removed from Pi-hole {i}."}
            except Exception as e:  # noqa: BLE001
                errors.append(f"Pi-hole {i}: {e}")
                yield {"step": f"dns-{i}", "status": "error", "message": f"Pi-hole {i} failed: {e}"}

        if revoke and self.cert_revoker:
            yield {"step": "cert", "status": "running", "message": "Revoking the certificate…"}
            try:
                serial = self.cert_revoker(hostname)
                if serial:
                    yield {"step": "cert", "status": "ok",
                           "message": f"Certificate revoked (serial {serial})."}
                else:
                    yield {"step": "cert", "status": "warn",
                           "message": "No ACME certificate found to revoke."}
            except Exception as e:  # noqa: BLE001
                yield {"step": "cert", "status": "warn",
                       "message": f"Could not revoke the certificate: {e}"}

        if errors:
            self.store.upsert_published_service(hostname, status="partial", error="; ".join(errors))
            yield {"step": "done", "status": "warn",
                   "message": "Unpublished with problems: " + "; ".join(errors)}
        else:
            self.store.delete_published_service(hostname)
            yield {"step": "done", "status": "ok", "message": f"{hostname} unpublished."}

    def unpublish(self, hostname, revoke=True):
        """Blocking unpublish; raises PublishError if a route/DNS step failed."""
        failed = False
        for ev in self.unpublish_events(hostname, revoke=revoke):
            if ev["status"] == "error":
                failed = True
        if failed:
            rec = self.store.get_published_service(hostname)
            raise PublishError((rec or {}).get("error") or "Unpublish partly failed.")
        return True

    def reconcile(self):
        """Re-apply Caddy routes for every 'published' service that Caddy is
        missing (e.g. after a `caddy reload` from the Caddyfile wiped them).
        Returns the list of hostnames re-applied."""
        present = set(self.caddy.list_managed())
        readded = []
        for svc in self.store.list_published_services():
            if svc["status"] != "published":
                continue
            if svc["hostname"] not in present:
                self.caddy.add_route(svc["hostname"], svc["upstream"])
                readded.append(svc["hostname"])
        return readded
