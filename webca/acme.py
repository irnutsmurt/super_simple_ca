"""ACME server HTTP surface (RFC 8555) — Flask blueprint.

Milestone 3 implements: directory, newNonce, newAccount, and the account
resource, plus the shared request machinery every ACME endpoint relies on:
JWS verification, nonce anti-replay, `url` binding, `Replay-Nonce`/`Link`
headers on every response, and RFC 7807 `problem+json` errors.

The blueprint is created via `create_acme_blueprint(cfg, store, nonces, ops)`
so it has no global state and is easy to test. It authenticates requests with
JWS (not the web-UI session), so app.py mounts it exempt from login+CSRF while
keeping the IP allowlist.
"""
import json
import re
import secrets
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, make_response, Response

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding

import acme_validate
import jws as jwsmod
from ca_ops import CaError

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")

ERROR_NS = "urn:ietf:params:acme:error:"


def _openssl_serial(n):
    """Render an integer serial the way `openssl x509 -serial` does: uppercase
    hex, zero-padded to an even number of digits (matches the mirror's keys)."""
    h = format(n, "X")
    return ("0" + h) if len(h) % 2 else h


class AcmeProblem(Exception):
    def __init__(self, acme_type, detail, status=400, extra=None):
        super().__init__(detail)
        self.acme_type = acme_type
        self.detail = detail
        self.status = status
        self.extra = extra or {}


def create_acme_blueprint(cfg, store, nonces, ops=None, passphrase_provider=None):
    bp = Blueprint("acme", __name__)

    # ------------------------------------------------------------- helpers
    def acme_cfg():
        return cfg.get("acme", {}) or {}

    def base_url():
        return (acme_cfg().get("external_url") or "").rstrip("/")

    def abs_url(path):
        return base_url() + path

    def account_url(aid):
        return abs_url(f"/acme/acct/{aid}")

    def require_enabled():
        c = acme_cfg()
        if not c.get("enabled"):
            raise AcmeProblem("unauthorized", "ACME is not enabled on this server.", 404)
        if not base_url():
            raise AcmeProblem("serverInternal",
                              "ACME external_url is not configured.", 500)

    @bp.after_request
    def _acme_headers(resp):
        # Every ACME response carries a fresh nonce and points at the directory.
        resp.headers["Replay-Nonce"] = nonces.new()
        resp.headers["Cache-Control"] = "no-store"
        resp.headers.setdefault("Link", f'<{abs_url("/acme/directory")}>;rel="index"')
        return resp

    @bp.errorhandler(AcmeProblem)
    def _handle_problem(err):
        doc = {"type": ERROR_NS + err.acme_type, "detail": err.detail}
        doc.update(err.extra)
        resp = make_response(json.dumps(doc), err.status)
        resp.headers["Content-Type"] = "application/problem+json"
        return resp

    def _resolve_account_key(kid):
        # kid is the absolute account URL; the id is its last path segment.
        if not kid or "/acme/acct/" not in kid:
            return None
        aid = kid.rstrip("/").rsplit("/", 1)[-1]
        acct = store.get_account(aid)
        if not acct or acct["status"] != "valid":
            return None
        return json.loads(acct["jwk_json"])

    def read_jws(require_kid=None):
        """Verify the JWS on the current request and return (parsed, account).

        require_kid: True -> must use kid (account must exist); False -> must use
        jwk (newAccount); None -> either.
        """
        require_enabled()
        if request.content_type != "application/jose+json":
            raise AcmeProblem("malformed",
                              "Content-Type must be application/jose+json", 415)
        try:
            parsed = jwsmod.verify_jws(request.get_data(), key_resolver=_resolve_account_key)
        except jwsmod.JwsError as e:
            raise AcmeProblem(e.acme_type, e.detail, e.status, e.extra)

        # Anti-replay nonce.
        if not nonces.consume(parsed.nonce or ""):
            raise AcmeProblem("badNonce",
                              "The nonce is invalid, already used, or expired.", 400)
        # The signed url must match where the request was sent (exact string).
        expected = abs_url(request.path)
        if parsed.url != expected:
            raise AcmeProblem("unauthorized",
                              f"JWS 'url' does not match the request URL ({expected}).", 400)

        if require_kid is True and parsed.kid is None:
            raise AcmeProblem("malformed", "This request must be signed with 'kid'.", 400)
        if require_kid is False and parsed.jwk is None:
            raise AcmeProblem("malformed", "This request must be signed with 'jwk'.", 400)

        account = None
        if parsed.kid is not None:
            aid = parsed.kid.rstrip("/").rsplit("/", 1)[-1]
            account = store.get_account(aid)
            if not account:
                raise AcmeProblem("accountDoesNotExist", "Unknown account.", 400)
        return parsed, account

    # ------------------------------------------------------------- endpoints
    @bp.route("/directory", methods=["GET"])
    def directory():
        require_enabled()
        return jsonify({
            "newNonce": abs_url("/acme/new-nonce"),
            "newAccount": abs_url("/acme/new-account"),
            "newOrder": abs_url("/acme/new-order"),
            "revokeCert": abs_url("/acme/revoke-cert"),
            "keyChange": abs_url("/acme/key-change"),
            "meta": {
                "website": base_url(),
                "externalAccountRequired": bool(acme_cfg().get("eab_required")),
            },
        })

    @bp.route("/new-nonce", methods=["GET", "HEAD"])
    def new_nonce():
        require_enabled()
        # after_request supplies the Replay-Nonce header.
        status = 200 if request.method == "HEAD" else 204
        return make_response("", status)

    @bp.route("/new-account", methods=["POST"])
    def new_account():
        parsed, _ = read_jws(require_kid=False)
        payload = parsed.payload_json()
        thumbprint = jwsmod.jwk_thumbprint(parsed.jwk)

        existing = store.get_account_by_thumbprint(thumbprint)
        if payload.get("onlyReturnExisting"):
            if not existing:
                raise AcmeProblem("accountDoesNotExist", "No account for this key.", 400)
            return _account_response(existing, status=200)

        if existing:
            return _account_response(existing, status=200)

        # Creating a brand-new account: enforce External Account Binding if the
        # client supplied one, or if the server requires it (RFC 8555 §7.3.4).
        eab_kid = _verify_eab(payload.get("externalAccountBinding"), parsed, thumbprint)

        contact = payload.get("contact") or []
        _validate_contacts(contact)
        acct = store.create_account(thumbprint, json.dumps(jwsmod.public_jwk(parsed.jwk)),
                                    contact, eab_kid=eab_kid)
        if eab_kid:
            store.bind_eab(eab_kid, acct["id"])
        return _account_response(acct, status=201)

    @bp.route("/acct/<aid>", methods=["POST"])
    def account(aid):
        parsed, account_obj = read_jws(require_kid=True)
        if not account_obj or account_obj["id"] != aid:
            raise AcmeProblem("unauthorized", "Account mismatch.", 403)
        if not parsed.is_post_as_get:
            payload = parsed.payload_json()
            updates = {}
            if "contact" in payload:
                _validate_contacts(payload["contact"])
                updates["contact"] = payload["contact"]
            if payload.get("status") == "deactivated":
                updates["status"] = "deactivated"
            if updates:
                account_obj = store.update_account(aid, **updates)
        return _account_response(account_obj, status=200)

    @bp.route("/acct/<aid>/orders", methods=["POST"])
    def account_orders(aid):
        _, account_obj = read_jws(require_kid=True)
        if not account_obj or account_obj["id"] != aid:
            raise AcmeProblem("unauthorized", "Account mismatch.", 403)
        urls = [abs_url(f"/acme/order/{o['id']}") for o in store.orders_for_account(aid)]
        return jsonify({"orders": urls})

    # ------------------------------------------------------------- orders
    @bp.route("/new-order", methods=["POST"])
    def new_order():
        parsed, account_obj = read_jws(require_kid=True)
        payload = parsed.payload_json()
        identifiers = _validate_identifiers(payload.get("identifiers"))
        c = acme_cfg()
        order = store.create_order(account_obj["id"], identifiers,
                                   ttl_hours=int(c.get("order_ttl_hours", 24)),
                                   not_before=payload.get("notBefore"),
                                   not_after=payload.get("notAfter"))
        for idf in identifiers:
            az = store.create_authorization(order["id"], idf["type"], idf["value"])
            store.create_challenge(az["id"], "http-01", secrets.token_urlsafe(32))
        return _order_response(store.get_order(order["id"]), status=201)

    @bp.route("/order/<oid>", methods=["POST"])
    def order(oid):
        parsed, account_obj = read_jws(require_kid=True)
        o = _owned_order(oid, account_obj)
        return _order_response(o, status=200)

    @bp.route("/order/<oid>/finalize", methods=["POST"])
    def finalize(oid):
        parsed, account_obj = read_jws(require_kid=True)
        o = _owned_order(oid, account_obj)
        if o["status"] == "valid":
            return _order_response(o, status=200)     # already issued (idempotent)
        if o["status"] != "ready":
            raise AcmeProblem("orderNotReady",
                              "The order's authorizations are not all valid yet.", 403)

        payload = parsed.payload_json()
        csr_b64 = payload.get("csr")
        if not csr_b64:
            raise AcmeProblem("badCSR", "finalize requires a 'csr' field.")
        try:
            csr_der = jwsmod.b64u_decode(csr_b64)
            csr = x509.load_der_x509_csr(csr_der)
        except Exception:  # noqa: BLE001
            raise AcmeProblem("badCSR", "The CSR is not valid base64url DER PKCS#10.")
        if not csr.is_signature_valid:
            raise AcmeProblem("badCSR", "The CSR signature is invalid.")

        # The CSR's DNS names must exactly match the order identifiers.
        order_names = {i["value"].lower() for i in json.loads(o["identifiers_json"])}
        csr_names = _csr_dns_names(csr)
        if csr_names != order_names:
            raise AcmeProblem("badCSR",
                              f"CSR names {sorted(csr_names)} do not match the order "
                              f"identifiers {sorted(order_names)}.")

        if ops is None:
            raise AcmeProblem("serverInternal", "Signing backend unavailable.", 500)
        passphrase = passphrase_provider() if passphrase_provider else None
        if ops.ca_key_encrypted() and passphrase is None:
            raise AcmeProblem("serverInternal",
                              "The CA key is locked. ACME needs unattended signing — use an "
                              "unencrypted CA key or enable 'keep unlocked across restarts'.", 503)

        store.set_order_status(oid, "processing")
        csr_pem = csr.public_bytes(Encoding.PEM).decode("ascii")
        try:
            serial, _cert_pem = ops.sign_csr(
                csr_pem, cert_type="server", validity_days=_order_validity(o),
                passphrase=passphrase, source="acme")
        except CaError as e:
            store.set_order_status(oid, "invalid",
                                   error={"type": ERROR_NS + "serverInternal", "detail": str(e)})
            raise AcmeProblem("serverInternal", f"Issuance failed: {e}", 500)

        cert_id = secrets.token_urlsafe(16)
        store.set_order_certificate(oid, serial, cert_id)

        # Optionally revoke the certs this renewal supersedes (same account, same
        # identifier set). Off by default; best-effort — never break issuance.
        if cfg.get("acme", {}).get("revoke_superseded"):
            revoked_any = False
            try:
                old_serials = store.certs_superseded_by(
                    account_obj["id"], json.loads(o["identifiers_json"]), oid)
            except Exception:  # noqa: BLE001
                old_serials = []
            for old in old_serials:
                if old == serial:
                    continue
                rec = ops.store.get(old)
                if not (rec and rec.get("status") == "valid" and rec.get("source") == "acme"):
                    continue
                try:
                    ops.revoke(old, passphrase, regen_crl=False)
                    revoked_any = True
                except CaError:
                    pass
            if revoked_any:
                try:
                    ops.generate_crl(passphrase)
                except CaError:
                    pass

        return _order_response(store.get_order(oid), status=200)

    @bp.route("/cert/<cert_id>", methods=["POST"])
    def certificate(cert_id):
        parsed, account_obj = read_jws(require_kid=True)
        o = store.order_by_cert_id(cert_id)
        if not o or not account_obj or o["account_id"] != account_obj["id"]:
            raise AcmeProblem("unauthorized", "Unknown certificate.", 404)
        cert_path = ops.layout.cert_pem_for_serial(o["cert_serial"])
        # Serve the issuing chain: intermediate (+ root) when two-tier, else the
        # root. Clients build leaf → intermediate → root; they already trust root.
        issuer_path = (ops.layout.int_chain if ops.layout.is_two_tier()
                       else ops.layout.ca_cert)
        try:
            with open(cert_path, "rb") as f:
                leaf = f.read()
            with open(issuer_path, "rb") as f:
                ca = f.read()
        except OSError:
            raise AcmeProblem("serverInternal", "Certificate file is missing.", 500)
        chain = leaf.rstrip() + b"\n" + ca.rstrip() + b"\n"
        resp = Response(chain, content_type="application/pem-certificate-chain")
        resp.headers["Link"] = f'<{abs_url("/acme/directory")}>;rel="index"'
        return resp

    # ------------------------------------------------------- revocation
    @bp.route("/revoke-cert", methods=["POST"])
    def revoke_cert():
        # Either the issuing account (kid) or the certificate key pair (jwk)
        # may sign a revocation (RFC 8555 §7.6).
        parsed, account = read_jws(require_kid=None)
        payload = parsed.payload_json()
        cert_b64 = payload.get("certificate")
        if not cert_b64:
            raise AcmeProblem("malformed", "revoke-cert requires a 'certificate' field.")
        try:
            der = jwsmod.b64u_decode(cert_b64)
            cert = x509.load_der_x509_certificate(der)
        except Exception:  # noqa: BLE001
            raise AcmeProblem("malformed", "The 'certificate' is not valid base64url DER.")

        if ops is None:
            raise AcmeProblem("serverInternal", "Revocation backend unavailable.", 500)
        serial = _openssl_serial(cert.serial_number)
        rec = ops.store.get(serial)
        if not rec:
            raise AcmeProblem("unauthorized", "This certificate was not issued by this CA.", 403)
        if rec["status"] == "revoked":
            raise AcmeProblem("alreadyRevoked", "The certificate is already revoked.", 400)

        authorized = False
        if account is not None:
            o = store.order_by_cert_serial(serial)
            authorized = bool(o and o["account_id"] == account["id"])
        if not authorized and parsed.jwk is not None:
            authorized = (jwsmod.cert_public_key_thumbprint(cert)
                          == jwsmod.jwk_thumbprint(parsed.jwk))
        if not authorized:
            raise AcmeProblem("unauthorized",
                              "The signing key is not authorized to revoke this certificate.", 403)

        passphrase = passphrase_provider() if passphrase_provider else None
        if ops.ca_key_encrypted() and passphrase is None:
            raise AcmeProblem("serverInternal",
                              "The CA key is locked. ACME needs unattended signing — use an "
                              "unencrypted CA key or enable 'keep unlocked across restarts'.", 503)
        try:
            ops.revoke(serial, passphrase)
        except CaError as e:
            raise AcmeProblem("serverInternal", f"Revocation failed: {e}", 500)
        return make_response("", 200)

    # ------------------------------------------------------- key rollover
    @bp.route("/key-change", methods=["POST"])
    def key_change():
        parsed, account = read_jws(require_kid=True)
        if not account:
            raise AcmeProblem("accountDoesNotExist", "Unknown account.", 400)
        # The outer JWS (old key) wraps an inner JWS signed by the NEW key.
        try:
            inner = jwsmod.parse_jws(parsed.payload_bytes, require_nonce=False)
        except jwsmod.JwsError as e:
            raise AcmeProblem(e.acme_type, e.detail, e.status, e.extra)
        if inner.jwk is None:
            raise AcmeProblem("malformed",
                              "keyChange inner JWS must be signed with 'jwk' (the new key).")
        try:
            jwsmod.verify_signature(inner, inner.jwk)
        except jwsmod.JwsError:
            raise AcmeProblem("malformed", "keyChange inner JWS signature is invalid.")
        if inner.url != parsed.url:
            raise AcmeProblem("malformed",
                              "keyChange inner 'url' does not match the request URL.")
        body = inner.payload_json()
        if body.get("account") != account_url(account["id"]):
            raise AcmeProblem("malformed", "keyChange 'account' does not match the signer.")
        old_key = body.get("oldKey")
        if not old_key or jwsmod.jwk_thumbprint(old_key) != account["thumbprint"]:
            raise AcmeProblem("malformed",
                              "keyChange 'oldKey' does not match the account's current key.")

        new_thumb = jwsmod.jwk_thumbprint(inner.jwk)
        if new_thumb == account["thumbprint"]:
            return _account_response(account, status=200)   # no-op
        other = store.get_account_by_thumbprint(new_thumb)
        if other:
            resp = make_response(jsonify(
                {"type": ERROR_NS + "malformed",
                 "detail": "The new key is already in use by another account."}), 409)
            resp.headers["Content-Type"] = "application/problem+json"
            resp.headers["Location"] = account_url(other["id"])
            return resp
        updated = store.update_account_key(
            account["id"], new_thumb, json.dumps(jwsmod.public_jwk(inner.jwk)))
        return _account_response(updated, status=200)

    # ------------------------------------------------------- authz / challenge
    @bp.route("/authz/<azid>", methods=["POST"])
    def authorization(azid):
        parsed, account_obj = read_jws(require_kid=True)
        az = store.get_authorization(azid)
        if not az:
            raise AcmeProblem("malformed", "Unknown authorization.", 404)
        _owned_order(az["order_id"], account_obj)
        return jsonify(_authz_obj(az))

    @bp.route("/chall/<cid>", methods=["POST"])
    def challenge(cid):
        parsed, account_obj = read_jws(require_kid=True)
        ch = store.get_challenge(cid)
        if not ch:
            raise AcmeProblem("malformed", "Unknown challenge.", 404)
        az = store.get_authorization(ch["authz_id"])
        _owned_order(az["order_id"], account_obj)
        # A non-empty POST (not POST-as-GET) is the client saying "I'm ready":
        # move the challenge to processing and validate in the background.
        if not parsed.is_post_as_get and ch["status"] == "pending":
            store.set_challenge_status(ch["id"], "processing")
            acme_validate.start_http01(store, ch["id"], _http01_port_for(account_obj))
            ch = store.get_challenge(ch["id"])
        return jsonify(_challenge_obj(ch))

    # ------------------------------------------------------------- builders
    def _http01_port_for(account):
        """Port to fetch this account's http-01 challenge on: the port on the EAB
        credential it enrolled with (blank → RFC default 80), else the server-wide
        `http01_port`. Lets each client (Caddy on 8031, Proxmox on 80, …) be
        validated on its own port."""
        if account and account.get("eab_kid"):
            eab = store.get_eab(account["eab_kid"])
            if eab:
                return int(eab["http01_port"]) if eab.get("http01_port") else 80
        return int(acme_cfg().get("http01_port", 80))

    def _owned_order(oid, account_obj):
        o = store.get_order(oid)
        if not o:
            raise AcmeProblem("malformed", "Unknown order.", 404)
        if not account_obj or o["account_id"] != account_obj["id"]:
            raise AcmeProblem("unauthorized", "Order does not belong to this account.", 403)
        return o

    def _order_response(o, status):
        authzs = store.authorizations_for_order(o["id"])
        body = {
            "status": o["status"],
            "expires": o["expires"],
            "identifiers": json.loads(o["identifiers_json"]),
            "authorizations": [abs_url(f"/acme/authz/{a['id']}") for a in authzs],
            "finalize": abs_url(f"/acme/order/{o['id']}/finalize"),
        }
        if o["not_before"]:
            body["notBefore"] = o["not_before"]
        if o["not_after"]:
            body["notAfter"] = o["not_after"]
        if o["cert_id"]:
            body["certificate"] = abs_url(f"/acme/cert/{o['cert_id']}")
        if o["error_json"]:
            body["error"] = json.loads(o["error_json"])
        resp = make_response(jsonify(body), status)
        resp.headers["Location"] = abs_url(f"/acme/order/{o['id']}")
        return resp

    def _authz_obj(az):
        obj = {
            "status": az["status"],
            "identifier": {"type": az["identifier_type"], "value": az["identifier_value"]},
            "expires": az["expires"],
            "challenges": [_challenge_obj(c) for c in store.challenges_for_authz(az["id"])],
        }
        return obj

    def _challenge_obj(ch):
        obj = {
            "type": ch["type"],
            "url": abs_url(f"/acme/chall/{ch['id']}"),
            "status": ch["status"],
            "token": ch["token"],
        }
        if ch["validated_at"]:
            obj["validated"] = ch["validated_at"]
        if ch["error_json"]:
            obj["error"] = json.loads(ch["error_json"])
        return obj

    def _csr_dns_names(csr):
        names = set()
        try:
            san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            names = {n.lower() for n in san.get_values_for_type(x509.DNSName)}
        except x509.ExtensionNotFound:
            pass
        if not names:
            cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn:
                names = {cn[0].value.lower()}
        return names

    def _order_validity(o):
        c = acme_cfg()
        days = int(c.get("validity_days", 90))
        maxd = int(c.get("max_validity_days", 397))
        na = o.get("not_after")
        if na:
            try:
                dt = datetime.fromisoformat(str(na).replace("Z", "+00:00"))
                req = (dt - datetime.now(timezone.utc)).days
                if req > 0:
                    days = req
            except ValueError:
                pass
        return max(1, min(days, maxd))

    def _validate_identifiers(identifiers):
        if not isinstance(identifiers, list) or not identifiers:
            raise AcmeProblem("malformed", "Order must include a non-empty 'identifiers' array.")
        allowed = [d.lower() for d in (acme_cfg().get("allowed_domains") or [])]
        out = []
        for idf in identifiers:
            if not isinstance(idf, dict) or idf.get("type") != "dns" or not idf.get("value"):
                raise AcmeProblem("malformed", "Each identifier must be {type:'dns', value:...}.")
            val = str(idf["value"]).strip().lower()
            if val.startswith("*."):
                raise AcmeProblem("rejectedIdentifier",
                                  f"Wildcard identifiers require dns-01, which is not supported "
                                  f"yet: {val}", 400)
            if not _HOSTNAME_RE.match(val):
                raise AcmeProblem("rejectedIdentifier", f"Not a valid DNS name: {val}", 400)
            if allowed and not any(val == d or val.endswith("." + d) for d in allowed):
                raise AcmeProblem("rejectedIdentifier",
                                  f"This CA does not issue certificates for {val}.", 400)
            out.append({"type": "dns", "value": val})
        return out

    # ------------------------------------------------------------- responses
    def _account_response(acct, status):
        body = {
            "status": acct["status"],
            "contact": json.loads(acct["contact"] or "[]"),
            "orders": abs_url(f"/acme/acct/{acct['id']}/orders"),
        }
        resp = make_response(jsonify(body), status)
        resp.headers["Location"] = account_url(acct["id"])
        return resp

    def _verify_eab(eab, parsed, account_thumbprint):
        """Validate an External Account Binding; return the bound kid or None.

        Raises AcmeProblem when EAB is required but missing, or present but
        invalid (unknown/revoked kid, bad HMAC, wrong url, or a payload that
        doesn't bind the account key that signed this request).
        """
        if eab is None:
            if acme_cfg().get("eab_required"):
                raise AcmeProblem("externalAccountRequired",
                                  "This ACME server requires External Account Binding.", 400)
            return None
        if not isinstance(eab, dict) or not isinstance(eab.get("protected"), str):
            raise AcmeProblem("malformed", "externalAccountBinding is malformed.", 400)
        # Read the (as-yet unverified) kid so we can find its MAC key; the
        # signature below covers this same header, so a forged kid can't pass.
        try:
            header = json.loads(jwsmod.b64u_decode(eab["protected"]))
            kid = header.get("kid")
        except Exception:  # noqa: BLE001
            kid = None
        if not kid:
            raise AcmeProblem("malformed", "EAB protected header must carry a 'kid'.", 400)
        cred = store.get_eab(kid)
        if not cred or cred["status"] != "active":
            raise AcmeProblem("unauthorized", "Unknown or revoked EAB key identifier.", 403)
        try:
            protected, payload_bytes = jwsmod.verify_eab(eab, cred["mac_key"])
        except jwsmod.JwsError as e:
            raise AcmeProblem(e.acme_type, e.detail, e.status, e.extra)
        if protected.get("url") != parsed.url:
            raise AcmeProblem("malformed", "EAB 'url' does not match the newAccount URL.", 400)
        try:
            inner_key = json.loads(payload_bytes)
        except ValueError:
            raise AcmeProblem("malformed", "EAB payload is not a JSON JWK.", 400)
        if jwsmod.jwk_thumbprint(inner_key) != account_thumbprint:
            raise AcmeProblem("unauthorized",
                              "EAB does not bind the account key that signed this request.", 403)
        return kid

    def _validate_contacts(contacts):
        if not isinstance(contacts, list):
            raise AcmeProblem("malformed", "'contact' must be an array.", 400)
        for c in contacts:
            if not isinstance(c, str) or not c.startswith("mailto:"):
                raise AcmeProblem("unsupportedContact",
                                  f"Unsupported contact: {c!r} (only mailto: is supported).", 400)

    return bp
