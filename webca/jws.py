"""JWS/JWK handling for the ACME server (RFC 8555 §6, RFC 7638 thumbprints).

Signature verification is delegated to jwcrypto so we don't hand-roll crypto.
This module validates the JWS *structure* and *signature* only; ACME-level
checks (nonce freshness, url match, account lookup, issuance policy) live in the
ACME endpoints, which have the request/nonce-store context.

ACME requires the flattened JWS JSON serialization with a single signature, a
protected header carrying `alg`, `nonce`, `url` and exactly one of `jwk`/`kid`,
and forbids unprotected headers, detached payloads and RFC 7797 (`b64`).
"""
import base64
import json

from jwcrypto import jwk as _jwk, jws as _jws
from jwcrypto.jws import InvalidJWSSignature, InvalidJWSObject

# Signature algorithms we accept — never "none" and never a MAC (HS*).
SUPPORTED_ALGS = {"ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "EdDSA"}


class JwsError(Exception):
    """A JWS/JWK failure mapped to an ACME problem type (RFC 8555 §6.7)."""

    def __init__(self, acme_type, detail, status=400, extra=None):
        super().__init__(detail)
        self.acme_type = acme_type      # e.g. "malformed", "badSignatureAlgorithm"
        self.detail = detail
        self.status = status
        self.extra = extra or {}         # merged into the problem document


# ------------------------------------------------------------- base64url
def b64u_decode(data):
    if isinstance(data, str):
        data = data.encode("ascii")
    return base64.urlsafe_b64decode(data + b"=" * (-len(data) % 4))


def b64u_encode(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# ------------------------------------------------------------- JWK helpers
def _as_jwk(obj):
    if isinstance(obj, _jwk.JWK):
        return obj
    if not isinstance(obj, dict):
        raise JwsError("malformed", "JWK must be a JSON object")
    try:
        return _jwk.JWK(**obj)
    except Exception as e:  # noqa: BLE001
        raise JwsError("badPublicKey", f"Invalid JWK: {e}")


def jwk_thumbprint(obj):
    """RFC 7638 SHA-256 thumbprint, base64url without padding."""
    return _as_jwk(obj).thumbprint()


def public_jwk(obj):
    """Return the canonical public JWK dict (private fields stripped)."""
    return json.loads(_as_jwk(obj).export_public())


def key_authorization(token, thumbprint):
    """RFC 8555 §8.1: token || '.' || base64url(SHA256(JWK))."""
    return f"{token}.{thumbprint}"


# ------------------------------------------------------------- parsing
class ParsedJws:
    def __init__(self, protected, payload_b64, signature_b64, raw_json):
        self.protected = protected
        self.payload_b64 = payload_b64
        self.signature_b64 = signature_b64
        self.raw_json = raw_json
        self.alg = protected.get("alg")
        self.kid = protected.get("kid")
        self.jwk = protected.get("jwk")
        self.nonce = protected.get("nonce")
        self.url = protected.get("url")
        self.verified_key = None

    @property
    def is_post_as_get(self):
        # POST-as-GET carries an empty string payload (RFC 8555 §6.3).
        return self.payload_b64 == ""

    @property
    def payload_bytes(self):
        return b"" if self.payload_b64 == "" else b64u_decode(self.payload_b64)

    def payload_json(self):
        if self.is_post_as_get or self.payload_bytes == b"":
            return {}
        try:
            obj = json.loads(self.payload_bytes)
        except ValueError:
            raise JwsError("malformed", "JWS payload is not valid JSON")
        if not isinstance(obj, dict):
            raise JwsError("malformed", "JWS payload must be a JSON object")
        return obj

    def thumbprint(self):
        key = self.verified_key if self.verified_key is not None else self.jwk
        if key is None:
            return None
        return jwk_thumbprint(key)


def cert_public_key_thumbprint(cert):
    """RFC 7638 thumbprint of an X.509 certificate's public key.

    Used to authorize an ACME revocation signed by the certificate's own key
    pair (RFC 8555 §7.6): compare this to the JWS signing key's thumbprint.
    """
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pem = cert.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return _jwk.JWK.from_pem(pem).thumbprint()


def parse_jws(raw_body, require_nonce=True):
    """Parse and structurally validate a flattened JWS (no signature check yet).

    `require_nonce` is True for normal ACME requests; the inner JWS of a
    keyChange (RFC 8555 §7.3.5) carries no nonce, so callers pass False there.
    """
    if isinstance(raw_body, (bytes, bytearray)):
        raw_body = bytes(raw_body).decode("utf-8", "replace")
    try:
        obj = json.loads(raw_body)
    except ValueError:
        raise JwsError("malformed", "Request body is not valid JSON")
    if not isinstance(obj, dict):
        raise JwsError("malformed", "JWS must be a JSON object")
    if "signatures" in obj:
        raise JwsError("malformed", "JWS must use the flattened serialization (one signature)")
    if "header" in obj:
        raise JwsError("malformed", "JWS must not contain an unprotected header")
    for field in ("protected", "payload", "signature"):
        if field not in obj or not isinstance(obj[field], str):
            raise JwsError("malformed", f"JWS '{field}' is missing or not a string")
    try:
        protected = json.loads(b64u_decode(obj["protected"]))
    except Exception:  # noqa: BLE001
        raise JwsError("malformed", "JWS protected header is not valid base64url JSON")
    if not isinstance(protected, dict):
        raise JwsError("malformed", "JWS protected header must be a JSON object")
    if "b64" in protected:
        raise JwsError("malformed", "JWS 'b64' (RFC 7797) is not allowed")

    alg = protected.get("alg")
    if alg not in SUPPORTED_ALGS:
        raise JwsError("badSignatureAlgorithm", f"Unsupported JWS 'alg': {alg!r}",
                       extra={"algorithms": sorted(SUPPORTED_ALGS)})
    if ("jwk" in protected) == ("kid" in protected):
        raise JwsError("malformed", "JWS must contain exactly one of 'jwk' or 'kid'")
    if require_nonce and "nonce" not in protected:
        raise JwsError("badNonce", "JWS protected header is missing 'nonce'")
    if "url" not in protected:
        raise JwsError("malformed", "JWS protected header is missing 'url'")
    return ParsedJws(protected, obj["payload"], obj["signature"], raw_body)


def verify_signature(parsed, key):
    """Verify the JWS signature against `key` (JWK dict or jwcrypto JWK)."""
    k = _as_jwk(key)
    token = _jws.JWS()
    try:
        token.deserialize(parsed.raw_json)
        token.verify(k, alg=parsed.alg)
    except (InvalidJWSSignature, InvalidJWSObject):
        raise JwsError("unauthorized", "JWS signature verification failed")
    except Exception as e:  # noqa: BLE001
        raise JwsError("unauthorized", f"JWS verification failed: {e}")
    parsed.verified_key = key
    return parsed


def verify_eab(eab, mac_key_b64u):
    """Verify an External Account Binding JWS (RFC 8555 §7.3.4).

    The EAB is a flattened JWS (dict with protected/payload/signature) signed
    with HS256 over the account's public JWK, using a symmetric MAC key the CA
    issued out-of-band. Returns (protected_header, payload_bytes) on success.
    """
    if not isinstance(eab, dict):
        raise JwsError("malformed", "externalAccountBinding must be a JSON object")
    for field in ("protected", "payload", "signature"):
        if field not in eab or not isinstance(eab[field], str):
            raise JwsError("malformed", f"EAB '{field}' is missing or not a string")
    try:
        protected = json.loads(b64u_decode(eab["protected"]))
    except Exception:  # noqa: BLE001
        raise JwsError("malformed", "EAB protected header is not valid base64url JSON")
    if not isinstance(protected, dict):
        raise JwsError("malformed", "EAB protected header must be a JSON object")
    if protected.get("alg") != "HS256":
        raise JwsError("badSignatureAlgorithm",
                       "EAB must be signed with HS256", extra={"algorithms": ["HS256"]})
    try:
        key = _jwk.JWK(kty="oct", k=mac_key_b64u)
    except Exception:  # noqa: BLE001
        raise JwsError("serverInternal", "Stored EAB MAC key is invalid", 500)
    token = _jws.JWS()
    try:
        token.deserialize(json.dumps(eab))
        token.verify(key, alg="HS256")
    except (InvalidJWSSignature, InvalidJWSObject):
        raise JwsError("unauthorized", "EAB signature verification failed", 403)
    except Exception as e:  # noqa: BLE001
        raise JwsError("unauthorized", f"EAB verification failed: {e}", 403)
    return protected, b64u_decode(eab["payload"])


def verify_jws(raw_body, key_resolver):
    """Parse, resolve the key, and verify. Returns a ParsedJws.

    - `jwk` in the header (newAccount etc.): the request is verified against that
      embedded key.
    - `kid` in the header: `key_resolver(kid)` must return the account's stored
      JWK (dict or jwcrypto JWK), or None -> accountDoesNotExist.
    """
    parsed = parse_jws(raw_body)
    if parsed.jwk is not None:
        key = parsed.jwk
    else:
        key = key_resolver(parsed.kid)
        if key is None:
            raise JwsError("accountDoesNotExist", "Unknown account URL in 'kid'")
    return verify_signature(parsed, key)
