"""Compact JWS helpers built on jwcrypto (maintained JOSE library).

All verification goes through an explicit algorithm allowlist; ``alg`` from
the token header is never trusted on its own.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, Optional, Tuple

from jwcrypto import jwk as jwc_jwk
from jwcrypto import jws as jwc_jws
from jwcrypto.jws import InvalidJWSObject, InvalidJWSSignature

from .keys import KeyHandle, b64url_decode, b64url_encode, public_jwk_strip

DEFAULT_ALLOWED_ALGS = ("ES256",)
MAX_TOKEN_BYTES = 256 * 1024


class SignatureError(Exception):
    """Raised when a JWS cannot be parsed or its signature/algorithm is not acceptable."""

    def __init__(self, message: str, code: str = "INVALID_SIGNATURE"):
        super().__init__(message)
        self.code = code


def _json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_compact(handle: KeyHandle, header: Dict[str, Any], payload: Any) -> str:
    """Sign ``payload`` (dict or bytes) with the handle. ``alg`` is derived from the key
    and cannot be overridden by the caller."""
    hdr = dict(header)
    hdr["alg"] = handle.alg
    body = payload if isinstance(payload, (bytes, bytearray)) else _json_bytes(payload)
    key = jwc_jwk.JWK.from_pyca(handle._private)  # noqa: SLF001 - inside the signer boundary
    token = jwc_jws.JWS(bytes(body))
    token.add_signature(key, alg=handle.alg, protected=json.dumps(hdr, separators=(",", ":")))
    return token.serialize(compact=True)


def peek_header(token: str) -> Dict[str, Any]:
    try:
        return json.loads(b64url_decode(token.split(".")[0]))
    except Exception as exc:  # pragma: no cover - defensive
        raise SignatureError(f"malformed JWS header: {exc}", code="MALFORMED_ARTIFACT") from exc


def peek_payload(token: str) -> Dict[str, Any]:
    try:
        return json.loads(b64url_decode(token.split(".")[1]))
    except Exception as exc:
        raise SignatureError(f"malformed JWS payload: {exc}", code="MALFORMED_ARTIFACT") from exc


def verify_compact(
    token: str,
    public_jwk: Dict[str, Any],
    allowed_algs: Iterable[str] = DEFAULT_ALLOWED_ALGS,
    expected_typ: Optional[str] = None,
) -> Tuple[Dict[str, Any], bytes]:
    """Verify a compact JWS and return ``(header, payload_bytes)``.

    Raises :class:`SignatureError` with a stable ``code`` on any failure.
    """
    if not isinstance(token, str) or token.count(".") != 2:
        raise SignatureError("not a compact JWS", code="MALFORMED_ARTIFACT")
    if len(token) > MAX_TOKEN_BYTES:
        raise SignatureError("token exceeds size limit", code="INPUT_TOO_LARGE")
    header = peek_header(token)
    alg = header.get("alg")
    allowed = tuple(allowed_algs)
    if alg not in allowed:
        raise SignatureError(f"algorithm {alg!r} not in allowlist {allowed}", code="UNSUPPORTED_ALGORITHM")
    if expected_typ is not None and header.get("typ") != expected_typ:
        raise SignatureError(f"unexpected typ {header.get('typ')!r}", code="MALFORMED_ARTIFACT")
    try:
        key = jwc_jwk.JWK(**public_jwk_strip(public_jwk))
    except Exception as exc:
        raise SignatureError(f"unusable public key: {exc}", code="UNKNOWN_KEY") from exc
    obj = jwc_jws.JWS()
    obj.allowed_algs = list(allowed)
    try:
        obj.deserialize(token)
        obj.verify(key, alg=alg)
    except InvalidJWSSignature as exc:
        raise SignatureError("signature verification failed", code="INVALID_SIGNATURE") from exc
    except InvalidJWSObject as exc:
        raise SignatureError(f"malformed JWS: {exc}", code="MALFORMED_ARTIFACT") from exc
    except Exception as exc:
        raise SignatureError(f"signature verification failed: {exc}", code="INVALID_SIGNATURE") from exc
    return header, bytes(obj.payload)


def verify_compact_json(token: str, public_jwk: Dict[str, Any], **kw) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    header, payload = verify_compact(token, public_jwk, **kw)
    try:
        body = json.loads(payload)
    except Exception as exc:
        raise SignatureError("payload is not JSON", code="MALFORMED_ARTIFACT") from exc
    if not isinstance(body, dict):
        raise SignatureError("payload is not a JSON object", code="MALFORMED_ARTIFACT")
    return header, body


__all__ = [
    "SignatureError",
    "sign_compact",
    "verify_compact",
    "verify_compact_json",
    "peek_header",
    "peek_payload",
    "b64url_encode",
    "b64url_decode",
]
