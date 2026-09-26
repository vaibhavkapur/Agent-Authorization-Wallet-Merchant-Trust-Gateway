"""Key material helpers.

Algorithms used by this project (see docs/protocol-versions):

* ``ES256`` (ECDSA P-256 / SHA-256) for every JOSE artifact: issuer credentials,
  user-signed mandates, agent-signed closed mandates, merchant checkout JWTs and
  verifier receipts. AP2 requires a non-deterministic signature scheme for the
  checkout JWT, which ES256 satisfies.
* ``Ed25519`` for TAP (RFC 9421) HTTP message signatures, matching the Visa
  sample implementation's default algorithm.
* ``rsa-pss-sha256`` is accepted by the TAP verifier for parity with the Visa
  sample but is not used by any local signer.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    if not isinstance(data, str):
        raise ValueError("base64url input must be a string")
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _int_to_b64url(n: int, length: int) -> str:
    return b64url_encode(n.to_bytes(length, "big"))


def _b64url_to_int(s: str) -> int:
    return int.from_bytes(b64url_decode(s), "big")


# --------------------------------------------------------------------------- #
# JWK conversions
# --------------------------------------------------------------------------- #


def ec_public_jwk(key: ec.EllipticCurvePublicKey, kid: Optional[str] = None) -> Dict[str, Any]:
    if not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("only P-256 keys are supported")
    nums = key.public_numbers()
    jwk: Dict[str, Any] = {
        "kty": "EC",
        "crv": "P-256",
        "x": _int_to_b64url(nums.x, 32),
        "y": _int_to_b64url(nums.y, 32),
    }
    if kid:
        jwk["kid"] = kid
    return jwk


def ec_private_jwk(key: ec.EllipticCurvePrivateKey, kid: Optional[str] = None) -> Dict[str, Any]:
    jwk = ec_public_jwk(key.public_key(), kid)
    jwk["d"] = _int_to_b64url(key.private_numbers().private_value, 32)
    return jwk


def ed25519_public_jwk(key: ed25519.Ed25519PublicKey, kid: Optional[str] = None) -> Dict[str, Any]:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    jwk: Dict[str, Any] = {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(raw)}
    if kid:
        jwk["kid"] = kid
    return jwk


def ed25519_private_jwk(key: ed25519.Ed25519PrivateKey, kid: Optional[str] = None) -> Dict[str, Any]:
    jwk = ed25519_public_jwk(key.public_key(), kid)
    raw = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    jwk["d"] = b64url_encode(raw)
    return jwk


def jwk_to_public_key(jwk: Dict[str, Any]):
    """Return a ``cryptography`` public key for an EC P-256, OKP Ed25519 or RSA JWK."""
    kty = jwk.get("kty")
    if kty == "EC":
        if jwk.get("crv") != "P-256":
            raise ValueError("unsupported EC curve")
        nums = ec.EllipticCurvePublicNumbers(_b64url_to_int(jwk["x"]), _b64url_to_int(jwk["y"]), ec.SECP256R1())
        return nums.public_key()
    if kty == "OKP":
        if jwk.get("crv") != "Ed25519":
            raise ValueError("unsupported OKP curve")
        return ed25519.Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"]))
    if kty == "RSA":
        nums = rsa.RSAPublicNumbers(_b64url_to_int(jwk["e"]), _b64url_to_int(jwk["n"]))
        return nums.public_key()
    raise ValueError("unsupported key type")


def jwk_to_private_key(jwk: Dict[str, Any]):
    kty = jwk.get("kty")
    if kty == "EC":
        pub = jwk_to_public_key(jwk)
        return ec.EllipticCurvePrivateNumbers(_b64url_to_int(jwk["d"]), pub.public_numbers()).private_key()
    if kty == "OKP":
        return ed25519.Ed25519PrivateKey.from_private_bytes(b64url_decode(jwk["d"]))
    raise ValueError("unsupported private key type")


def public_jwk_from_handle(handle: "KeyHandle") -> Dict[str, Any]:
    return handle.public_jwk()


def jwk_thumbprint(jwk: Dict[str, Any]) -> str:
    """RFC 7638 SHA-256 thumbprint (base64url)."""
    kty = jwk.get("kty")
    if kty == "EC":
        members = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "OKP":
        members = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
    elif kty == "RSA":
        members = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    else:
        raise ValueError("unsupported key type")
    canon = json.dumps(members, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return b64url_encode(hashlib.sha256(canon).digest())


def public_jwk_strip(jwk: Dict[str, Any]) -> Dict[str, Any]:
    """Return only the public members of a JWK (never leak ``d``)."""
    return {k: v for k, v in jwk.items() if k in ("kty", "crv", "x", "y", "n", "e", "kid", "alg", "use")}


# --------------------------------------------------------------------------- #
# Generation
# --------------------------------------------------------------------------- #


def generate_es256() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def generate_ed25519() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


# --------------------------------------------------------------------------- #
# Key handle
# --------------------------------------------------------------------------- #


@dataclass
class KeyHandle:
    """A signing capability. Holds the private key; exposes only signing operations
    and the public JWK. ``alg`` is the JOSE algorithm for JWS artifacts (``ES256``
    or ``EdDSA``)."""

    kid: str
    _private: Any
    role: str = ""

    @classmethod
    def from_private_jwk(cls, jwk: Dict[str, Any], role: str = "") -> "KeyHandle":
        return cls(kid=jwk.get("kid") or jwk_thumbprint(jwk), _private=jwk_to_private_key(jwk), role=role)

    @classmethod
    def new_es256(cls, kid: str, role: str = "") -> "KeyHandle":
        return cls(kid=kid, _private=generate_es256(), role=role)

    @classmethod
    def new_ed25519(cls, kid: str, role: str = "") -> "KeyHandle":
        return cls(kid=kid, _private=generate_ed25519(), role=role)

    # -- properties -----------------------------------------------------------

    @property
    def alg(self) -> str:
        if isinstance(self._private, ec.EllipticCurvePrivateKey):
            return "ES256"
        if isinstance(self._private, ed25519.Ed25519PrivateKey):
            return "EdDSA"
        raise ValueError("unsupported key")

    @property
    def tap_alg(self) -> str:
        """Algorithm identifier used in TAP ``Signature-Input`` parameters."""
        if isinstance(self._private, ed25519.Ed25519PrivateKey):
            return "ed25519"
        if isinstance(self._private, rsa.RSAPrivateKey):
            return "rsa-pss-sha256"
        raise ValueError("key type not usable for TAP signatures")

    def public_jwk(self) -> Dict[str, Any]:
        if isinstance(self._private, ec.EllipticCurvePrivateKey):
            return ec_public_jwk(self._private.public_key(), self.kid)
        if isinstance(self._private, ed25519.Ed25519PrivateKey):
            return ed25519_public_jwk(self._private.public_key(), self.kid)
        raise ValueError("unsupported key")

    def public_key(self):
        return self._private.public_key()

    def private_jwk(self) -> Dict[str, Any]:
        """Serialization for the dev keystore only. Never returned over an API."""
        if isinstance(self._private, ec.EllipticCurvePrivateKey):
            return ec_private_jwk(self._private, self.kid)
        if isinstance(self._private, ed25519.Ed25519PrivateKey):
            return ed25519_private_jwk(self._private, self.kid)
        raise ValueError("unsupported key")

    def ec_private_key(self) -> ec.EllipticCurvePrivateKey:
        """Used only by profile adapters that must call a pinned reference
        implementation taking a ``cryptography`` private key (the VI reference
        implementation). The key object must not be persisted or logged."""
        if not isinstance(self._private, ec.EllipticCurvePrivateKey):
            raise ValueError("not an EC key")
        return self._private

    # -- signing --------------------------------------------------------------

    def sign_bytes(self, data: bytes) -> bytes:
        """Raw signature over ``data``. ES256 → raw r||s (JWS style); Ed25519 → 64 bytes;
        RSA → PSS/SHA-256."""
        if isinstance(self._private, ec.EllipticCurvePrivateKey):
            der = self._private.sign(data, ec.ECDSA(hashes.SHA256()))
            r, s = decode_dss_signature(der)
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")
        if isinstance(self._private, ed25519.Ed25519PrivateKey):
            return self._private.sign(data)
        if isinstance(self._private, rsa.RSAPrivateKey):
            return self._private.sign(
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
        raise ValueError("unsupported key")


def verify_bytes(public_key, alg: str, data: bytes, signature: bytes) -> bool:
    """Verify a raw signature produced by :meth:`KeyHandle.sign_bytes`.

    ``alg`` is one of ``ES256``, ``EdDSA``/``ed25519``, ``rsa-pss-sha256``.
    """
    try:
        if alg == "ES256":
            if not isinstance(public_key, ec.EllipticCurvePublicKey) or len(signature) != 64:
                return False
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            public_key.verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))
            return True
        if alg in ("EdDSA", "ed25519"):
            if not isinstance(public_key, ed25519.Ed25519PublicKey) or len(signature) != 64:
                return False
            public_key.verify(signature, data)
            return True
        if alg == "rsa-pss-sha256":
            if not isinstance(public_key, rsa.RSAPublicKey):
                return False
            public_key.verify(
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True
    except Exception:
        return False
    return False
