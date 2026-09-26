"""Signer boundary.

Private keys live only inside this package. Other packages receive a
``KeyHandle`` (which signs) or a public JWK (which verifies). The agent
process never receives the user's ``KeyHandle``; it receives only the
artifacts the user signing component produced.
"""

from .keys import (
    KeyHandle,
    b64url_decode,
    b64url_encode,
    generate_ed25519,
    generate_es256,
    jwk_thumbprint,
    public_jwk_from_handle,
)
from .jws import SignatureError, peek_header, peek_payload, sign_compact, verify_compact
from .keystore import DevKeyStore
from .user_component import ApprovedConsent, ConsentBindingError, UserSigningComponent

__all__ = [
    "KeyHandle",
    "b64url_decode",
    "b64url_encode",
    "generate_ed25519",
    "generate_es256",
    "jwk_thumbprint",
    "public_jwk_from_handle",
    "SignatureError",
    "peek_header",
    "peek_payload",
    "sign_compact",
    "verify_compact",
    "DevKeyStore",
    "ApprovedConsent",
    "ConsentBindingError",
    "UserSigningComponent",
]
