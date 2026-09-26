"""Trusted Agent Protocol (TAP) request signing and gateway verification.

Profile pin: Visa reference implementation ``visa/trusted-agent-protocol`` @
16d59bdf3f8a542bc538d0962edbb80ea30a02af (RFC 9421 HTTP Message Signatures,
label ``sig2``, covered components ``@authority`` ``@path``, parameters
``created`` ``expires`` ``keyId`` ``alg`` ``nonce`` ``tag``, algorithms
``ed25519`` and ``rsa-pss-sha256``, registry lookup by ``keyId``, nonce replay
cache, 8 minute lifetime).

Local extension (documented in docs/protocol-versions/tap.md): requests that
carry a body MUST also cover ``content-digest`` (RFC 9530, sha-256). The
gateway rejects payment operations whose ``tag`` is not ``agent-payer-auth``.
"""

from .signing import TAG_BROWSER_AUTH, TAG_PAYER_AUTH, content_digest_header, sign_tap_request
from .verify import TapRequest, TapVerification, parse_signature_input, verify_tap_request

__all__ = [
    "TAG_BROWSER_AUTH",
    "TAG_PAYER_AUTH",
    "content_digest_header",
    "sign_tap_request",
    "TapRequest",
    "TapVerification",
    "parse_signature_input",
    "verify_tap_request",
]
