"""TAP request signer (agent side)."""

from __future__ import annotations

import base64
import hashlib
import time
import uuid
from typing import Dict, List, Optional

from aaw_signer import KeyHandle

TAG_BROWSER_AUTH = "agent-browser-auth"
TAG_PAYER_AUTH = "agent-payer-auth"
SIGNATURE_LABEL = "sig2"
DEFAULT_LIFETIME = 8 * 60  # matches the Visa sample


def content_digest_header(body: bytes) -> str:
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode("ascii") + ":"


def signature_params(covered: List[str], created: int, expires: int, key_id: str, alg: str, nonce: str, tag: str) -> str:
    comps = " ".join(f'"{c}"' for c in covered)
    return f'({comps});created={created};expires={expires};keyId="{key_id}";alg="{alg}";nonce="{nonce}";tag="{tag}"'


def signature_base(covered: List[str], values: Dict[str, str], params: str) -> str:
    lines = [f'"{c}": {values[c]}' for c in covered]
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines)


def sign_tap_request(
    handle: KeyHandle,
    *,
    authority: str,
    path: str,
    body: Optional[bytes],
    key_id: str,
    tag: str = TAG_PAYER_AUTH,
    nonce: Optional[str] = None,
    created: Optional[int] = None,
    lifetime: int = DEFAULT_LIFETIME,
    agent_identity: Optional[str] = None,
    override_covered: Optional[List[str]] = None,
) -> Dict[str, str]:
    """Return the HTTP headers to attach: ``Signature-Input``, ``Signature`` and, for
    requests with a body, ``Content-Digest``."""
    created = int(created if created is not None else time.time())
    expires = created + lifetime
    nonce = nonce or str(uuid.uuid4())
    covered = ["@authority", "@path"]
    headers: Dict[str, str] = {}
    values = {"@authority": authority, "@path": path}
    if body is not None:
        cd = content_digest_header(body)
        headers["Content-Digest"] = cd
        values["content-digest"] = cd
        covered.append("content-digest")
    if override_covered is not None:
        covered = override_covered
    params = signature_params(covered, created, expires, key_id, handle.tap_alg, nonce, tag)
    base = signature_base(covered, values, params)
    sig = handle.sign_bytes(base.encode("utf-8"))
    headers["Signature-Input"] = f"{SIGNATURE_LABEL}={params}"
    headers["Signature"] = f"{SIGNATURE_LABEL}=:{base64.b64encode(sig).decode('ascii')}:"
    if agent_identity:
        headers["Signature-Agent"] = f'"{agent_identity}"'
    return headers
