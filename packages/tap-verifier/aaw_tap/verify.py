"""TAP request verification at the merchant gateway.

Order of checks (each failure yields a stable reason code):

1. headers present and parseable (``Signature-Input``, ``Signature``)
2. exactly one signature label; covered components include ``@authority`` and
   ``@path``; ``content-digest`` covered when a body is present
3. ``created``/``expires`` window, maximum lifetime, clock skew
4. operation context: ``tag`` equals the required tag for this endpoint
5. key resolution through the registry-backed trust store (``keyId`` is a hint;
   the registered algorithm must match ``alg``)
6. ``Content-Digest`` recomputed over the body
7. signature over the RFC 9421 signature base
8. nonce replay record inserted atomically (unique ``(keyId, nonce)``)
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from aaw_domain.models import RequestReplayRecord, new_id
from aaw_domain.outcomes import Reason
from aaw_domain.trust import TrustError, TrustStore
from aaw_signer.keys import jwk_to_public_key, verify_bytes

from .signing import signature_base

MAX_LIFETIME = 8 * 60
MAX_SKEW = 60
ALLOWED_ALGS = ("ed25519", "rsa-pss-sha256")
ALLOWED_TAGS = ("agent-browser-auth", "agent-payer-auth")

_INPUT_RE = re.compile(r"^\s*([A-Za-z0-9_-]+)=\(([^)]*)\)\s*;\s*(.*)$", re.S)
_PARAM_RE = re.compile(r'\s*([A-Za-z]+)=("(?:[^"\\]|\\.)*"|[0-9]+)\s*(?:;|$)')
_SIG_RE = re.compile(r"^\s*([A-Za-z0-9_-]+)=:([A-Za-z0-9+/=]+):\s*$")


@dataclass
class TapRequest:
    method: str
    authority: str
    path: str
    headers: Dict[str, str]
    body: Optional[bytes] = None

    def header(self, name: str) -> Optional[str]:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None


@dataclass
class TapVerification:
    ok: bool = False
    reason: Optional[Reason] = None
    detail: str = ""
    key_id: Optional[str] = None
    agent_id: Optional[str] = None
    alg: Optional[str] = None
    tag: Optional[str] = None
    nonce: Optional[str] = None
    created: Optional[int] = None
    expires: Optional[int] = None
    covered: List[str] = field(default_factory=list)
    params: str = ""

    def fail(self, reason: Reason, detail: str) -> "TapVerification":
        self.ok = False
        self.reason = reason
        self.detail = detail
        return self

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "reason": self.reason.value if self.reason else None,
            "detail": self.detail,
            "key_id": self.key_id,
            "agent_id": self.agent_id,
            "alg": self.alg,
            "tag": self.tag,
            "nonce": self.nonce,
            "created": self.created,
            "expires": self.expires,
            "covered": self.covered,
        }


def parse_signature_input(value: str) -> Dict[str, Any]:
    """Parse ``label=("c1" "c2");p=v;...`` leniently (the Visa sample emits spaces)."""
    m = _INPUT_RE.match(value)
    if not m:
        raise ValueError("Signature-Input is not in RFC 9421 form")
    label, comps, rest = m.group(1), m.group(2), m.group(3)
    covered = [c.strip().strip('"') for c in comps.split() if c.strip()]
    params: Dict[str, Any] = {}
    pos = 0
    while pos < len(rest):
        pm = _PARAM_RE.match(rest, pos)
        if not pm:
            raise ValueError(f"malformed signature parameter near {rest[pos:pos + 20]!r}")
        k, v = pm.group(1), pm.group(2)
        params[k.lower()] = v[1:-1] if v.startswith('"') else int(v)
        pos = pm.end()
    return {"label": label, "covered": covered, "params": params, "params_raw": value.split("=", 1)[1]}


def verify_tap_request(
    req: TapRequest,
    trust: TrustStore,
    session: Session,
    now: int,
    *,
    required_tag: Optional[str] = "agent-payer-auth",
    require_content_digest: bool = True,
    trace_id: Optional[str] = None,
    record_replay: bool = True,
) -> TapVerification:
    v = TapVerification()
    sig_input = req.header("signature-input")
    sig = req.header("signature")
    if not sig_input or not sig:
        return v.fail(Reason.REQUEST_SIGNATURE_MISSING, "Signature-Input or Signature header missing")
    if len(sig_input) > 4096 or len(sig) > 4096:
        return v.fail(Reason.REQUEST_SIGNATURE_MALFORMED, "signature headers too large")
    try:
        parsed = parse_signature_input(sig_input)
    except ValueError as exc:
        return v.fail(Reason.REQUEST_SIGNATURE_MALFORMED, str(exc))
    sm = _SIG_RE.match(sig)
    if not sm or sm.group(1) != parsed["label"]:
        return v.fail(Reason.REQUEST_SIGNATURE_MALFORMED, "Signature header label/format mismatch")
    try:
        sig_bytes = base64.b64decode(sm.group(2), validate=True)
    except Exception:
        return v.fail(Reason.REQUEST_SIGNATURE_MALFORMED, "signature is not base64")

    p = parsed["params"]
    v.covered = parsed["covered"]
    v.params = parsed["params_raw"]
    v.key_id = p.get("keyid")
    v.alg = p.get("alg")
    v.tag = p.get("tag")
    v.nonce = p.get("nonce")
    v.created = p.get("created")
    v.expires = p.get("expires")
    for name in ("keyid", "alg", "nonce", "tag", "created", "expires"):
        if name not in p:
            return v.fail(Reason.REQUEST_SIGNATURE_MALFORMED, f"missing signature parameter {name}")
    if not isinstance(v.created, int) or not isinstance(v.expires, int):
        return v.fail(Reason.REQUEST_SIGNATURE_MALFORMED, "created/expires must be integers")

    # coverage
    if "@authority" not in v.covered or "@path" not in v.covered:
        return v.fail(Reason.REQUEST_COVERAGE_INSUFFICIENT, "@authority and @path must be covered")
    if req.body is not None and len(req.body) > 0 and require_content_digest and "content-digest" not in v.covered:
        return v.fail(Reason.REQUEST_COVERAGE_INSUFFICIENT, "requests with a body must cover content-digest")
    for c in v.covered:
        if c not in ("@authority", "@path", "@method", "content-digest", "content-type"):
            return v.fail(Reason.REQUEST_COVERAGE_INSUFFICIENT, f"unsupported covered component {c!r}")

    # time checks
    if v.created > now + MAX_SKEW:
        return v.fail(Reason.REQUEST_NOT_YET_VALID, "signature created in the future")
    if v.expires < now:
        return v.fail(Reason.REQUEST_EXPIRED, "signature expired")
    if v.expires - v.created > MAX_LIFETIME:
        return v.fail(Reason.REQUEST_LIFETIME_TOO_LONG, f"lifetime exceeds {MAX_LIFETIME}s")
    if v.expires <= v.created:
        return v.fail(Reason.REQUEST_SIGNATURE_MALFORMED, "expires must be after created")

    # operation context
    if v.tag not in ALLOWED_TAGS:
        return v.fail(Reason.OPERATION_CONTEXT_MISMATCH, f"unknown tag {v.tag!r}")
    if required_tag and v.tag != required_tag:
        return v.fail(Reason.OPERATION_CONTEXT_MISMATCH, f"tag {v.tag!r} not permitted for this operation")
    if v.alg not in ALLOWED_ALGS:
        return v.fail(Reason.UNSUPPORTED_ALGORITHM, f"alg {v.alg!r} not in allowlist")

    # key resolution
    try:
        key = trust.resolve_tap_key(str(v.key_id), at=now)
    except TrustError as exc:
        return v.fail(exc.reason, str(exc))
    if key.algorithm != v.alg:
        return v.fail(Reason.UNSUPPORTED_ALGORITHM, f"key {v.key_id} registered for {key.algorithm}, request says {v.alg}")
    v.agent_id = key.participant_id
    agent_hdr = req.header("signature-agent")
    if agent_hdr and agent_hdr.strip('"') not in (key.participant_id, f"urn:aaw:agent:{key.participant_id}"):
        return v.fail(Reason.UNKNOWN_AGENT_KEY, "Signature-Agent does not match the registry entry for keyId")

    # content digest
    values: Dict[str, str] = {"@authority": req.authority, "@path": req.path, "@method": req.method.upper()}
    if "content-digest" in v.covered:
        cd = req.header("content-digest")
        if not cd:
            return v.fail(Reason.CONTENT_DIGEST_MISMATCH, "content-digest covered but header missing")
        expected = "sha-256=:" + base64.b64encode(hashlib.sha256(req.body or b"").digest()).decode("ascii") + ":"
        if cd.strip() != expected:
            return v.fail(Reason.CONTENT_DIGEST_MISMATCH, "Content-Digest does not match body")
        values["content-digest"] = cd.strip()
    if "content-type" in v.covered:
        values["content-type"] = req.header("content-type") or ""

    # signature
    base = signature_base(v.covered, values, v.params)
    try:
        pub = jwk_to_public_key(key.public_jwk)
    except Exception as exc:
        return v.fail(Reason.UNKNOWN_AGENT_KEY, f"unusable registry key: {exc}")
    if not verify_bytes(pub, v.alg, base.encode("utf-8"), sig_bytes):
        return v.fail(Reason.REQUEST_SIGNATURE_INVALID, "signature does not verify over the request")

    # replay
    if record_replay:
        try:
            with session.begin_nested():
                session.add(RequestReplayRecord(id=new_id("rr"), key_id=str(v.key_id), nonce=str(v.nonce),
                                                created=v.created, expires=v.expires, first_seen_at=now,
                                                trace_id=trace_id or ""))
                session.flush()
        except IntegrityError:
            return v.fail(Reason.REQUEST_REPLAY, "nonce already used with this key (transport replay)")
    v.ok = True
    v.detail = "verified"
    return v
