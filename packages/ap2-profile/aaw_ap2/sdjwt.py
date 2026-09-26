"""SD-JWT (RFC 9901) and Delegate SD-JWT (draft-gco-oauth-delegate-sd-jwt-00)
serialization primitives used by the AP2 profile.

Compact chain format (draft §5.1.1)::

    <SD-JWT>~<d>~...~~<KB-SD-JWT 1>~<d>~...~~<KB-SD-JWT n>~<d>~

An empty component separates the links; a trailing ``~`` marks a dSD-JWT
(no final KB-JWT). Only ``sha-256`` is accepted for ``_sd_alg``.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from aaw_signer import b64url_decode, b64url_encode

SD_ALG = "sha-256"
MAX_CHAIN_LINKS = 4
MAX_DISCLOSURES = 64
MAX_COMPONENT_BYTES = 128 * 1024


class SdJwtError(Exception):
    def __init__(self, message: str, code: str = "MALFORMED_ARTIFACT"):
        super().__init__(message)
        self.code = code


def hash_b64(data: str) -> str:
    return b64url_encode(hashlib.sha256(data.encode("ascii")).digest())


def new_salt() -> str:
    return b64url_encode(secrets.token_bytes(16))


def make_disclosure(value: Any, name: Optional[str] = None, salt: Optional[str] = None) -> str:
    """Object-property disclosure ``[salt, name, value]`` or array-element ``[salt, value]``."""
    arr = [salt or new_salt(), name, value] if name is not None else [salt or new_salt(), value]
    return b64url_encode(json.dumps(arr, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def digest_disclosure(disclosure_b64: str) -> str:
    return hash_b64(disclosure_b64)


def decode_disclosure(disclosure_b64: str) -> List[Any]:
    try:
        arr = json.loads(b64url_decode(disclosure_b64))
    except Exception as exc:
        raise SdJwtError(f"undecodable disclosure: {exc}") from exc
    if not isinstance(arr, list) or len(arr) not in (2, 3) or not isinstance(arr[0], str):
        raise SdJwtError("disclosure must be [salt, value] or [salt, name, value]")
    return arr


def sd_ref(digest: str) -> Dict[str, str]:
    return {"...": digest}


@dataclass
class Link:
    """One SD-JWT in a chain: a JWS plus the disclosures presented with it."""

    jwt: str
    disclosures: List[str] = field(default_factory=list)

    def serialize(self) -> str:
        return "~".join([self.jwt] + list(self.disclosures)) + "~"

    @property
    def header(self) -> Dict[str, Any]:
        return json.loads(b64url_decode(self.jwt.split(".")[0]))

    @property
    def payload(self) -> Dict[str, Any]:
        return json.loads(b64url_decode(self.jwt.split(".")[1]))

    def sd_hash(self) -> str:
        """``sd_hash`` per RFC 9901 §4.3: digest over the presentation (JWT and
        disclosures, with the trailing ``~``)."""
        return hash_b64(self.serialize())

    def issuer_jwt_hash(self) -> str:
        return hash_b64(self.jwt)

    def select(self, digests: Set[str]) -> "Link":
        """Return a copy presenting only the disclosures whose digest is in ``digests``."""
        return Link(self.jwt, [d for d in self.disclosures if digest_disclosure(d) in digests])


def serialize_chain(links: List[Link]) -> str:
    return "~".join(link.serialize() for link in links)


def parse_chain(compact: str) -> List[Link]:
    if not isinstance(compact, str) or not compact:
        raise SdJwtError("empty chain")
    if not compact.endswith("~"):
        raise SdJwtError("dSD-JWT must end with '~' (dSD-JWT+KB with a final KB-JWT is not used by this profile)")
    parts = compact.split("~")
    if parts[-1] != "":
        raise SdJwtError("unexpected trailing component")
    parts = parts[:-1]
    links: List[Link] = []
    current: Optional[Link] = None
    for comp in parts:
        if len(comp) > MAX_COMPONENT_BYTES:
            raise SdJwtError("component exceeds size limit", code="INPUT_TOO_LARGE")
        if comp == "":
            if current is None:
                raise SdJwtError("chain separator without a preceding SD-JWT")
            links.append(current)
            current = None
            continue
        if current is None:
            if comp.count(".") != 2:
                raise SdJwtError("expected a compact JWS at the start of a chain link")
            current = Link(jwt=comp)
        else:
            current.disclosures.append(comp)
            if len(current.disclosures) > MAX_DISCLOSURES:
                raise SdJwtError("too many disclosures", code="INPUT_TOO_LARGE")
    if current is not None:
        links.append(current)
    if not links:
        raise SdJwtError("no SD-JWT found")
    if len(links) > MAX_CHAIN_LINKS:
        raise SdJwtError("chain too long", code="INPUT_TOO_LARGE")
    return links


# --------------------------------------------------------------------------- #
# Disclosure resolution (RFC 9901 §7.1 steps for _sd / ...)
# --------------------------------------------------------------------------- #


class ResolvedClaims:
    def __init__(self, claims: Any, used: Set[str], available: Dict[str, List[Any]]):
        self.claims = claims
        self.used = used
        self.available = available

    def unused(self) -> Set[str]:
        return set(self.available) - self.used


def index_disclosures(disclosures: List[str]) -> Dict[str, List[Any]]:
    by_digest: Dict[str, List[Any]] = {}
    for d in disclosures:
        dg = digest_disclosure(d)
        if dg in by_digest:
            raise SdJwtError("duplicate disclosure digest", code="DISCLOSURE_DIGEST_MISMATCH")
        by_digest[dg] = decode_disclosure(d)
    return by_digest


def resolve_claims(payload: Any, disclosures: List[str]) -> ResolvedClaims:
    """Replace ``_sd`` entries and ``{"...": digest}`` array elements with disclosed
    values, recursively. Undisclosed digests are dropped. Every provided disclosure
    must be reachable (caller may treat unused ones as an error)."""
    available = index_disclosures(disclosures)
    used: Set[str] = set()
    seen_digests: Set[str] = set()

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            out: Dict[str, Any] = {}
            for k, v in node.items():
                if k in ("_sd", "_sd_alg"):
                    continue
                out[k] = walk(v)
            sd = node.get("_sd", [])
            if not isinstance(sd, list):
                raise SdJwtError("_sd must be an array")
            for dg in sd:
                if not isinstance(dg, str):
                    raise SdJwtError("_sd digest must be a string")
                if dg in seen_digests:
                    raise SdJwtError("digest appears more than once", code="DISCLOSURE_DIGEST_MISMATCH")
                seen_digests.add(dg)
                disc = available.get(dg)
                if disc is None:
                    continue
                if len(disc) != 3:
                    raise SdJwtError("object property disclosure must have a claim name",
                                     code="DISCLOSURE_DIGEST_MISMATCH")
                name = disc[1]
                if not isinstance(name, str) or name in out or name in ("_sd", "..."):
                    raise SdJwtError(f"invalid or duplicate disclosed claim name {name!r}",
                                     code="DISCLOSURE_DIGEST_MISMATCH")
                used.add(dg)
                out[name] = walk(disc[2])
            return out
        if isinstance(node, list):
            out_list: List[Any] = []
            for el in node:
                if isinstance(el, dict) and set(el.keys()) == {"..."}:
                    dg = el["..."]
                    if not isinstance(dg, str):
                        raise SdJwtError("array element digest must be a string")
                    if dg in seen_digests:
                        raise SdJwtError("digest appears more than once", code="DISCLOSURE_DIGEST_MISMATCH")
                    seen_digests.add(dg)
                    disc = available.get(dg)
                    if disc is None:
                        continue
                    if len(disc) != 2:
                        raise SdJwtError("array element disclosure must not carry a claim name",
                                         code="DISCLOSURE_DIGEST_MISMATCH")
                    used.add(dg)
                    out_list.append(walk(disc[1]))
                else:
                    out_list.append(walk(el))
            return out_list
        return node

    return ResolvedClaims(walk(payload), used, available)


def sd_alg_ok(payload: Dict[str, Any]) -> bool:
    return payload.get("_sd_alg", SD_ALG) == SD_ALG


def digests_in(payload: Any) -> List[str]:
    """All digests referenced (``_sd`` and ``...``) at any depth, in document order."""
    out: List[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for dg in node.get("_sd", []) or []:
                out.append(dg)
            for k, v in node.items():
                if k == "_sd":
                    continue
                if k == "..." and isinstance(v, str) and len(node) == 1:
                    out.append(v)
                else:
                    walk(v)
        elif isinstance(node, list):
            for el in node:
                walk(el)

    walk(payload)
    return out


def split_jws(token: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    try:
        h, p, _ = token.split(".")
        return json.loads(b64url_decode(h)), json.loads(b64url_decode(p))
    except Exception as exc:
        raise SdJwtError(f"malformed JWS: {exc}") from exc
