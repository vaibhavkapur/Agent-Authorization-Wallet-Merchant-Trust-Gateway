"""Development key store.

Every participant in the local demo has a distinct key. Keys are generated on
first use and persisted as private JWKs under ``AAW_KEYS_DIR`` (default
``./.keys``) so restarts keep verifying previously produced evidence. With
``directory=None`` the store is in-memory (tests).

This is a **simulated** key custody boundary. Nothing here is production key
management.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Dict, Optional

from .keys import KeyHandle

# name -> (algorithm family, role description)
DEFAULT_KEYS = {
    "test_issuer": ("es256", "Test credential issuer (L1 credentials / user credential SD-JWT)"),
    "user_device": ("es256", "Simulated user device key bound by the issuer credential cnf"),
    "agent_shopping_es256": ("es256", "Shopping agent mandate key (cnf in open mandates)"),
    "agent_shopping_ed25519": ("ed25519", "Shopping agent TAP request-signing key"),
    "merchant_a": ("es256", "Merchant A checkout signer"),
    "merchant_b": ("es256", "Merchant B checkout signer"),
    "merchant_gateway": ("es256", "Merchant gateway receipt signer"),
    "payment_processor": ("es256", "Simulated payment processor receipt signer"),
    "wallet_service": ("es256", "Wallet service (trusted surface) attestation signer"),
    "rogue_agent_es256": ("es256", "Unauthorized agent key used for negative tests"),
    "rogue_agent_ed25519": ("ed25519", "Unauthorized TAP key used for negative tests"),
}


class DevKeyStore:
    def __init__(self, directory: Optional[str] = None):
        self._dir = Path(directory) if directory else None
        self._cache: Dict[str, KeyHandle] = {}
        self._lock = threading.Lock()
        if self._dir:
            self._dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_env(cls) -> "DevKeyStore":
        directory = os.environ.get("AAW_KEYS_DIR", ".keys")
        if directory in ("", "memory"):
            return cls(None)
        return cls(directory)

    def get(self, name: str) -> KeyHandle:
        with self._lock:
            if name in self._cache:
                return self._cache[name]
            family, role = DEFAULT_KEYS.get(name, ("es256", name))
            handle = self._load(name, role)
            if handle is None:
                kid = f"{name}-key-1"
                handle = KeyHandle.new_es256(kid, role) if family == "es256" else KeyHandle.new_ed25519(kid, role)
                if not self._save_new(name, handle):
                    # another process created the key first; use theirs so all services agree
                    handle = self._load(name, role) or handle
            self._cache[name] = handle
            return handle

    def rotate(self, name: str) -> KeyHandle:
        """Generate a new key for ``name`` (kid suffix incremented). The previous
        handle stays retrievable through :meth:`historical` so old evidence still verifies."""
        with self._lock:
            old = self._cache.get(name) or self._load(name, name)
            family, role = DEFAULT_KEYS.get(name, ("es256", name))
            n = 1
            if old and old.kid.rsplit("-", 1)[-1].isdigit():
                n = int(old.kid.rsplit("-", 1)[-1]) + 1
            kid = f"{name}-key-{n}"
            handle = KeyHandle.new_es256(kid, role) if family == "es256" else KeyHandle.new_ed25519(kid, role)
            if old:
                self._cache[f"{name}@{old.kid}"] = old
                self._save(f"{name}@{old.kid}", old)
            self._save(name, handle)
            self._cache[name] = handle
            return handle

    def historical(self, name: str, kid: str) -> Optional[KeyHandle]:
        cur = self._cache.get(name)
        if cur and cur.kid == kid:
            return cur
        return self._cache.get(f"{name}@{kid}") or self._load(f"{name}@{kid}", name)

    def names(self):
        return list(DEFAULT_KEYS.keys())

    # -- persistence ----------------------------------------------------------

    def _path(self, name: str) -> Optional[Path]:
        return (self._dir / f"{name}.json") if self._dir else None

    def _load(self, name: str, role: str) -> Optional[KeyHandle]:
        path = self._path(name)
        if not path or not path.exists():
            return None
        data = json.loads(path.read_text())
        return KeyHandle.from_private_jwk(data, role=role)

    def _save(self, name: str, handle: KeyHandle) -> None:
        path = self._path(name)
        if not path:
            return
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(handle.private_jwk()))
        os.chmod(tmp, 0o600)
        tmp.replace(path)

    def _save_new(self, name: str, handle: KeyHandle) -> bool:
        """Create the key file only if it does not exist yet (O_EXCL). Returns False if
        another process won the race."""
        path = self._path(name)
        if not path:
            return True
        try:
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return False
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(handle.private_jwk()))
        return True
