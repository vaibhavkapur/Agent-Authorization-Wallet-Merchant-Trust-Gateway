"""Process context for the wallet API: runtime, profiles, coordinator, clients."""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

import httpx

from aaw_ap2 import AP2Profile
from aaw_domain.bootstrap import bootstrap
from aaw_domain.clock import Clock
from aaw_domain.profiles import register_profile
from aaw_domain.runtime import Runtime
from aaw_exec import Coordinator, ReceiptSigner, ReceiptSigners
from aaw_signer import UserSigningComponent
from aaw_vi import VIProfile

from .settings import Settings


class AppContext:
    def __init__(self, settings: Optional[Settings] = None, clock: Optional[Clock] = None):
        self.settings = settings or Settings()
        self.rt = Runtime(self.settings.database_url, self.settings.keys_dir, clock)
        bootstrap(self.rt, issuer_id=self.settings.issuer_id, gateway_id=self.settings.gateway_id,
                  processor_id=self.settings.processor_id)
        self.ap2 = AP2Profile(self.settings.payment_audience)
        self.vi = VIProfile(self.settings.payment_audience)
        register_profile(self.ap2)
        register_profile(self.vi)
        self.coordinator = Coordinator(
            ReceiptSigners(
                checkout=ReceiptSigner(self.rt.keys.get("merchant_gateway"), self.settings.gateway_id),
                payment=ReceiptSigner(self.rt.keys.get("payment_processor"), self.settings.processor_id),
            ),
            self.rt.clock,
        )
        # The user signing component lives behind the consent flow; only the consent service touches it.
        self._user_component = UserSigningComponent(self.rt.keys.get("user_device"))
        # Clients to sibling services (embedded → direct call; remote → HTTP). Set by app factory.
        self.issue_credential: Callable[[str, str, Dict[str, Any]], Dict[str, Any]] = self._remote_issue
        self.gateway_transport: Optional[httpx.BaseTransport] = None  # set in embedded mode
        self.gateway_base_url: str = self.settings.gateway_url

    @property
    def clock(self) -> Clock:
        return self.rt.clock

    @property
    def user_component(self) -> UserSigningComponent:
        return self._user_component

    def agent_audience(self, agent_id: str) -> str:
        return f"urn:aaw:agent:{agent_id}"

    # -- remote clients (compose mode) ----------------------------------------

    def _remote_issue(self, profile: str, user_id: str, user_public_jwk: Dict[str, Any]) -> Dict[str, Any]:
        with httpx.Client(timeout=15) as client:
            r = client.post(f"{self.settings.issuer_url}/issuer/credentials",
                            json={"profile": profile, "user_id": user_id, "user_public_jwk": user_public_jwk},
                            headers={"Authorization": f"Bearer {self.settings.admin_token}"})
            r.raise_for_status()
            return r.json()

    def gateway_client(self) -> httpx.Client:
        if self.gateway_transport is not None:
            return httpx.Client(transport=self.gateway_transport, base_url=self.gateway_base_url, timeout=60)
        return httpx.Client(base_url=self.gateway_base_url, timeout=60)
