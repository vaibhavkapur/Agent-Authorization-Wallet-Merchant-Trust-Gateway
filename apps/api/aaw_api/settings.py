"""Environment configuration for the wallet API (and embedded services)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List


@dataclass
class Settings:
    database_url: str = field(default_factory=lambda: os.environ.get("DATABASE_URL", "sqlite:///./aaw.db"))
    keys_dir: str = field(default_factory=lambda: os.environ.get("AAW_KEYS_DIR", ".keys"))
    wallet_issuer: str = field(default_factory=lambda: os.environ.get("AAW_WALLET_ISSUER", "https://wallet.aaw.test"))
    issuer_id: str = field(default_factory=lambda: os.environ.get("AAW_ISSUER_ID", "https://issuer.aaw.test"))
    gateway_id: str = field(default_factory=lambda: os.environ.get("AAW_GATEWAY_ID", "urn:aaw:merchant-gateway"))
    processor_id: str = field(default_factory=lambda: os.environ.get("AAW_PROCESSOR_ID", "urn:aaw:payment-processor"))
    payment_audience: str = field(default_factory=lambda: os.environ.get("AAW_PAYMENT_AUDIENCE", "urn:aaw:verifier:payment"))
    gateway_authority: str = field(default_factory=lambda: os.environ.get("AAW_GATEWAY_AUTHORITY", "gateway.aaw.test"))
    gateway_mode: str = field(default_factory=lambda: os.environ.get("AAW_GATEWAY_MODE", "embedded"))  # embedded | remote
    gateway_url: str = field(default_factory=lambda: os.environ.get("AAW_GATEWAY_URL", "http://gateway:8010"))
    api_url: str = field(default_factory=lambda: os.environ.get("AAW_API_URL", "http://api:8000"))
    issuer_url: str = field(default_factory=lambda: os.environ.get("AAW_ISSUER_URL", "http://issuer:8020"))
    admin_token: str = field(default_factory=lambda: os.environ.get("AAW_ADMIN_TOKEN", "dev-admin-token"))
    cors_origins: List[str] = field(
        default_factory=lambda: os.environ.get("AAW_CORS_ORIGINS", "http://localhost:3000").split(",")
    )
    consent_challenge_ttl: int = 300
    expose_demo_tokens: bool = field(default_factory=lambda: os.environ.get("AAW_EXPOSE_DEMO_TOKENS", "1") == "1")
