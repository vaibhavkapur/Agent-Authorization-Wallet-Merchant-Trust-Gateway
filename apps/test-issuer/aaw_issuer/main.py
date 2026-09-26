"""uvicorn entrypoint for the standalone issuer service."""

from .app import create_app

app = create_app()
