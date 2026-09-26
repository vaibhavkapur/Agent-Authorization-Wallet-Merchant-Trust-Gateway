"""uvicorn entrypoint for the standalone registry service."""

from .app import create_app

app = create_app()
