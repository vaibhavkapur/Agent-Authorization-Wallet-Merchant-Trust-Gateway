"""uvicorn entrypoint for the standalone gateway service."""

from .app import create_app

app = create_app()
