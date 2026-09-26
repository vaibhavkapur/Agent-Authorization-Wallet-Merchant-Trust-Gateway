"""uvicorn entrypoint: ``uvicorn aaw_api.main:app``."""

from .app import create_app

app = create_app()
