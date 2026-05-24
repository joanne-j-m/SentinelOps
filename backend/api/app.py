"""
api/app.py
───────────
FastAPI application factory.

Phase 7 fixes:
  - CORS locked down to known origins (no more wildcard + credentials).
  - Version bumped to 0.7.0.
"""

from __future__ import annotations
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from .routes import router


# Allowed CORS origins — extend this list for production deployments
_ALLOWED_ORIGINS = [
    "http://localhost:8000",
    "http://localhost:9000",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:9000",
]


def create_app() -> FastAPI:
    app = FastAPI(
        title="Sentinel-Ops",
        description="Autonomous Multi-Agent Threat Hunting Pipeline",
        version="0.7.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_ALLOWED_ORIGINS,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-API-Key"],
    )

    app.include_router(router, prefix="/api/v1")

    # ── Serve React dashboard ─────────────────────────────────────────────
    frontend_dir = os.path.join(os.path.dirname(__file__), "..", "..", "frontend")
    frontend_dir = os.path.abspath(frontend_dir)

    if os.path.exists(frontend_dir):
        app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

        @app.get("/", response_class=FileResponse)
        async def serve_dashboard():  # noqa: F811 — registered as FastAPI route
            return FileResponse(os.path.join(frontend_dir, "index.html"))

    return app


app = create_app()