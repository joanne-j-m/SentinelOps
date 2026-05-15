"""
api/app.py
───────────
FastAPI application factory.
Phase 4: Serves the React dashboard as a static file.
"""

from __future__ import annotations
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
from .routes import router


def create_app() -> FastAPI:
    app = FastAPI(
        title="Sentinel-Ops",
        description="Autonomous Multi-Agent Threat Hunting Pipeline",
        version="0.3.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router, prefix="/api/v1")

    # ── Phase 4: Serve React dashboard ────────────────────────────────────
    frontend_dir = os.path.join(os.path.dirname(__file__), "..", "..", "frontend")
    frontend_dir = os.path.abspath(frontend_dir)

    if os.path.exists(frontend_dir):
        app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

        @app.get("/", response_class=FileResponse)
        async def serve_dashboard():
            return FileResponse(os.path.join(frontend_dir, "index.html"))

    return app


app = create_app()
