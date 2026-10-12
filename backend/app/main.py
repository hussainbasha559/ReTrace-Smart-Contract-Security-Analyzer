
"""ReTrace API entry point.
Run with: uvicorn app.main:app
"""

from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import (
    ai_routes,
    auth_routes,
    file_routes,
    project_routes,
    scan_routes,
    usage_routes,
)
from app.api.routes import router
from app.config import get_settings
from app.deps import SAFE_METHODS

settings = get_settings()
log = logging.getLogger("retrace")

FRONTEND_ORIGIN = "https://re-trace-smart-contract-security-an.vercel.app"


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.secret_key_is_ephemeral:
        log.warning(
            "RETRACE_SECRET_KEY is not set (or shorter than 32 chars): "
            "using a random per-process key. Sessions will not survive a restart."
        )

    if settings.database_url:
        from app.services.scan_service import recover_stale_scans

        n = recover_stale_scans()
        if n:
            log.warning("Marked %s interrupted scan(s) as FAILED.", n)

    yield


app = FastAPI(
    title="ReTrace",
    description=(
        "Multi-user EVM bytecode security platform: decompilation, "
        "re-entrancy analysis, history and AI-assisted explanations."
    ),
    version="0.2.0",
    lifespan=lifespan,
    docs_url="/docs",
    openapi_url="/openapi.json",
)


@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "ok", "service": "ReTrace backend"}


@app.get("/health/db", tags=["Health"])
def health_db():
    """Cheap database connectivity probe (no details leaked on failure)."""
    from sqlalchemy import text
    from app.db import get_engine

    try:
        with get_engine().connect() as conn:
            conn.execute(text("select 1"))
    except Exception:
        log.exception("Database health check failed")
        return JSONResponse(status_code=503, content={"status": "error", "database": "unreachable"})
    return {"status": "ok", "database": "reachable"}


# CORS: allow the deployed frontend and configured development origins.
configured_origins = list(settings.cors_origins)
allowed_origins = list(
    dict.fromkeys(configured_origins + [FRONTEND_ORIGIN])
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=[
        "GET",
        "POST",
        "PATCH",
        "DELETE",
        "OPTIONS",
    ],
    allow_headers=[
        "Content-Type",
        "X-CSRF-Token",
    ],
)


def _denied(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "detail": {
                "code": code,
                "message": message,
            }
        },
    )


@app.middleware("http")
async def guard(request: Request, call_next):
    request.state.request_id = str(uuid.uuid4())

    length = request.headers.get("content-length")

    if (
        length
        and length.isdigit()
        and int(length)
        > max(
            settings.max_request_body_bytes,
            settings.max_upload_bytes + 8192,
        )
    ):
        return _denied(
            413,
            "too_large",
            "Request body is too large.",
        )

    # Keep the existing origin/CSRF security check.
    if request.method not in SAFE_METHODS:
        origin = request.headers.get("origin")

        if (
            origin
            and origin not in allowed_origins
            and urlparse(origin).netloc != request.headers.get("host")
        ):
            return _denied(
                403,
                "bad_origin",
                "Cross-origin request blocked.",
            )

    response = await call_next(request)

    response.headers["X-Request-ID"] = request.state.request_id
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")

    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")

    return response


# Register existing API routers.
for route_router in (
    router,
    auth_routes.router,
    project_routes.router,
    file_routes.router,
    scan_routes.router,
    usage_routes.router,
    ai_routes.router,
):
    app.include_router(route_router)
