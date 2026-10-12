
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

# Production frontend URL
FRONTEND_ORIGIN = (
    "https://re-trace-smart-contract-security-an.vercel.app"
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run startup and shutdown tasks."""

    if settings.secret_key_is_ephemeral:
        log.warning(
            "RETRACE_SECRET_KEY is not set or is shorter than 32 "
            "characters. A random per-process key is being used. "
            "Sessions will not survive a restart."
        )

    if settings.database_url:
        try:
            from app.services.scan_service import recover_stale_scans

            count = recover_stale_scans()

            if count:
                log.warning(
                    "Marked %s interrupted scan(s) as FAILED.",
                    count,
                )
        except Exception:
            # Do not silently hide database startup failures.
            log.exception("Failed to recover stale scans.")

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


# ---------------------------------------------------------
# CORS CONFIGURATION
# ---------------------------------------------------------

configured_origins = list(settings.cors_origins)

allowed_origins = list(
    dict.fromkeys(
        configured_origins + [FRONTEND_ORIGIN]
    )
)

# Temporary diagnostic log. Remove after confirming deployment.
log.warning("Effective CORS origins: %s", allowed_origins)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------
# HEALTH ENDPOINTS
# ---------------------------------------------------------

@app.get("/health", tags=["Health"])
async def health_check():
    """Check whether the backend is running."""

    return {
        "status": "ok",
        "service": "ReTrace backend",
    }


@app.get("/health/db", tags=["Health"])
def health_db():
    """Check database connectivity without exposing credentials."""

    from sqlalchemy import text
    from app.db import get_engine

    try:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))

    except Exception:
        log.exception("Database health check failed")

        return JSONResponse(
            status_code=503,
            content={
                "status": "error",
                "database": "unreachable",
            },
        )

    return {
        "status": "ok",
        "database": "reachable",
    }


# ---------------------------------------------------------
# ERROR RESPONSE HELPER
# ---------------------------------------------------------

def _denied(
    status: int,
    code: str,
    message: str,
) -> JSONResponse:
    """Return a consistent security error response."""

    return JSONResponse(
        status_code=status,
        content={
            "detail": {
                "code": code,
                "message": message,
            }
        },
    )


# ---------------------------------------------------------
# REQUEST SECURITY MIDDLEWARE
# ---------------------------------------------------------

@app.middleware("http")
async def guard(request: Request, call_next):
    """Apply request-size and origin security checks."""

    request.state.request_id = str(uuid.uuid4())

    content_length = request.headers.get("content-length")

    max_body_size = max(
        settings.max_request_body_bytes,
        settings.max_upload_bytes + 8192,
    )

    if (
        content_length
        and content_length.isdigit()
        and int(content_length) > max_body_size
    ):
        return _denied(
            413,
            "too_large",
            "Request body is too large.",
        )

    # Enforce origin checks for unsafe methods.
    # CORS preflight OPTIONS requests are safe and are handled
    # by CORSMiddleware.
    if request.method not in SAFE_METHODS:
        origin = request.headers.get("origin")

        if origin:
            request_origin = urlparse(origin)
            request_host = request.headers.get("host", "")

            same_host = (
                request_origin.netloc.lower()
                == request_host.lower()
            )

            if origin not in allowed_origins and not same_host:
                return _denied(
                    403,
                    "bad_origin",
                    "Cross-origin request blocked.",
                )

    response = await call_next(request)

    # Add security and diagnostic headers.
    response.headers["X-Request-ID"] = (
        request.state.request_id
    )

    response.headers.setdefault(
        "X-Content-Type-Options",
        "nosniff",
    )

    response.headers.setdefault(
        "X-Frame-Options",
        "DENY",
    )

    response.headers.setdefault(
        "Referrer-Policy",
        "no-referrer",
    )

    if request.url.path.startswith("/api/"):
        response.headers.setdefault(
            "Cache-Control",
            "no-store",
        )

    return response


# ---------------------------------------------------------
# API ROUTER REGISTRATION
# ---------------------------------------------------------

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
