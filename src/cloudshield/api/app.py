import threading
from collections.abc import Callable
from contextlib import asynccontextmanager
from functools import partial
from importlib.metadata import version
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from cloudshield.api.jobs import JobLock, scan_with_boto3
from cloudshield.api.routes import router
from cloudshield.config import Settings, load_env_file
from cloudshield.db import store
from cloudshield.db.session import make_engine, make_session_factory
from cloudshield.fixes.explain import HourlyLimit
from cloudshield.imports.runner import RunOutput, StatusCache, check_runner, run_prowler


DEFAULT_PORTS = {"http": 80, "https": 443}


def same_origin(origin: str, allowed: str) -> bool:
    """Scheme, host and port must all be equal. localhost and 127.0.0.1 are different origins."""

    def key(value: str) -> tuple:
        parts = urlparse(value)
        return parts.scheme, parts.hostname, parts.port or DEFAULT_PORTS.get(parts.scheme)

    try:
        return key(origin) == key(allowed)
    except ValueError:  # a port that is not a number
        return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    with app.state.session_factory() as session:
        store.fail_unfinished(session)
    yield
    # Stops a running extended check, and with it the program it started.
    app.state.extended_cancel.set()


def create_app(
    database_url: str | None = None,
    scan_function: Callable[[list[str]], dict] | None = None,
    gemini_transport: httpx.BaseTransport | None = None,
    load_env: bool = True,
    extended_function: Callable[[list[str]], RunOutput] | None = None,
    extended_status: StatusCache | None = None,
) -> FastAPI:
    if load_env:
        load_env_file()
    settings = Settings()
    app = FastAPI(title="CloudShield", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.frontend_origin],
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-Filename"],
    )
    app.state.settings = settings

    # A browser sends a body-less POST from any web page without asking first, so CORS alone does
    # not stop another site from starting a scan. A request without an Origin header (a script,
    # curl) is not from a web page and stays allowed.
    @app.middleware("http")
    async def refuse_foreign_origin(request: Request, call_next):
        origin = request.headers.get("origin")
        writes = request.method not in ("GET", "OPTIONS")
        if writes and origin is not None and not same_origin(origin, settings.frontend_origin):
            detail = (
                "This request came from another origin. "
                f"Open the dashboard at {settings.frontend_origin}."
            )
            return JSONResponse(status_code=403, content={"detail": detail})
        return await call_next(request)

    engine = make_engine(database_url or settings.database_url)
    app.state.session_factory = make_session_factory(engine)
    app.state.scan_function = scan_function or scan_with_boto3
    app.state.job_lock = JobLock()
    app.state.ai_limit = HourlyLimit(settings.ai_max_calls_per_hour)
    app.state.gemini_transport = gemini_transport
    app.state.extended_cancel = threading.Event()
    app.state.extended_function = extended_function or partial(
        run_prowler, settings, cancel=app.state.extended_cancel
    )
    app.state.extended_status = extended_status or StatusCache(partial(check_runner, settings))
    app.include_router(router)

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": version("cloudshield")}

    return app
