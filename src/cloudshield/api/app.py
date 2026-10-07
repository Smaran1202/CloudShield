import threading
from collections.abc import Callable
from contextlib import asynccontextmanager
from importlib.metadata import version

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from cloudshield.api.jobs import scan_with_boto3
from cloudshield.api.routes import router
from cloudshield.config import Settings, load_env_file
from cloudshield.db import store
from cloudshield.db.session import make_engine, make_session_factory
from cloudshield.fixes.explain import HourlyLimit


@asynccontextmanager
async def lifespan(app: FastAPI):
    with app.state.session_factory() as session:
        store.fail_unfinished(session)
    yield


def create_app(
    database_url: str | None = None,
    scan_function: Callable[[list[str]], dict] | None = None,
    gemini_transport: httpx.BaseTransport | None = None,
    load_env: bool = True,
) -> FastAPI:
    if load_env:
        load_env_file()
    settings = Settings()
    app = FastAPI(title="CloudShield", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.frontend_origin],
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Content-Type"],
    )
    app.state.settings = settings
    engine = make_engine(database_url or settings.database_url)
    app.state.session_factory = make_session_factory(engine)
    app.state.scan_function = scan_function or scan_with_boto3
    app.state.scan_lock = threading.Lock()
    app.state.ai_limit = HourlyLimit(settings.ai_max_calls_per_hour)
    app.state.gemini_transport = gemini_transport
    app.include_router(router)

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": version("cloudshield")}

    return app
