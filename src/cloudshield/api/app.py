from importlib.metadata import version

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from cloudshield.config import Settings


def create_app() -> FastAPI:
    settings = Settings()
    app = FastAPI(title="CloudShield")
    app.add_middleware(CORSMiddleware, allow_origins=[settings.frontend_origin])

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": version("cloudshield")}

    return app
