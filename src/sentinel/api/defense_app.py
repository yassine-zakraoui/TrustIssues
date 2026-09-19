"""FastAPI app exposing any in-process Defense over the official HTTP contract."""

from __future__ import annotations

from fastapi import FastAPI

from sentinel.api.schemas import API_VERSION, DefenseDecision, DefenseRequest
from sentinel.defenses.interface import Defense


def create_defense_app(defense: Defense) -> FastAPI:
    app = FastAPI(
        title=f"SENTINEL defense: {defense.name}", version=API_VERSION, docs_url=None, redoc_url=None, openapi_url=None
    )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "defense": defense.name}

    @app.post("/v1/decision", response_model=DefenseDecision)
    def decide(request: DefenseRequest) -> DefenseDecision:
        return defense.decide(request)

    return app
