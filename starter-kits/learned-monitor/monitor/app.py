"""FastAPI service serving the trained monitor over the v1 defense API."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request

from monitor.model import DEFAULT_MODEL_PATH, LearnedMonitor, load

REQUIRED_FIELDS = ("run_id", "step_id", "user_goal", "candidate_action")


def create_app(model_path: Path | None = None) -> FastAPI:
    path = model_path or Path(os.environ.get("MONITOR_MODEL_PATH", str(DEFAULT_MODEL_PATH)))
    monitor = LearnedMonitor(load(path))
    app = FastAPI(title="SENTINEL learned monitor", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/decision")
    async def decision(request: Request) -> dict[str, Any]:
        body = await request.json()
        if not isinstance(body, dict) or any(field not in body for field in REQUIRED_FIELDS):
            raise HTTPException(status_code=422, detail="malformed DefenseRequest")
        return monitor.decide(body)

    return app
