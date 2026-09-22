import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_security_gateway.core.config import Settings
from ai_security_gateway.main import create_app


def test_lifecycle_and_redacted_logs(app: FastAPI, capsys: pytest.CaptureFixture[str]) -> None:
    @app.get("/test-failure")
    async def failure() -> None:
        raise RuntimeError("exception-secret")

    with TestClient(app) as client:
        response = client.get(
            "/health?token=query-secret", headers={"Authorization": "header-secret"}
        )
        client.get("/path-secret")
        failure_response = client.get("/test-failure")
    logs = capsys.readouterr().err
    for expected in (
        "application_started",
        "application_stopped",
        "processing_time_ms=",
        "status=200",
        "status=500",
        "error_type=RuntimeError",
        response.headers["X-Request-ID"],
        failure_response.headers["X-Request-ID"],
    ):
        assert expected in logs
    for secret in ("query-secret", "header-secret", "path-secret", "exception-secret"):
        assert secret not in logs


def test_app_settings_are_isolated() -> None:
    first = create_app(Settings(_env_file=None, app_name="First"))
    second = create_app(Settings(_env_file=None, app_name="Second"))
    with TestClient(first) as client:
        assert client.get("/health").json()["service"] == "First"
    with TestClient(second) as client:
        assert client.get("/health").json()["service"] == "Second"
