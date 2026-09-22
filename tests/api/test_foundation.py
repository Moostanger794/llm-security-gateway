from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "AI Security Gateway", "version": "0.1.0"}
    assert UUID(response.headers["X-Request-ID"]).version == 4
    assert response.headers["content-type"] == "application/json"


def test_request_ids_are_fresh(client: TestClient) -> None:
    first = client.get("/health", headers={"X-Request-ID": "untrusted"})
    second = client.get("/health")
    assert first.headers["X-Request-ID"] != "untrusted"
    assert first.headers["X-Request-ID"] != second.headers["X-Request-ID"]


@pytest.mark.parametrize(
    ("method", "path", "status", "detail"),
    [("GET", "/missing", 404, "Not Found"), ("POST", "/health", 405, "Method Not Allowed")],
)
def test_http_errors(client: TestClient, method: str, path: str, status: int, detail: str) -> None:
    response = client.request(method, path)
    assert response.status_code == status
    assert response.json() == {"detail": detail, "request_id": response.headers["X-Request-ID"]}
    if status == 405:
        assert "GET" in response.headers["allow"]


class TestPayload(BaseModel):
    __test__ = False
    model_config = ConfigDict(strict=True, extra="forbid")
    count: int


@pytest.mark.parametrize("body", ['{"count":', "{}", '{"count":"private-secret"}'])
def test_invalid_json_and_schema(app: FastAPI, body: str) -> None:
    @app.post("/test-input")
    async def test_input(payload: TestPayload) -> TestPayload:
        return payload

    with TestClient(app) as client:
        response = client.post(
            "/test-input", content=body, headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422
        assert response.json() == {
            "detail": "Request validation failed",
            "request_id": response.headers["X-Request-ID"],
        }
        assert "private-secret" not in response.text
        assert client.get("/health").status_code == 200


def test_unexpected_error_is_redacted(app: FastAPI) -> None:
    @app.get("/test-failure")
    async def test_failure() -> None:
        raise RuntimeError("private-secret")

    with TestClient(app) as client:
        response = client.get("/test-failure")
        assert response.status_code == 500
        assert response.json() == {
            "detail": "Internal server error",
            "request_id": response.headers["X-Request-ID"],
        }
        assert client.get("/health").status_code == 200


def test_openapi_and_docs(client: TestClient) -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert set(schema["paths"]) == {"/health", "/analyze/prompt", "/analyze/email", "/analyze/text"}
    assert "HealthResponse" in schema["components"]["schemas"]
    assert "ErrorResponse" in schema["components"]["schemas"]
    assert client.get("/docs").status_code == 200
