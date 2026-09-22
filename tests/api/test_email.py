import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai_security_gateway.models.security import SecurityResult
from ai_security_gateway.security.email_normalization import (
    MAX_EMAIL_BODY_LENGTH,
    MAX_EMAIL_REQUEST_BYTES,
    MAX_SENDER_LENGTH,
    MAX_SUBJECT_LENGTH,
)

CASES = json.loads((Path(__file__).parents[1] / "fixtures/emails.json").read_text("utf-8"))
SAFE = {"sender": "alice@example.com", "subject": "Notes", "body": "Meeting tomorrow"}


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_email_endpoint(client: TestClient, case: dict) -> None:
    response = client.post("/analyze/email", json=case["input"])
    assert response.status_code == 200
    result = SecurityResult.model_validate(response.json())
    assert result.action == case["expected_action"]
    assert result.assessment == case["label"]
    assert response.headers["X-Request-ID"]


@pytest.mark.parametrize("field", ["sender", "subject", "body"])
@pytest.mark.parametrize("value", ["", " \n\t", "\u200b", None, 42, True, [], {}])
def test_email_invalid_fields(client: TestClient, field: str, value: object) -> None:
    response = client.post("/analyze/email", json=SAFE | {field: value})
    assert response.status_code == 422
    assert response.json() == {
        "detail": "Request validation failed",
        "request_id": response.headers["X-Request-ID"],
    }


@pytest.mark.parametrize(
    "payload", [{}, [], None, {"sender": "a@example.com"}, SAFE | {"extra": "secret"}]
)
def test_email_invalid_schema(client: TestClient, payload: object) -> None:
    assert client.post("/analyze/email", json=payload).status_code == 422


@pytest.mark.parametrize(
    ("field", "limit"),
    [
        ("sender", MAX_SENDER_LENGTH),
        ("subject", MAX_SUBJECT_LENGTH),
        ("body", MAX_EMAIL_BODY_LENGTH),
    ],
)
def test_email_field_limits(client: TestClient, field: str, limit: int) -> None:
    assert client.post("/analyze/email", json=SAFE | {field: "界" * limit}).status_code == 200
    assert client.post("/analyze/email", json=SAFE | {field: "界" * (limit + 1)}).status_code == 422


def test_email_json_and_request_limits(client: TestClient) -> None:
    assert client.post("/analyze/email", content='{"sender":').status_code == 422
    # Valid maximum-size fields with astral characters escaped as JSON surrogate pairs.
    payload = {
        "sender": "😀" * MAX_SENDER_LENGTH,
        "subject": "😀" * MAX_SUBJECT_LENGTH,
        "body": "😀" * MAX_EMAIL_BODY_LENGTH,
    }
    assert (
        client.post(
            "/analyze/email",
            content=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        ).status_code
        == 200
    )
    for route in ("/analyze/email", "/analyze/email/", "/health", "/missing"):
        response = client.post(route, content=b"x" * (MAX_EMAIL_REQUEST_BYTES + 1))
        assert response.status_code == 413
        assert response.json()["detail"] == "Request body too large"
    assert client.get("/health").status_code == 200


def test_email_openapi(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    fields = schema["components"]["schemas"]["EmailRequest"]["properties"]
    assert [fields[f]["maxLength"] for f in ("sender", "subject", "body")] == [320, 998, 100_000]
    assert "413" in schema["paths"]["/analyze/email"]["post"]["responses"]
