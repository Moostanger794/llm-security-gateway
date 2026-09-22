import asyncio
import socket

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_security_gateway.security.email_guard import EmailGuard
from ai_security_gateway.security.email_normalization import MAX_EMAIL_REQUEST_BYTES


def test_email_privacy(
    app: FastAPI, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = {
        "sender": "sender-secret@example.com",
        "subject": "URGENT subject-secret",
        "body": "Enter your password body-secret https://user-secret:password-secret@192.0.2.1/?token=url-secret",
    }
    responses = []
    with TestClient(app) as client:
        responses.append(client.post("/analyze/email?key=query-secret", json=payload))
        responses.append(client.post("/analyze/email", json=payload | {"extra": "extra-secret"}))
        responses.append(client.post("/analyze/email", content='{"body":"malformed-secret"'))
        responses.append(
            client.post("/analyze/email", content="large-secret" * MAX_EMAIL_REQUEST_BYTES)
        )

        def fail(*args: object, **kwargs: object) -> None:
            raise ValueError("exception-secret")

        monkeypatch.setattr(EmailGuard, "detect", fail)
        responses.append(client.post("/analyze/email", json=payload))
    assert [r.status_code for r in responses] == [200, 422, 422, 413, 500]
    logs = capsys.readouterr().err
    output = logs + " ".join(r.text for r in responses)
    for marker in (
        "sender-secret",
        "subject-secret",
        "body-secret",
        "user-secret",
        "password-secret",
        "url-secret",
        "query-secret",
        "extra-secret",
        "malformed-secret",
        "large-secret",
        "exception-secret",
        "192.0.2.1",
    ):
        assert marker not in output
    assert "email_analyzed" in logs and "action=BLOCK" in logs
    assert all(r.headers["X-Request-ID"] in logs for r in responses)


def test_email_analysis_has_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("network attempted")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "socket", fail)
    result = EmailGuard().analyze(
        "a@example.com", "Urgent", "Enter your password https://192.0.2.1"
    )
    assert result.action == "BLOCK"


@pytest.mark.parametrize("declared_length", [None, b"1", b"99999999"])
@pytest.mark.parametrize("path", ["/analyze/email", "/analyze/email/", "/unknown"])
def test_streamed_email_request_limit(
    app: FastAPI, declared_length: bytes | None, path: str
) -> None:
    async def run() -> list[dict]:
        chunks = iter(
            [
                {
                    "type": "http.request",
                    "body": b"x" * (MAX_EMAIL_REQUEST_BYTES // 2),
                    "more_body": True,
                },
                {
                    "type": "http.request",
                    "body": b"x" * (MAX_EMAIL_REQUEST_BYTES // 2 + 1),
                    "more_body": True,
                },
            ]
        )
        messages = []

        async def receive() -> dict:
            return next(chunks)

        async def send(message: dict) -> None:
            messages.append(message)

        await app(
            {
                "type": "http",
                "asgi": {"version": "3.0", "spec_version": "2.4"},
                "http_version": "1.1",
                "method": "POST",
                "scheme": "http",
                "path": path,
                "raw_path": path.encode(),
                "query_string": b"",
                "headers": []
                if declared_length is None
                else [(b"content-length", declared_length)],
                "server": ("test", 80),
                "client": ("test", 123),
            },
            receive,
            send,
        )
        return messages

    messages = asyncio.run(run())
    assert messages[0]["status"] == 413
    assert b"x-request-id" in dict(messages[0]["headers"])
