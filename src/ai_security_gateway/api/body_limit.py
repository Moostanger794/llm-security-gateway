from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ai_security_gateway.api.errors import error_response
from ai_security_gateway.security.email_normalization import MAX_EMAIL_REQUEST_BYTES
from ai_security_gateway.security.normalization import MAX_PROMPT_BODY_BYTES


class RequestBodyLimit:
    """Bound actual bytes before JSON parsing, including requests without Content-Length."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = (
            MAX_PROMPT_BODY_BYTES
            if scope["path"].rstrip("/") == "/analyze/prompt"
            else MAX_EMAIL_REQUEST_BYTES
        )
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > limit:
                response = error_response(Request(scope), 413, "Request body too large")
                await response(scope, receive, send)
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        delivered = False

        async def replay() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
