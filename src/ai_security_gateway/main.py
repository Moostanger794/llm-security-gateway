from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from time import perf_counter
from uuid import uuid4

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException

from ai_security_gateway import __version__
from ai_security_gateway.api.body_limit import RequestBodyLimit
from ai_security_gateway.api.errors import (
    error_response,
    http_error_handler,
    validation_error_handler,
)
from ai_security_gateway.api.routes import router
from ai_security_gateway.api.schemas import ErrorResponse
from ai_security_gateway.core.config import Settings
from ai_security_gateway.core.logging import configure_logging, logger


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build an isolated app; no external services or secrets are required."""
    settings = settings if settings is not None else Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_logging(settings.log_level)
        logger.info("application_started version=%s", __version__)
        yield
        logger.info("application_stopped")

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        debug=False,
        lifespan=lifespan,
        responses={
            404: {"model": ErrorResponse},
            405: {"model": ErrorResponse},
            422: {"model": ErrorResponse},
            500: {"model": ErrorResponse},
        },
    )
    app.state.settings = settings
    app.add_exception_handler(HTTPException, http_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_middleware(RequestBodyLimit)

    @app.middleware("http")
    async def request_logging(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        started = perf_counter()
        request.state.request_id = uuid4().hex
        try:
            response = await call_next(request)
        except Exception as exc:
            # HTTP boundary: redact exception messages/tracebacks that may contain secrets.
            logger.error(
                "request_failed request_id=%s error_type=%s",
                request.state.request_id,
                type(exc).__name__,
            )
            response = error_response(request, 500, "Internal server error")
        elapsed_ms = (perf_counter() - started) * 1000
        response.headers["X-Request-ID"] = request.state.request_id
        # Do not log raw paths, query strings, bodies, or headers.
        logger.info(
            "request_completed request_id=%s status=%s processing_time_ms=%.3f",
            request.state.request_id,
            response.status_code,
            elapsed_ms,
        )
        return response

    app.include_router(router)
    return app


app = create_app()
