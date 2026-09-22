from http import HTTPStatus

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from ai_security_gateway.api.schemas import ErrorResponse


def error_response(request: Request, status_code: int, detail: str) -> JSONResponse:
    body = ErrorResponse(detail=detail, request_id=request.state.request_id)
    return JSONResponse(status_code=status_code, content=body.model_dump())


async def http_error_handler(request: Request, exc: HTTPException) -> JSONResponse:
    # Exception details may contain submitted data. Return only a public status phrase.
    try:
        detail = HTTPStatus(exc.status_code).phrase
    except ValueError:
        detail = "HTTP error"
    response = error_response(request, exc.status_code, detail)
    if exc.headers:
        response.headers.update(exc.headers)
    return response


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return error_response(request, 422, "Request validation failed")
