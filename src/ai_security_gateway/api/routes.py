from typing import Annotated

from fastapi import APIRouter, Depends, Request

from ai_security_gateway import __version__
from ai_security_gateway.api.schemas import (
    EmailRequest,
    ErrorResponse,
    HealthResponse,
    PromptRequest,
    TextRequest,
)
from ai_security_gateway.core.logging import logger
from ai_security_gateway.models.security import SecurityResult
from ai_security_gateway.orchestration import SecurityOrchestrator

router = APIRouter()


def get_orchestrator() -> SecurityOrchestrator:
    return SecurityOrchestrator()


OrchestratorDependency = Annotated[SecurityOrchestrator, Depends(get_orchestrator)]


@router.get("/health", response_model=HealthResponse, tags=["health"])
async def health(request: Request) -> HealthResponse:
    """Process liveness only; does not claim security analysis is available."""
    return HealthResponse(service=request.app.state.settings.app_name, version=__version__)


@router.post(
    "/analyze/prompt",
    response_model=SecurityResult,
    tags=["analysis"],
    responses={413: {"model": ErrorResponse}},
)
def analyze_prompt(
    payload: PromptRequest, request: Request, service: OrchestratorDependency
) -> SecurityResult:
    """Local heuristic analysis of 1–20,000 characters; no LLM or outbound requests."""
    result = service.analyze_prompt(payload.text)
    logger.info(
        "prompt_analyzed request_id=%s risk_level=%s action=%s processing_time_ms=%.3f",
        request.state.request_id,
        result.risk_level,
        result.action,
        result.processing_time_ms,
    )
    return result


@router.post(
    "/analyze/email",
    response_model=SecurityResult,
    tags=["analysis"],
    responses={413: {"model": ErrorResponse}},
)
def analyze_email(
    payload: EmailRequest, request: Request, service: OrchestratorDependency
) -> SecurityResult:
    """Local email and URL heuristics; no network access or sender authentication."""
    result = service.analyze_email(payload.sender, payload.subject, payload.body)
    logger.info(
        "email_analyzed request_id=%s risk_level=%s action=%s processing_time_ms=%.3f",
        request.state.request_id,
        result.risk_level,
        result.action,
        result.processing_time_ms,
    )
    return result


@router.post(
    "/analyze/text",
    response_model=SecurityResult,
    tags=["analysis"],
    responses={413: {"model": ErrorResponse}},
)
def analyze_text(
    payload: TextRequest, request: Request, service: OrchestratorDependency
) -> SecurityResult:
    """Analyze plain untrusted text using the common local service."""
    result = service.analyze_text(payload.text)
    logger.info(
        "text_analyzed request_id=%s risk_level=%s action=%s processing_time_ms=%.3f",
        request.state.request_id,
        result.risk_level,
        result.action,
        result.processing_time_ms,
    )
    return result
