from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response

from ai_security_gateway import __version__
from ai_security_gateway.api.schemas import (
    EmailRequest,
    ErrorResponse,
    HealthResponse,
    PromptRequest,
    TextRequest,
)
from ai_security_gateway.core.logging import logger
from ai_security_gateway.llm import ClassifierInput
from ai_security_gateway.models.security import SecurityResult
from ai_security_gateway.orchestration import SecurityOrchestrator
from ai_security_gateway.orchestration.diagnostics import AnalysisMetadata

router = APIRouter()


def get_orchestrator(request: Request) -> SecurityOrchestrator:
    return request.app.state.orchestrator


def set_analysis_headers(response: Response, metadata: AnalysisMetadata) -> None:
    """Only validated enum/counter/configuration metadata crosses the HTTP boundary."""
    response.headers["X-Requested-Analysis-Mode"] = metadata.requested_mode
    response.headers["X-Analysis-Mode"] = metadata.actual_mode
    response.headers["X-LLM-Status"] = metadata.llm_status
    response.headers["X-LLM-Requests"] = str(metadata.requests)
    response.headers["X-LLM-Reservations"] = str(metadata.reservations)
    response.headers["X-LLM-Released-Reservations"] = str(metadata.released_reservations)
    if metadata.fallback_reason is not None:
        response.headers["X-LLM-Fallback-Reason"] = metadata.fallback_reason
    if metadata.model is not None:
        response.headers["X-LLM-Model"] = metadata.model
    if metadata.input_tokens is not None:
        response.headers["X-LLM-Input-Tokens"] = str(metadata.input_tokens)
    if metadata.output_tokens is not None:
        response.headers["X-LLM-Output-Tokens"] = str(metadata.output_tokens)


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
    payload: PromptRequest, request: Request, response: Response, service: OrchestratorDependency
) -> SecurityResult:
    """Rules by default; optional configured LLM analysis, with per-call status headers."""
    analysis = service.analyze_with_metadata(
        ClassifierInput(source_type="prompt", text=payload.text)
    )
    result = analysis.result
    set_analysis_headers(response, analysis.metadata)
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
    payload: EmailRequest, request: Request, response: Response, service: OrchestratorDependency
) -> SecurityResult:
    """Email/URL rules and optional LLM inspection of sender, subject and body together."""
    analysis = service.analyze_with_metadata(
        ClassifierInput(
            source_type="email", sender=payload.sender, subject=payload.subject, body=payload.body
        )
    )
    result = analysis.result
    set_analysis_headers(response, analysis.metadata)
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
    payload: TextRequest, request: Request, response: Response, service: OrchestratorDependency
) -> SecurityResult:
    """Analyze untrusted document text using the common service and configured mode."""
    analysis = service.analyze_with_metadata(
        ClassifierInput(source_type="document", text=payload.text)
    )
    result = analysis.result
    set_analysis_headers(response, analysis.metadata)
    logger.info(
        "text_analyzed request_id=%s risk_level=%s action=%s processing_time_ms=%.3f",
        request.state.request_id,
        result.risk_level,
        result.action,
        result.processing_time_ms,
    )
    return result
