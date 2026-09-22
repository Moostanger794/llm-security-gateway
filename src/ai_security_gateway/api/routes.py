from fastapi import APIRouter, Request

from ai_security_gateway import __version__
from ai_security_gateway.api.schemas import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["health"])
async def health(request: Request) -> HealthResponse:
    """Process liveness only; does not claim security analysis is available."""
    return HealthResponse(service=request.app.state.settings.app_name, version=__version__)
