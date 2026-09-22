from typing import Literal

from pydantic import BaseModel, ConfigDict


class HealthResponse(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    status: Literal["ok"] = "ok"
    service: str
    version: str


class ErrorResponse(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    detail: str
    request_id: str
