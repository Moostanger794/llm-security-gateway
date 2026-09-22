import logging
from pathlib import Path

import pytest
from pydantic import ValidationError

from ai_security_gateway.api.schemas import ErrorResponse, HealthResponse
from ai_security_gateway.core.config import Settings
from ai_security_gateway.core.logging import configure_logging


def test_defaults_without_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_NAME", raising=False)
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    settings = Settings(_env_file=None)
    assert settings.app_name == "AI Security Gateway"
    assert settings.log_level == "INFO"


def test_environment_overrides_dotenv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        "APP_NAME=Test service\nLOG_LEVEL=WARNING\nUNRELATED=value\n", encoding="utf-8"
    )
    monkeypatch.delenv("APP_NAME", raising=False)
    monkeypatch.setenv("LOG_LEVEL", "ERROR")
    settings = Settings(_env_file=dotenv)
    assert settings.app_name == "Test service"
    assert settings.log_level == "ERROR"


@pytest.mark.parametrize("value", ["", "verbose", "info"])
def test_invalid_log_level(value: str) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, log_level=value)


@pytest.mark.parametrize("value", ["", "x" * 101])
def test_invalid_app_name(value: str) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_name=value)


def test_settings_immutable() -> None:
    settings = Settings(_env_file=None)
    with pytest.raises(ValidationError):
        settings.app_name = "changed"


def test_response_models_reject_wrong_types_and_extra_fields() -> None:
    with pytest.raises(ValidationError):
        HealthResponse(service=123, version="0.1.0")
    with pytest.raises(ValidationError):
        HealthResponse(service="test", version="0.1.0", status="unsafe")
    with pytest.raises(ValidationError):
        ErrorResponse(detail="error", request_id="id", secret="hidden")


def test_logging_configuration_is_idempotent() -> None:
    configure_logging("WARNING")
    configure_logging("INFO")
    logger = logging.getLogger("ai_security_gateway")
    assert len(logger.handlers) == 1
    assert logger.level == logging.INFO
    assert not logger.propagate
