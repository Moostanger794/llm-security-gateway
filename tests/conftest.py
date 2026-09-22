from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_security_gateway.core.config import Settings
from ai_security_gateway.main import create_app


@pytest.fixture
def app() -> FastAPI:
    return create_app(Settings(_env_file=None, app_name="AI Security Gateway", log_level="INFO"))


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client
