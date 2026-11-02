import ipaddress
import socket
from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_security_gateway.core.config import Settings
from ai_security_gateway.main import create_app


@pytest.fixture(autouse=True)
def offline_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """A configured real key is never authorization for tests to contact a provider."""
    monkeypatch.setenv("ENABLE_LLM_ANALYSIS", "false")
    monkeypatch.setenv("ALLOW_EXTERNAL_LLM", "false")
    monkeypatch.setenv("LLM_API_KEY", "")
    monkeypatch.setenv("LLM_MODEL", "")
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_lookup = socket.getaddrinfo

    def local(address: object) -> bool:
        if not isinstance(address, tuple):
            return True  # Unix-domain socket pairs used by async test infrastructure.
        host = address[0]
        if host == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def connect(sock, address):
        if not local(address):
            raise AssertionError("External network is forbidden in offline tests")
        return original_connect(sock, address)

    def connect_ex(sock, address):
        if not local(address):
            raise AssertionError("External network is forbidden in offline tests")
        return original_connect_ex(sock, address)

    def lookup(host, port, *args, **kwargs):
        if not local((host, port)):
            raise AssertionError("External DNS is forbidden in offline tests")
        return original_lookup(host, port, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", lookup)


@pytest.fixture
def app() -> FastAPI:
    return create_app(Settings(_env_file=None, app_name="AI Security Gateway", log_level="INFO"))


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client
