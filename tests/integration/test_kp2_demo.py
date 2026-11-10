"""Presentation/lifecycle checks, including real HTTP; no model-quality claims."""

import os
import socket
import subprocess
import sys
from unittest.mock import Mock

import httpx
import pytest

from ai_security_gateway.evaluation.comparison import classifier_input
from ai_security_gateway.orchestration import SecurityOrchestrator
from scripts import kp2_demo as demo


def capture_processes(monkeypatch):
    processes = []
    original = subprocess.Popen

    def start(*args, **kwargs):
        process = original(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(demo.subprocess, "Popen", start)
    return processes


def test_real_http_matches_service_and_discloses_miss(monkeypatch, tmp_path, capsys):
    # A real key is neither needed nor used. Any inherited value must be removed.
    sentinel = "private-demo-environment-sentinel"
    for key in ("LLM_API_KEY", "OPENAI_API_KEY", "OPENAI_CUSTOM_HEADERS"):
        monkeypatch.setenv(key, sentinel)
    monkeypatch.setenv("ENABLE_LLM_ANALYSIS", "true")
    monkeypatch.setenv("ALLOW_EXTERNAL_LLM", "true")
    monkeypatch.setenv("LLM_MODEL", "ambient-model")
    monkeypatch.setenv("LLM_MAX_RETRIES", "invalid")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    (tmp_path / ".env").write_text(
        f"ENABLE_LLM_ANALYSIS=true\nALLOW_EXTERNAL_LLM=true\nLLM_API_KEY={sentinel}\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    before = dict(os.environ)
    processes = capture_processes(monkeypatch)
    service = SecurityOrchestrator()
    results = {}
    with demo.local_server() as client:
        base_url = str(client.base_url)
        assert client.get("/health").json()["service"] == "AI Security Gateway"
        for case in demo.cases():
            result = demo.analyze_case(client, case)
            expected = service.analyze_with_metadata(classifier_input(case)).result
            assert result.model_dump(exclude={"processing_time_ms"}) == expected.model_dump(
                exclude={"processing_time_ms"}
            )
            results[case.id] = result
    assert results["ii-dev-009"].action == "ALLOW"
    assert results["ii-dev-005"].action == "BLOCK"
    assert results["ii-dev-007"].action == "BLOCK"
    assert results["ii-dev-008"].action == "ALLOW"  # Retain the known miss, not a relabelled case.
    assert {r.id: r for r in demo.cases()}["ii-dev-008"].expected_action == "BLOCK"
    output = capsys.readouterr()
    assert "ii-dev-008 | label=attack | expected_action=BLOCK" in output.out
    assert "LIMITATION: missed attack" in output.out
    assert output.out.count("provider_attempts=0") == 4
    assert all(sample_id in output.out for sample_id in demo.CASE_IDS)
    assert sentinel not in output.out + output.err
    assert dict(os.environ) == before
    assert len(processes) == 1 and processes[0].poll() == 0
    with httpx.Client(trust_env=False, timeout=1) as client:
        with pytest.raises((httpx.ConnectError, httpx.ConnectTimeout)):
            client.get(base_url.rstrip("/") + "/health")


@pytest.mark.parametrize("failure,exit_code", [(RuntimeError, 1), (KeyboardInterrupt, 130)])
def test_error_redaction_and_owned_process_cleanup(monkeypatch, capsys, failure, exit_code):
    processes = capture_processes(monkeypatch)

    def fail(*args):
        raise failure("private-error-and-header-sentinel")

    monkeypatch.setattr(demo, "analyze_case", fail)
    # An unrelated listener survives; cleanup never scans ports or kills by process name.
    with socket.socket() as unrelated:
        unrelated.bind(("127.0.0.1", 0))
        unrelated.listen()
        address = unrelated.getsockname()
        assert demo.main() == exit_code
        assert unrelated.getsockname() == address
    assert len(processes) == 1 and processes[0].poll() == 0
    output = capsys.readouterr()
    assert "private-error-and-header-sentinel" not in output.out + output.err
    assert "graceful shutdown, exit 0" not in output.out


def test_startup_failure_is_reaped_and_redacted(monkeypatch, capsys):
    original = subprocess.Popen
    processes = []

    def failed_child(args, **kwargs):
        process = original([sys.executable, "-c", "raise SystemExit(7)"], **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(demo.subprocess, "Popen", failed_child)
    assert demo.main() == 1
    assert processes[0].poll() == 7
    assert "Demo failed" in capsys.readouterr().err


def test_startup_timeout_cleans_up_real_process(monkeypatch, capsys):
    processes = capture_processes(monkeypatch)

    def not_ready(*args):
        raise RuntimeError("private-health-timeout")

    monkeypatch.setattr(demo, "wait_for_health", not_ready)
    assert demo.main() == 1
    assert processes[0].poll() is not None
    output = capsys.readouterr()
    assert "private-health-timeout" not in output.out + output.err


def test_health_wait_is_bounded():
    client = Mock()
    client.get.side_effect = httpx.ConnectError("private-network-error")
    process = Mock()
    process.poll.return_value = None
    with pytest.raises(RuntimeError, match="did not become ready"):
        demo.wait_for_health(client, process, timeout=0)
    assert client.get.call_count == 1


def test_forced_shutdown_is_not_reported_as_graceful():
    process = Mock()
    process.wait.side_effect = [subprocess.TimeoutExpired("demo", 5), 1]
    with pytest.raises(RuntimeError, match="forced shutdown"):
        demo.stop_server(process)
    process.kill.assert_called_once_with()
    assert process.wait.call_count == 2
    process.stdin.close.assert_called_once()
    process.stdout.close.assert_called_once()


@pytest.mark.parametrize("status", [422, 500])
def test_http_errors_are_not_presented_as_decisions(status, capsys):
    with httpx.Client(
        base_url="http://127.0.0.1",
        transport=httpx.MockTransport(lambda _: httpx.Response(status, text="private-response")),
    ) as client:
        with pytest.raises(httpx.HTTPStatusError):
            demo.analyze_case(client, demo.cases()[0])
    assert not capsys.readouterr().out


@pytest.mark.parametrize(
    "header,value",
    [("X-Analysis-Mode", "hybrid"), ("X-LLM-Status", "success"), ("X-LLM-Requests", "1")],
)
def test_unexpected_provider_activity_is_rejected(header, value, capsys):
    headers = {
        "X-Requested-Analysis-Mode": "rules",
        "X-Analysis-Mode": "rules",
        "X-LLM-Status": "disabled",
        "X-LLM-Requests": "0",
        header: value,
    }
    with httpx.Client(
        base_url="http://127.0.0.1",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={}, headers=headers)),
    ) as client:
        with pytest.raises(RuntimeError, match="Offline analysis contract"):
            demo.analyze_case(client, demo.cases()[0])
    assert not capsys.readouterr().out


def test_child_environment_does_not_mutate_or_forward_secrets():
    original = {
        "LLM_API_KEY": "private-key",
        "OPENAI_API_KEY": "another-private-key",
        "OPENAI_LOG": "debug",
        "ALLOW_EXTERNAL_LLM": "true",
        "ENABLE_LLM_ANALYSIS": "true",
    }
    before = original.copy()
    child = demo.offline_environment(original)
    assert original == before
    assert child["LLM_API_KEY"] == ""
    assert child["ENABLE_LLM_ANALYSIS"] == child["ALLOW_EXTERNAL_LLM"] == "false"
    assert not any(key.startswith("OPENAI_") for key in child)


def test_annotations_never_reach_http_payload():
    case = demo.cases()[0]
    client = Mock()
    client.post.side_effect = httpx.ConnectError("stop before response")
    with pytest.raises(httpx.ConnectError):
        demo.analyze_case(client, case)
    client.post.assert_called_once_with("/analyze/email", json=case.input.model_dump())
    assert set(client.post.call_args.kwargs["json"]) == {"sender", "subject", "body"}


@pytest.mark.parametrize(
    "event",
    [
        "sys.audit('socket.getaddrinfo', 'forbidden.invalid', 443, 0, 0, 0)",
        "sys.audit('socket.connect', None, ('203.0.113.8', 443))",
    ],
)
def test_child_network_guard_rejects_external_events_without_network(event):
    # Synthetic audit events perform no DNS or socket operation, even if this test fails.
    code = demo.SERVER_CODE.split("import uvicorn", 1)[0]
    code += f"\ntry:\n    {event}\nexcept OSError:\n    sys.exit(0)\nsys.exit(9)\n"
    env = demo.offline_environment()
    env.pop("PYTHONPATH", None)  # Verify the demo's own guard, independently of audit tooling.
    result = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, timeout=5)
    assert result.returncode == 0
