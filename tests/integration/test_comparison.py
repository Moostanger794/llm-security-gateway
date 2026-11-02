import json
import socket
from pathlib import Path

import httpx
import pytest

from ai_security_gateway.core.config import Settings
from ai_security_gateway.evaluation import comparison
from ai_security_gateway.evaluation.injection_dataset import load_injection_dataset
from ai_security_gateway.llm import ClassificationOutcome, OpenAIClassifier, RequestBudget


def deny(*args, **kwargs):
    raise AssertionError("Network/provider settings must not be used")


def test_default_comparison_offline_with_external_environment(monkeypatch, capsys):
    monkeypatch.setenv("ENABLE_LLM_ANALYSIS", "true")
    monkeypatch.setenv("ALLOW_EXTERNAL_LLM", "true")
    monkeypatch.setenv("LLM_API_KEY", "test-not-a-real-key")
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(comparison, "Settings", deny)
    monkeypatch.setattr(comparison, "build_classifier", deny)
    assert comparison.main(["--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["execution"] == "offline_rules"
    assert report["operational"]["provider_requests"] == 0
    assert set(report["modes"]) == {"rules"}


@pytest.mark.parametrize(
    "argv",
    [
        ["--mode", "compare"],
        ["--mode", "hybrid", "--max-requests", "10"],
        ["--mode", "llm-only", "--live"],
        ["--mode", "compare", "--live", "--max-requests", "0"],
        ["--mode", "compare", "--live", "--max-requests", "-1"],
        ["--mode", "rules", "--live", "--max-requests", "10"],
    ],
)
def test_live_guard_before_factory(argv, monkeypatch, capsys):
    monkeypatch.setattr(comparison, "build_classifier", deny)
    assert comparison.main(argv) == 1
    assert "Evaluation error" in capsys.readouterr().err


def test_cli_incomplete_exit_and_client_close(monkeypatch, capsys):
    class Fake:
        closed = False

        def classify(self, data):
            return ClassificationOutcome(status="missing_key", fallback_reason="missing_key")

        def close(self):
            self.closed = True

    fake = Fake()
    monkeypatch.setattr(comparison, "build_classifier", lambda settings, budget: fake)
    assert comparison.main(["--mode", "compare", "--live", "--max-requests", "10", "--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert not report["complete"] and fake.closed
    assert report["configuration"]["limits"]["max_requests"] == 10
    assert report["operational"]["provider_requests"] == 0


def test_no_overwrite_or_external_output(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "existing.json"
    path.write_text("keep", encoding="utf-8")
    assert comparison.main(["--output", "existing.json"]) == 1
    assert path.read_text() == "keep"
    assert comparison.main(["--output", "../outside.json"]) == 1
    assert "Evaluation error" in capsys.readouterr().err


def test_comparison_budget_retries_with_real_sdk_offline_transport(monkeypatch):
    monkeypatch.setattr("ai_security_gateway.llm.provider.sleep", lambda _: None)
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(429, json={"error": {"message": "private-provider-error"}})

    budget = RequestBudget(2)
    classifier = OpenAIClassifier(
        Settings(
            _env_file=None,
            enable_llm_analysis=True,
            allow_external_llm=True,
            llm_api_key="offline-placeholder",
            llm_model="test-model",
            llm_max_retries=3,
        ),
        budget=budget,
        transport=httpx.MockTransport(respond),
    )
    try:
        report = comparison.run_comparison(
            load_injection_dataset(), mode="compare", classifier=classifier
        )
    finally:
        classifier.close()
    assert report["execution"] == "offline_test"
    assert report["operational"]["provider_requests"] == budget.used == len(requests) == 2
    assert report["operational"]["reservations"] == 2
    assert report["operational"]["released_reservations"] == budget.reserved == 0
    assert report["operational"]["budget_exhausted"]
    assert not report["complete"]
    assert report["modes"]["llm-only"]["prediction_coverage"] == 0
    assert report["modes"]["hybrid"]["prediction_coverage"] == 1
    assert "private-provider-error" not in json.dumps(report)
    assert report["configuration"]["limits"]["max_requests"] == 2
    assert report["configuration"]["limits"]["max_retries"] == 3


@pytest.mark.parametrize("reason", ["missing_parent", "denied"])
def test_bad_output_prevents_provider_construction(reason, monkeypatch, tmp_path, capsys):
    dataset = load_injection_dataset()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(comparison, "load_injection_dataset", lambda _: dataset)
    monkeypatch.setattr(comparison, "build_classifier", deny)
    path = "missing-parent/report.json" if reason == "missing_parent" else "report.json"
    if reason == "denied":

        def inaccessible(*args, **kwargs):
            raise PermissionError("private-filesystem-details")

        monkeypatch.setattr(Path, "open", inaccessible)
    assert (
        comparison.main(["--mode", "compare", "--live", "--max-requests", "10", "--output", path])
        == 1
    )
    error = capsys.readouterr().err
    assert "Evaluation error" in error
    assert "private-filesystem-details" not in error


def test_output_reserved_before_provider_and_closed_after_write(monkeypatch, tmp_path, capsys):
    dataset = load_injection_dataset()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(comparison, "load_injection_dataset", lambda _: dataset)
    destination = tmp_path / "report.json"

    class Fake:
        def classify(self, data):
            assert destination.exists()
            return ClassificationOutcome(status="missing_key")

        def close(self):
            pass

    def build(settings, budget):
        assert destination.exists()
        return Fake()

    monkeypatch.setattr(comparison, "build_classifier", build)
    assert (
        comparison.main(
            ["--mode", "compare", "--live", "--max-requests", "10", "--output", "report.json"]
        )
        == 2
    )
    report = json.loads(destination.read_text(encoding="utf-8"))
    assert report["execution"] == "offline_test"
    assert not report["complete"]
    assert "Traceback" not in capsys.readouterr().err


@pytest.mark.parametrize("failure", ["key", "preparation"])
def test_local_errors_do_not_count_as_provider_latency_or_resolved_predictions(
    failure, monkeypatch
):
    requests = []
    budget = RequestBudget(3)
    classifier = OpenAIClassifier(
        Settings(
            _env_file=None,
            enable_llm_analysis=True,
            allow_external_llm=True,
            llm_api_key="review-\u043a" if failure == "key" else "offline-placeholder",
            llm_model="test-model",
            llm_max_retries=3,
        ),
        budget,
        transport=httpx.MockTransport(lambda request: requests.append(request)),
    )
    if failure == "preparation":

        def fail(*args, **kwargs):
            raise ValueError("private-local-error")

        monkeypatch.setattr(classifier, "_get_client", fail)
    try:
        report = comparison.run_comparison(
            load_injection_dataset(), mode="compare", split="all", classifier=classifier
        )
    finally:
        classifier.close()
    operational = report["operational"]
    assert operational["provider_requests"] == operational["reservations"] == budget.used == 0
    assert operational["released_reservations"] == budget.reserved == len(requests) == 0
    assert operational["calls_with_requests"] == 0
    assert operational["uncached_call_p50_ms"] is operational["uncached_call_p95_ms"] is None
    assert report["modes"]["llm-only"]["unresolved_count"] == 32
    assert report["modes"]["llm-only"]["metrics"] is None
    assert report["modes"]["hybrid"]["fallback_count"] == 32
    assert report["modes"]["hybrid"]["prediction_coverage"] == 1
    assert "private-local-error" not in json.dumps(report)


def test_compare_reuses_successful_transport_outcome_and_reservation_once():
    attempts = []
    budget = RequestBudget(3)

    def respond(request):
        attempts.append(request)
        return httpx.Response(
            200,
            json={
                "id": "review",
                "object": "response",
                "created_at": 0,
                "model": "test-model",
                "status": "completed",
                "error": None,
                "incomplete_details": None,
                "output": [
                    {
                        "id": "m",
                        "type": "message",
                        "role": "assistant",
                        "status": "completed",
                        "content": [
                            {
                                "type": "output_text",
                                "annotations": [],
                                "text": json.dumps(
                                    {
                                        "verdict": "no_attack_detected",
                                        "threat_types": [],
                                        "reason_codes": ["no_instruction_attack"],
                                    }
                                ),
                            }
                        ],
                    }
                ],
                "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
            },
        )

    classifier = OpenAIClassifier(
        Settings(
            _env_file=None,
            enable_llm_analysis=True,
            allow_external_llm=True,
            llm_api_key="offline-placeholder",
            llm_model="test-model",
        ),
        budget,
        transport=httpx.MockTransport(respond),
    )
    try:
        report = comparison.run_comparison(
            load_injection_dataset(), mode="compare", split="all", classifier=classifier
        )
    finally:
        classifier.close()
    op = report["operational"]
    assert op["provider_requests"] == op["reservations"] == budget.used == len(attempts) == 3
    assert op["released_reservations"] == budget.reserved == 0
    assert op["input_tokens"] == 30 and op["output_tokens"] == 15
    assert op["calls_with_requests"] == 3
    for mode in ("llm-only", "hybrid"):
        assert report["modes"][mode]["llm_coverage"] == 3 / 32
        assert report["modes"][mode]["sample_ids"] == report["configuration"]["sample_ids"]
    assert report["modes"]["llm-only"]["unresolved_count"] == 29
    assert report["modes"]["hybrid"]["fallback_count"] == 29
    assert not report["complete"]
