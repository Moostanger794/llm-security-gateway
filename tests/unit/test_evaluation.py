import json
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from ai_security_gateway.evaluation import benchmark
from ai_security_gateway.evaluation.benchmark import EvaluationAdapter, main, run, serialize
from ai_security_gateway.evaluation.dataset import (
    Dataset,
    EvaluationError,
    Record,
    URLInput,
    load_dataset,
)
from ai_security_gateway.evaluation.metrics import Prediction, aggregate
from ai_security_gateway.orchestration import SecurityOrchestrator
from ai_security_gateway.security.risk_engine import Finding


def sample(**changes):
    return (
        dict(
            id="sample-1",
            kind="prompt",
            input={"text": "Example input"},
            label="safe",
            attack_type=None,
            expected_action="ALLOW",
        )
        | changes
    )


def write_data(tmp_path, values):
    path = tmp_path / "data.jsonl"
    path.write_text("".join(json.dumps(v) + "\n" for v in values), encoding="utf-8")
    return path


def prediction(index=1, **changes):
    return Prediction(
        **(
            dict(
                id=f"sample-{index}",
                kind="prompt",
                label="safe",
                attack_type=None,
                expected_action="ALLOW",
                predicted_positive=False,
                action="ALLOW",
                risk_score=0.0,
                latency_ms=float(index),
            )
            | changes
        )
    )


def test_all_metrics_and_mismatches():
    rows = [
        prediction(
            1,
            label="attack",
            attack_type="jailbreak",
            predicted_positive=True,
            action="BLOCK",
            expected_action="BLOCK",
        ),
        prediction(2),
        prediction(3, predicted_positive=True, action="REQUIRE_CONFIRMATION"),
        prediction(4, label="attack", attack_type="jailbreak", expected_action="BLOCK"),
    ]
    result = aggregate(rows)
    assert (result.tp, result.tn, result.fp, result.fn) == (1, 1, 1, 1)
    for name in (
        "accuracy",
        "precision",
        "recall",
        "f1",
        "false_positive_rate",
        "false_negative_rate",
        "attack_success_rate_proxy",
        "action_accuracy",
    ):
        assert getattr(result, name) == 0.5
    assert result.average_latency_ms == 2.5
    assert result.p95_latency_ms == 4.0
    assert result.action_mismatch_ids == ["sample-3", "sample-4"]
    assert result.detection_mismatch_ids == ["sample-3", "sample-4"]


def test_asymmetric_metrics():
    rows = [prediction(i, label="attack", predicted_positive=True) for i in range(3)]
    rows += [prediction(4, label="attack"), prediction(5, predicted_positive=True)]
    rows += [prediction(i) for i in range(6, 11)]
    m = aggregate(rows)
    assert m.accuracy == 0.8 and m.precision == 0.75 and m.recall == 0.75
    assert m.f1 == 0.75 and m.false_negative_rate == 0.25
    assert m.false_positive_rate == pytest.approx(1 / 6)


@pytest.mark.parametrize("action", ["SANITIZE", "REQUIRE_CONFIRMATION", "BLOCK"])
def test_asr_does_not_count_non_allow(action):
    m = aggregate([prediction(label="attack", action=action, predicted_positive=True)])
    assert m.attack_success_rate_proxy == 0


def test_zero_denominators():
    empty = aggregate([])
    assert empty.samples == 0
    for field in (
        "accuracy",
        "precision",
        "recall",
        "f1",
        "false_positive_rate",
        "false_negative_rate",
        "attack_success_rate_proxy",
        "average_latency_ms",
        "p95_latency_ms",
        "action_accuracy",
    ):
        assert getattr(empty, field) is None
    safe = aggregate([prediction()])
    assert safe.precision is None and safe.recall is None and safe.f1 is None
    missed = aggregate([prediction(label="attack")])
    assert missed.precision is None and missed.recall == 0 and missed.f1 == 0
    assert missed.false_positive_rate is None and missed.false_negative_rate == 1
    assert "null" in empty.model_dump_json() and "NaN" not in empty.model_dump_json()


@pytest.mark.parametrize(("size", "p95"), [(1, 1), (20, 19), (21, 20), (100, 95)])
def test_nearest_rank(size, p95):
    m = aggregate([prediction(i) for i in range(size, 0, -1)])
    assert m.p95_latency_ms == p95
    assert m.average_latency_ms == (size + 1) / 2


@pytest.mark.parametrize("latency", [-1, float("nan"), float("inf")])
def test_invalid_latency(latency):
    with pytest.raises(ValidationError):
        prediction(latency_ms=latency)


def test_valid_dataset_and_hash(tmp_path):
    path = write_data(tmp_path, [sample()])
    data = load_dataset([path])
    assert data.records[0].id == "sample-1"
    assert len(data.sources[0]["sha256"]) == 64
    assert data == load_dataset([path])
    path.write_text(path.read_text() + "\n", encoding="utf-8")
    with pytest.raises(EvaluationError, match="record 2"):
        load_dataset([path])


def test_unicode_line_separator_is_not_a_jsonl_delimiter(tmp_path):
    path = tmp_path / "unicode.jsonl"
    value = sample(input={"text": "First\u2028second\u0085third"})
    path.write_text(json.dumps(value, ensure_ascii=False) + "\n", encoding="utf-8")
    assert load_dataset([path]).records[0].input.text == value["input"]["text"]


@pytest.mark.parametrize(
    "change",
    [
        {"id": "bad\nidentifier"},
        {"label": "unknown"},
        {"attack_type": []},
        {"attack_type": "unknown"},
        {"expected_action": "EXECUTE"},
        {"kind": "tool"},
        {"input": {"text": 12}},
        {"input": {"text": ""}},
        {"input": {"text": "x" * 20001}},
        {"input": {"text": "ok", "extra-secret": "private"}},
        {"extra": "private"},
        {"kind": "email"},
        {"label": "attack"},
        {"attack_type": "phishing"},
        {"kind": "url", "input": {"url": True}},
    ],
)
def test_invalid_record_redacted(tmp_path, change):
    path = write_data(tmp_path, [sample(**change)])
    with pytest.raises(EvaluationError) as error:
        load_dataset([path])
    assert str(path.as_posix()) in str(error.value) and "record 1" in str(error.value)
    assert "private" not in str(error.value) and "extra-secret" not in str(error.value)


@pytest.mark.parametrize("field", list(sample()))
def test_required_fields(tmp_path, field):
    value = sample()
    del value[field]
    with pytest.raises(EvaluationError, match="invalid record schema"):
        load_dataset([write_data(tmp_path, [value])])


@pytest.mark.parametrize(
    "raw", ["", "{broken-secret", "[]", "null", '{"id":1,"id":2}', '{"input":NaN}', "\n"]
)
def test_malformed_json(tmp_path, raw):
    path = tmp_path / "data.jsonl"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(EvaluationError) as error:
        load_dataset([path])
    assert "broken-secret" not in str(error.value)


@pytest.mark.parametrize("separate_files", [False, True])
def test_duplicate_ids(tmp_path, separate_files):
    path = write_data(tmp_path, [sample()] if separate_files else [sample(), sample()])
    with pytest.raises(EvaluationError, match="duplicate ID"):
        load_dataset([path, path] if separate_files else [path])


def test_file_errors(tmp_path):
    path = tmp_path / "missing.jsonl"
    with pytest.raises(EvaluationError, match="cannot read"):
        load_dataset([path])
    path.write_bytes(b"\xff")
    with pytest.raises(EvaluationError, match="UTF-8"):
        load_dataset([path])
    path.write_bytes(b"x" * (4 * 1024 * 1024 + 1))
    with pytest.raises(EvaluationError, match="4 MiB"):
        load_dataset([path])


@pytest.mark.parametrize("kind", ["prompt", "text", "email"])
def test_routing(kind):
    adapter = EvaluationAdapter()
    service = Mock()
    adapter.service = service
    getattr(service, f"analyze_{kind}").return_value = SecurityOrchestrator().analyze_text("Hello")
    value = (
        {"sender": "team@example.org", "subject": "Plan", "body": "Draft"}
        if kind == "email"
        else {"text": "Draft"}
    )
    row = Record.model_validate(sample(kind=kind, input=value))
    assert adapter.predict(row.kind, row.input) == (False, "ALLOW", 0.0)
    getattr(service, f"analyze_{kind}").assert_called_once_with(*value.values())
    assert (
        sum(getattr(service, f"analyze_{k}").call_count for k in ("prompt", "text", "email")) == 1
    )


def test_url_routing_shared_policy():
    adapter = EvaluationAdapter()
    adapter.url_guard = Mock()
    adapter.url_guard.detect.return_value = [Finding("suspicious_url", 0.45, "Why", "Advice")]
    assert adapter.predict("url", URLInput(url="synthetic")) == (True, "REQUIRE_CONFIRMATION", 0.45)
    adapter.url_guard.detect.assert_called_once_with("synthetic")


def test_no_label_leakage_and_deterministic_serialization(monkeypatch):
    ticks = iter([1.0, 1.001, 2.0, 2.001])
    monkeypatch.setattr(benchmark, "perf_counter", lambda: next(ticks))
    adapter = Mock(spec=EvaluationAdapter)
    adapter.predict.return_value = (False, "ALLOW", 0.0)
    safe = Record.model_validate(sample())
    attack = Record.model_validate(
        sample(id="sample-2", label="attack", attack_type="jailbreak", expected_action="BLOCK")
    )
    report = run(Dataset((safe, attack), ()), adapter=adapter)
    assert adapter.predict.call_args_list[0] == adapter.predict.call_args_list[1]
    assert adapter.predict.call_args.args == ("prompt", safe.input)
    assert report["metrics"]["fn"] == 1 and report["metrics"]["tn"] == 1
    assert report["metrics"]["action_mismatch_ids"] == ["sample-2"]
    assert report["metrics"]["average_latency_ms"] == pytest.approx(1)
    assert serialize(report) == serialize(json.loads(serialize(report)))
    assert "Example input" not in serialize(report)


def test_filter_and_empty_selection():
    data = Dataset((Record.model_validate(sample()),), ())
    assert run(data, kind="prompt")["metrics"]["samples"] == 1
    with pytest.raises(EvaluationError, match="No samples"):
        run(data, kind="url")


def test_execution_error_redacted():
    adapter = Mock(spec=EvaluationAdapter)
    adapter.predict.side_effect = RuntimeError("raw-input-secret")
    with pytest.raises(EvaluationError, match="sample-1") as error:
        run(Dataset((Record.model_validate(sample()),), ()), adapter=adapter)
    assert "raw-input-secret" not in str(error.value)


def test_cli_output_and_exit_codes(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    path = write_data(tmp_path, [sample(label="attack", attack_type="jailbreak")])
    assert main(["--dataset", str(path), "--json", "--output", "report.json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report == json.loads((tmp_path / "report.json").read_text())
    assert report["metrics"]["false_negative_rate"] == 1
    assert main(["--dataset", str(path), "--output", "report.json"]) == 1
    assert main(["--dataset", str(path), "--output", "../outside.json"]) == 1
    assert main(["--dataset", "//server/share/data.jsonl"]) == 1
    assert main(["--dataset", "absent.jsonl"]) == 1
    assert main(["--dataset", str(path), "--kind", "email"]) == 1
    assert "Traceback" not in capsys.readouterr().err


def test_help(capsys):
    with pytest.raises(SystemExit) as result:
        main(["--help"])
    assert result.value.code == 0
    assert "--dataset" in capsys.readouterr().out
