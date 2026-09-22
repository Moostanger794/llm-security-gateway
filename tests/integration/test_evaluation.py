import ast
import json
import re
import socket
from pathlib import Path

from ai_security_gateway.evaluation.benchmark import DEFAULT_DATASETS, run, serialize, summary
from ai_security_gateway.evaluation.dataset import load_dataset


def test_real_benchmark_offline_private_deterministic(monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise AssertionError("Network attempted")

    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(socket, "getaddrinfo", fail)
    dataset = load_dataset(DEFAULT_DATASETS)
    report = run(dataset)
    repeated = run(dataset)
    assert report["metrics"]["samples"] == len(dataset.records) == 64
    assert set(report["by_kind"]) == {"prompt", "text", "email", "url"}
    assert report["metrics"]["tp"] > 0 and report["metrics"]["tn"] > 0
    for first, second in zip(report["predictions"], repeated["predictions"], strict=True):
        assert {k: v for k, v in first.items() if k != "latency_ms"} == {
            k: v for k, v in second.items() if k != "latency_ms"
        }
    serialized = serialize(report)
    readable = summary(report)
    assert report["datasets"][0]["sha256"] in readable
    assert "repeats" in readable and "0.1.0" in readable
    logs = capsys.readouterr()
    for record in dataset.records:
        for raw in record.input.model_dump().values():
            assert raw not in serialized + readable + logs.out + logs.err
    assert "synthetic-only" not in serialized
    assert json.loads(serialized)["project_version"] == "0.1.0"


def test_production_does_not_import_evaluation_or_datasets():
    root = Path("src/ai_security_gateway")
    for path in root.rglob("*.py"):
        if "evaluation" in path.parts:
            continue
        source = path.read_text("utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert "evaluation" not in (node.module or "")
            elif isinstance(node, ast.Import):
                assert all("evaluation" not in alias.name for alias in node.names)
        assert "datasets/" not in source and "v1.jsonl" not in source


def test_dataset_separation_and_obvious_secret_markers():
    dataset = load_dataset(DEFAULT_DATASETS)
    fixtures = []
    for path in Path("tests/fixtures").glob("*.json"):
        fixtures.extend(json.loads(path.read_text("utf-8")))
    old = [case["input"] for case in fixtures]
    for record in dataset.records:
        data = record.input.model_dump()
        assert data not in old
        assert data.get("text", object()) not in old
    raw = "\n".join(p.read_text("utf-8") for p in DEFAULT_DATASETS)
    assert not re.search(r"(?:sk-[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|-----BEGIN .*PRIVATE KEY)", raw)
    assert "synthetic-only" in raw
    assert "???" not in raw
    assert "Ｄｉｓｒｅｇａｒｄ" in raw and "Забудь" in raw and "bücher" in raw
