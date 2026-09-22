"""Run from the repository root: python -m ai_security_gateway.evaluation.benchmark."""

import argparse
import json
import platform
import sys
from pathlib import Path
from time import perf_counter

from ai_security_gateway import __version__
from ai_security_gateway.api.schemas import EmailRequest, PromptRequest
from ai_security_gateway.evaluation.dataset import (
    Dataset,
    EvaluationError,
    Kind,
    URLInput,
    load_dataset,
)
from ai_security_gateway.evaluation.metrics import Prediction, aggregate
from ai_security_gateway.models.security import SecurityAction
from ai_security_gateway.orchestration import SecurityOrchestrator
from ai_security_gateway.security.risk_engine import RiskEngine
from ai_security_gateway.security.url_guard import URLGuard

DEFAULT_DATASETS = [Path(f"datasets/{name}/v1.jsonl") for name in ("prompts", "emails", "urls")]


class EvaluationAdapter:
    """Only kind and input cross this boundary; ground truth is unavailable here."""

    def __init__(self) -> None:
        self.service = SecurityOrchestrator()
        self.url_guard = URLGuard()
        self.risk_engine = RiskEngine()

    def predict(
        self, kind: Kind, data: PromptRequest | EmailRequest | URLInput
    ) -> tuple[bool, SecurityAction, float]:
        if kind == "url" and isinstance(data, URLInput):
            score = self.risk_engine.score(self.url_guard.detect(data.url))
            _, action, assessment = self.risk_engine.decide(score)
            return assessment != "SAFE", action, score
        if kind == "email" and isinstance(data, EmailRequest):
            result = self.service.analyze_email(data.sender, data.subject, data.body)
        elif kind in {"prompt", "text"} and isinstance(data, PromptRequest):
            method = self.service.analyze_prompt if kind == "prompt" else self.service.analyze_text
            result = method(data.text)
        else:
            raise EvaluationError("Input does not match evaluation kind")
        return not result.safe, result.action, result.risk_score


def run(
    dataset: Dataset, kind: Kind | None = None, adapter: EvaluationAdapter | None = None
) -> dict:
    adapter = adapter if adapter is not None else EvaluationAdapter()
    rows = []
    for record in dataset.records:
        if kind is not None and record.kind != kind:
            continue
        try:
            started = perf_counter()
            positive, action, score = adapter.predict(record.kind, record.input)
            elapsed = (perf_counter() - started) * 1000
            # Compare annotations only after completing prediction and timing.
            rows.append(
                Prediction(
                    id=record.id,
                    kind=record.kind,
                    label=record.label,
                    attack_type=record.attack_type,
                    expected_action=record.expected_action,
                    predicted_positive=positive,
                    action=action,
                    risk_score=score,
                    latency_ms=elapsed,
                )
            )
        except Exception:
            # CLI is a privacy boundary: detector exceptions may contain submitted input.
            raise EvaluationError(f"Analysis failed for sample id={record.id}") from None
    if not rows:
        raise EvaluationError("No samples match the requested kind")
    return {
        "report_version": 1,
        "project_version": __version__,
        "python_version": platform.python_version(),
        "datasets": list(dataset.sources),
        "configuration": {
            "kind": kind,
            "repeats": 1,
            "warmup": 0,
            "clock": "perf_counter",
            "p95": "nearest_rank",
            "offline": True,
        },
        "metrics": aggregate(rows).model_dump(),
        "by_kind": {
            k: aggregate([r for r in rows if r.kind == k]).model_dump()
            for k in sorted({r.kind for r in rows})
        },
        "by_attack_type": {
            k: aggregate([r for r in rows if (r.attack_type or "benign") == k]).model_dump()
            for k in sorted({r.attack_type or "benign" for r in rows})
        },
        "predictions": [r.model_dump() for r in rows],
    }


def serialize(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"


def summary(report: dict) -> str:
    lines = ["Local project-authored benchmark (not real-world detection rates)"]
    lines.append(f"Project: {report['project_version']}; Python: {report['python_version']}")
    lines.append("Configuration: " + json.dumps(report["configuration"], sort_keys=True))
    for source in report["datasets"]:
        lines.append(
            f"Dataset: {json.dumps(source['path'], ensure_ascii=True)}; "
            f"records={source['records']}; sha256={source['sha256']}"
        )
    for key, value in report["metrics"].items():
        if isinstance(value, list):
            lines.append(f"{key}: {len(value)}; IDs: {', '.join(value) or '-'}")
        else:
            display = (
                "undefined"
                if value is None
                else (f"{value:.6f}" if isinstance(value, float) else str(value))
            )
            lines.append(f"{key}: {display}")
    for kind, metrics in report["by_kind"].items():
        lines.append(
            f"{kind}: {metrics['samples']} samples, "
            f"{metrics['safe']} safe, {metrics['attacks']} attacks"
        )
    return "\n".join(lines)


def local_path(value: str) -> Path:
    """CLI paths stay inside cwd, including symlink resolution; no UNC inputs."""
    if value.startswith(("\\\\", "//")):
        raise EvaluationError("Network paths are not supported")
    path = Path(value)
    if not path.resolve().is_relative_to(Path.cwd().resolve()):
        raise EvaluationError("Paths must remain inside the current working directory")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", action="append", help="Local JSONL file (repeatable)")
    parser.add_argument("--kind", choices=("prompt", "text", "email", "url"))
    parser.add_argument("--json", action="store_true", help="Print JSON instead of summary")
    parser.add_argument("--output", help="Create a new .json report inside cwd; never overwrite")
    args = parser.parse_args(argv)
    try:
        paths = [local_path(str(p)) for p in (args.dataset or DEFAULT_DATASETS)]
        output = local_path(args.output) if args.output else None
        if output is not None and (output.suffix != ".json" or output.exists()):
            raise EvaluationError("Output must be a new .json file")
        report = run(load_dataset(paths), kind=args.kind)
        encoded = serialize(report)
        if output is not None:
            with output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(encoded)
        print(encoded if args.json else summary(report), end="" if args.json else "\n")
    except EvaluationError as exc:
        print(f"Evaluation error: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError):
        print("Evaluation error: report could not be generated or written", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
