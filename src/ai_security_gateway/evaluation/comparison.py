"""Indirect-injection comparison. Defaults to rules; live calls need explicit opt-in."""

import argparse
import platform
import subprocess
import sys
from time import perf_counter
from typing import Literal

from ai_security_gateway import __version__
from ai_security_gateway.api.schemas import EmailRequest
from ai_security_gateway.core.config import Settings
from ai_security_gateway.evaluation.benchmark import local_path, serialize
from ai_security_gateway.evaluation.comparison_metrics import percentile, summarize_mode
from ai_security_gateway.evaluation.dataset import EvaluationError
from ai_security_gateway.evaluation.injection_dataset import (
    DEFAULT_INJECTION_DATASETS,
    InjectionDataset,
    InjectionRecord,
    load_injection_dataset,
)
from ai_security_gateway.evaluation.metrics import Prediction
from ai_security_gateway.llm import (
    CLASSIFIER_PROMPT_VERSION,
    POLICY_VERSION,
    ClassificationOutcome,
    Classifier,
    ClassifierInput,
    OpenAIClassifier,
    RequestBudget,
    build_classifier,
    to_findings,
)
from ai_security_gateway.models.security import SecurityResult
from ai_security_gateway.orchestration import SecurityOrchestrator

Mode = Literal["rules", "llm-only", "hybrid", "compare"]
Split = Literal["dev", "holdout", "all"]


def code_state() -> dict:
    """Read revision and dirty flag only; never emit paths or Git error text."""
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5, check=True
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain"], capture_output=True, timeout=5, check=True
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return {"revision": None, "dirty": None}
    return {"revision": revision, "dirty": bool(status)}


def classifier_input(record: InjectionRecord) -> ClassifierInput:
    """Labels, sample IDs and provenance never cross the classification boundary."""
    if isinstance(record.input, EmailRequest):
        return ClassifierInput(source_type="email", **record.input.model_dump())
    return ClassifierInput(source_type="document", text=record.input.text)


def _row(
    record: InjectionRecord,
    result: SecurityResult | None,
    latency_ms: float,
    actual_mode: str,
    outcome: ClassificationOutcome | None = None,
) -> dict:
    prediction = None
    if result is not None:
        prediction = Prediction(
            id=record.id,
            kind=record.kind,
            label=record.label,
            attack_type=record.attack_type,
            expected_action=record.expected_action,
            predicted_positive=not result.safe,
            action=result.action,
            risk_score=result.risk_score,
            latency_ms=latency_ms,
        ).model_dump()
    return {
        "id": record.id,
        "split": record.split,
        "group": record.group,
        "label": record.label,
        "actual_mode": actual_mode,
        "llm_status": outcome.status if outcome else "disabled",
        "fallback_reason": outcome.fallback_reason if outcome else None,
        "model": outcome.model if outcome else None,
        "latency_ms": latency_ms,
        "prediction": prediction,
    }


def run_comparison(
    dataset: InjectionDataset,
    *,
    mode: Mode = "rules",
    split: Split = "dev",
    classifier: Classifier | None = None,
    live: bool = False,
    limits: dict | None = None,
) -> dict:
    """Measure shared calls once. An injected classifier is an offline protocol test by default.

    Caller owns classifier lifetime. Network-capable OpenAI adapters additionally
    require `live=True` and a positive budget here, independently of CLI gates.
    Custom classifiers are trusted offline test dependencies, not live providers.
    """
    if mode not in {"rules", "llm-only", "hybrid", "compare"}:
        raise EvaluationError("Unsupported comparison mode")
    if split not in {"dev", "holdout", "all"}:
        raise EvaluationError("Unsupported split")
    if mode != "rules" and classifier is None:
        raise EvaluationError("Non-rules comparison requires an explicitly supplied classifier")
    network_provider = (
        mode != "rules" and isinstance(classifier, OpenAIClassifier) and classifier.uses_network
    )
    if network_provider and (
        not live or classifier.budget is None or classifier.budget.max_requests <= 0
    ):
        raise EvaluationError("Network comparison requires live=True and a positive request budget")
    if mode != "rules" and isinstance(classifier, OpenAIClassifier):
        settings = classifier.settings
        actual_limits = {
            "max_requests": classifier.budget.max_requests if classifier.budget else None,
            "max_retries": settings.llm_max_retries,
            "timeout_seconds": settings.llm_timeout_seconds,
            "max_input_chars": settings.llm_max_input_chars,
            "max_output_tokens": settings.llm_max_output_tokens,
        }
        if limits and any(
            key not in actual_limits or actual_limits[key] != value for key, value in limits.items()
        ):
            raise EvaluationError("Report limits must match classifier configuration")
        limits = actual_limits
    selected = [row for row in dataset.records if split == "all" or row.split == split]
    if not selected:
        raise EvaluationError("No samples match the requested split")
    modes = ("rules", "llm-only", "hybrid") if mode == "compare" else (mode,)
    rows: dict[str, list[dict]] = {name: [] for name in modes}
    calls: list[dict] = []
    service = SecurityOrchestrator()
    for record in selected:
        try:
            started = perf_counter()
            data = classifier_input(record)
            input_ms = (perf_counter() - started) * 1000
            rules_started = perf_counter()
            findings = service.collect_findings(data)
            rules = service.result_from_findings(findings, started)
            rules_ms = input_ms + (perf_counter() - rules_started) * 1000
            if "rules" in rows:
                rows["rules"].append(_row(record, rules, rules_ms, "rules"))
            if mode == "rules":
                continue
            # No ground truth, rule score, or expected policy is passed to the model.
            llm_started = perf_counter()
            outcome = classifier.classify(data)
            llm_ms = (perf_counter() - llm_started) * 1000
            calls.append(
                {
                    "id": record.id,
                    "status": outcome.status,
                    "fallback_reason": outcome.fallback_reason,
                    "model": outcome.model,
                    "requests": outcome.requests,
                    "reservations": outcome.reservations,
                    "released_reservations": outcome.released_reservations,
                    "input_tokens": outcome.input_tokens,
                    "output_tokens": outcome.output_tokens,
                    "call_latency_ms": llm_ms,
                }
            )
            successful = (
                outcome.status == "success"
                and outcome.result is not None
                and outcome.result.verdict in {"attack", "no_attack_detected"}
            )
            local_started = perf_counter()
            llm_findings = to_findings(outcome) if successful else []
            conversion_ms = (perf_counter() - local_started) * 1000
            if "llm-only" in rows:
                local_started = perf_counter()
                llm_result = (
                    service.result_from_findings(llm_findings, local_started)
                    if successful
                    else None
                )
                latency = (
                    input_ms + llm_ms + conversion_ms + (perf_counter() - local_started) * 1000
                )
                rows["llm-only"].append(
                    _row(
                        record,
                        llm_result,
                        latency,
                        "llm-only" if successful else "unresolved",
                        outcome,
                    )
                )
            if "hybrid" in rows:
                local_started = perf_counter()
                hybrid_result = service.result_from_findings(
                    [*findings, *llm_findings], local_started
                )
                latency = (
                    rules_ms + llm_ms + conversion_ms + (perf_counter() - local_started) * 1000
                )
                rows["hybrid"].append(
                    _row(
                        record,
                        hybrid_result,
                        latency,
                        "hybrid" if successful else "fallback_rules",
                        outcome,
                    )
                )
        except Exception:
            # A custom dependency can raise an exception containing private input.
            raise EvaluationError("Comparison failed at the analysis boundary") from None
    reports = {name: summarize_mode(values, name) for name, values in rows.items()}
    uncached = [call["call_latency_ms"] for call in calls if call["requests"] > 0]
    token_calls = [call for call in calls if call["input_tokens"] is not None]
    output_calls = [call for call in calls if call["output_tokens"] is not None]
    return {
        "report_version": 2,
        "project_version": __version__,
        "python_version": platform.python_version(),
        "code": code_state(),
        "dataset_revision": dataset.revision,
        "datasets": list(dataset.sources),
        "execution": "live_manual"
        if network_provider
        else ("offline_rules" if mode == "rules" else "offline_test"),
        "quality_claim": (
            "Rules baseline on this corpus only"
            if mode == "rules"
            else (
                "Manual API experiment; inspect coverage before comparison"
                if network_provider
                else "Protocol/policy test only; not real LLM quality"
            )
        ),
        "configuration": {
            "mode": mode,
            "live_requested": live,
            "split": split,
            "sample_ids": [record.id for record in selected],
            "classifier_prompt_version": CLASSIFIER_PROMPT_VERSION,
            "policy_version": POLICY_VERSION,
            "model_ids": sorted({call["model"] for call in calls if call["model"]}),
            "limits": limits or {},
            "repeats": 1,
            "warmup": 0,
            "latency_clock": "perf_counter",
            "percentiles": "nearest_rank",
            "latency_method": "sum of measured per-mode stages; shared provider wait included once",
            "response_reuse": "one transient response per sample shared by llm-only and hybrid",
            "persistent_cache": False,
        },
        "complete": all(report["experiment_complete"] for report in reports.values()),
        "operational": {
            "provider_requests": sum(call["requests"] for call in calls),
            "reservations": sum(call["reservations"] for call in calls),
            "released_reservations": sum(call["released_reservations"] for call in calls),
            "classifications": len(calls),
            "input_tokens": sum(call["input_tokens"] for call in token_calls)
            if token_calls
            else None,
            "output_tokens": (
                sum(call["output_tokens"] for call in output_calls) if output_calls else None
            ),
            "input_usage_available_calls": len(token_calls),
            "output_usage_available_calls": len(output_calls),
            "calls_with_requests": len(uncached),
            "uncached_call_p50_ms": percentile(uncached, 0.5),
            "uncached_call_p95_ms": percentile(uncached, 0.95),
            "budget_exhausted": any(call["status"] == "budget_exhausted" for call in calls),
            "calls": calls,
        },
        "modes": reports,
    }


def summary(report: dict) -> str:
    lines = [report["quality_claim"], f"Complete experiment: {report['complete']}"]
    lines.append(f"Execution: {report['execution']}; split: {report['configuration']['split']}")
    for name, result in report["modes"].items():
        lines.append(
            f"{name}: samples={result['samples']}; coverage={result['prediction_coverage']:.3f}; "
            f"unresolved={result['unresolved_count']}; fallback={result['fallback_count']}"
        )
        if result["metrics"] is None:
            lines.append(
                "  Complete-dataset quality metrics unavailable; see resolved subset in JSON"
            )
        else:
            metrics = result["metrics"]
            for key in (
                "tp",
                "tn",
                "fp",
                "fn",
                "precision",
                "recall",
                "f1",
                "false_positive_rate",
                "false_negative_rate",
                "attack_success_rate_proxy",
                "benign_allow_rate",
                "review_rate",
                "p50_latency_ms",
                "p95_latency_ms",
            ):
                lines.append(f"  {key}: {metrics[key]}")
    lines.append(
        "Provider requests (including retries, counted once): "
        f"{report['operational']['provider_requests']}"
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", action="append", help="Local v2 JSONL, repeatable")
    parser.add_argument(
        "--mode", choices=("rules", "llm-only", "hybrid", "compare"), default="rules"
    )
    parser.add_argument("--split", choices=("dev", "holdout", "all"), default="dev")
    parser.add_argument(
        "--live", action="store_true", help="Explicit external API experiment opt-in"
    )
    parser.add_argument("--max-requests", type=int, help="Required positive live attempt budget")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", help="New .json report within cwd; never overwritten")
    args = parser.parse_args(argv)
    classifier = None
    output_stream = None
    try:
        if args.mode != "rules" and (
            not args.live or args.max_requests is None or args.max_requests <= 0
        ):
            raise EvaluationError("LLM modes require --live and explicit positive --max-requests")
        if args.mode == "rules" and (args.live or args.max_requests is not None):
            raise EvaluationError("Rules mode does not accept live-request options")
        output = local_path(args.output) if args.output else None
        if output is not None and (output.suffix != ".json" or output.exists()):
            raise EvaluationError("Output must be a new .json file")
        paths = [local_path(str(path)) for path in (args.dataset or DEFAULT_INJECTION_DATASETS)]
        dataset = load_injection_dataset(paths)
        # Reserve the output before any provider can spend the request budget.
        # Exclusive opening also checks parent existence and actual write access.
        if output is not None:
            output_stream = output.open("x", encoding="utf-8", newline="\n")
        limits = {}
        if args.mode != "rules":
            settings = Settings()
            classifier = build_classifier(settings, budget=RequestBudget(args.max_requests))
            limits = {
                "max_requests": args.max_requests,
                "max_retries": settings.llm_max_retries,
                "timeout_seconds": settings.llm_timeout_seconds,
                "max_input_chars": settings.llm_max_input_chars,
                "max_output_tokens": settings.llm_max_output_tokens,
            }
        report = run_comparison(
            dataset,
            mode=args.mode,
            split=args.split,
            classifier=classifier,
            live=args.live,
            limits=limits,
        )
        encoded = serialize(report)
        if output_stream is not None:
            output_stream.write(encoded)
            output_stream.flush()
        print(encoded if args.json else summary(report), end="" if args.json else "\n")
        return 0 if report["complete"] else 2
    except EvaluationError as exc:
        print(f"Evaluation error: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError):
        print("Evaluation error: report could not be generated or written", file=sys.stderr)
        return 1
    finally:
        if output_stream is not None:
            output_stream.close()
        if classifier is not None:
            classifier.close()


if __name__ == "__main__":
    raise SystemExit(main())
