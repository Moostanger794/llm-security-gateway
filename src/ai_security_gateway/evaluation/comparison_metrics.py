"""Coverage-aware metrics for the indirect-injection experiment."""

from collections import Counter
from collections.abc import Sequence
from math import ceil

from ai_security_gateway.evaluation.metrics import Prediction, aggregate


def percentile(values: Sequence[float], quantile: float) -> float | None:
    """Nearest-rank percentile, matching the legacy benchmark's P95 convention."""
    ordered = sorted(values)
    return ordered[max(0, ceil(quantile * len(ordered)) - 1)] if ordered else None


def summarize_mode(rows: Sequence[dict], mode: str) -> dict:
    """Unresolved results have no prediction; never silently treat them as benign."""
    resolved = [Prediction.model_validate(row["prediction"]) for row in rows if row["prediction"]]
    unresolved = [row for row in rows if row["prediction"] is None]
    metrics = aggregate(resolved).model_dump()
    safe_count = sum(row.label == "safe" for row in resolved)
    metrics.update(
        benign_allow_rate=(
            sum(row.label == "safe" and row.action == "ALLOW" for row in resolved) / safe_count
            if safe_count
            else None
        ),
        review_rate=(
            sum(row.action == "REQUIRE_CONFIRMATION" for row in resolved) / len(resolved)
            if resolved
            else None
        ),
        p50_latency_ms=percentile([row.latency_ms for row in resolved], 0.5),
    )
    llm_success = sum(row["llm_status"] == "success" for row in rows)
    fallback = sum(row["actual_mode"] == "fallback_rules" for row in rows)
    all_latencies = [row["latency_ms"] for row in rows]
    return {
        "requested_mode": mode,
        "sample_ids": [row["id"] for row in rows],
        "samples": len(rows),
        "attacks": sum(row["label"] == "attack" for row in rows),
        "benign": sum(row["label"] == "safe" for row in rows),
        "prediction_coverage": len(resolved) / len(rows) if rows else None,
        "llm_coverage": llm_success / len(rows) if rows and mode != "rules" else None,
        "prediction_complete": not unresolved,
        "experiment_complete": not unresolved and (mode == "rules" or llm_success == len(rows)),
        # A subset's rates must not be mistaken for complete-dataset measurement.
        "metrics": metrics if not unresolved else None,
        "resolved_subset_metrics": metrics,
        "resolved_sample_ids": [row.id for row in resolved],
        "unresolved_count": len(unresolved),
        "unresolved_by_label": dict(Counter(row["label"] for row in unresolved)),
        "unresolved_ids": [row["id"] for row in unresolved],
        "unresolved_reasons": dict(Counter(row["llm_status"] for row in unresolved)),
        "fallback_count": fallback,
        "fallback_rate": fallback / len(rows) if rows else None,
        "llm_status_counts": dict(Counter(row["llm_status"] for row in rows)),
        "operational_latency_ms": {
            "samples": len(rows),
            "p50": percentile(all_latencies, 0.5),
            "p95": percentile(all_latencies, 0.95),
        },
        "predictions": list(rows),
    }
