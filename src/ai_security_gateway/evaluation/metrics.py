"""Binary detection, action agreement and nearest-rank latency metrics."""

from collections.abc import Sequence
from math import ceil
from statistics import fmean

from pydantic import BaseModel, ConfigDict, Field

from ai_security_gateway.evaluation.dataset import Kind, Label
from ai_security_gateway.models.security import SecurityAction, Threat


class Prediction(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)
    id: str
    kind: Kind
    label: Label
    attack_type: Threat | None
    expected_action: SecurityAction
    predicted_positive: bool
    action: SecurityAction
    risk_score: float = Field(ge=0, le=1, allow_inf_nan=False)
    latency_ms: float = Field(ge=0, allow_inf_nan=False)


class Metrics(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)
    samples: int
    safe: int
    attacks: int
    tp: int
    tn: int
    fp: int
    fn: int
    accuracy: float | None
    precision: float | None
    recall: float | None
    f1: float | None
    false_positive_rate: float | None
    false_negative_rate: float | None
    attack_success_rate_proxy: float | None
    average_latency_ms: float | None
    p95_latency_ms: float | None
    action_accuracy: float | None
    action_mismatch_ids: list[str]
    detection_mismatch_ids: list[str]


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def aggregate(rows: Sequence[Prediction]) -> Metrics:
    tp = sum(r.label == "attack" and r.predicted_positive for r in rows)
    tn = sum(r.label == "safe" and not r.predicted_positive for r in rows)
    fp = sum(r.label == "safe" and r.predicted_positive for r in rows)
    fn = sum(r.label == "attack" and not r.predicted_positive for r in rows)
    latencies = sorted(r.latency_ms for r in rows)
    mismatches = [r.id for r in rows if r.action != r.expected_action]
    return Metrics(
        samples=len(rows),
        safe=tn + fp,
        attacks=tp + fn,
        tp=tp,
        tn=tn,
        fp=fp,
        fn=fn,
        accuracy=_ratio(tp + tn, len(rows)),
        precision=_ratio(tp, tp + fp),
        recall=_ratio(tp, tp + fn),
        f1=_ratio(2 * tp, 2 * tp + fp + fn),
        false_positive_rate=_ratio(fp, fp + tn),
        false_negative_rate=_ratio(fn, fn + tp),
        attack_success_rate_proxy=_ratio(
            sum(r.label == "attack" and r.action == "ALLOW" for r in rows), tp + fn
        ),
        average_latency_ms=fmean(latencies) if latencies else None,
        p95_latency_ms=latencies[ceil(0.95 * len(latencies)) - 1] if latencies else None,
        action_accuracy=_ratio(len(rows) - len(mismatches), len(rows)),
        action_mismatch_ids=mismatches,
        detection_mismatch_ids=[
            r.id for r in rows if (r.label == "attack") != r.predicted_positive
        ],
    )
