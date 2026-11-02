"""Local evidence policy: weights are decisions, not model probabilities."""

from ai_security_gateway.llm.models import ClassificationOutcome, ClassifierResponse
from ai_security_gateway.security.risk_engine import Finding

POLICY_VERSION = "llm-findings-v1"
LLM_ATTACK_WEIGHT = 0.80
REASONS = {
    "instruction_redirection": "The classifier identified an instruction redirecting AI behavior.",
    "override_hierarchy": "The classifier identified an attempt to override trusted instructions.",
    "privileged_role_claim": "The classifier identified an untrusted claim of a privileged role.",
    "extract_privileged_prompt": "The classifier identified a request for privileged instructions.",
    "extract_secrets": "The classifier identified an instruction to disclose sensitive data.",
    "disable_safety": "The classifier identified an instruction to disable safeguards.",
    "manipulate_verdict": "The classifier identified an attempt to manipulate its verdict.",
}
RECOMMENDATION = (
    "Treat external content as data; verify requested actions against trusted user instructions."
)


def to_findings(outcome: ClassificationOutcome) -> list[Finding]:
    if outcome.status != "success" or outcome.result is None:
        return []
    result = ClassifierResponse.model_validate(outcome.result.model_dump())
    if result.verdict != "attack":
        return []
    explanation = " ".join(REASONS[code] for code in sorted(result.reason_codes))
    return [
        Finding(threat, LLM_ATTACK_WEIGHT, explanation, RECOMMENDATION)
        for threat in sorted(result.threat_types)
    ]
