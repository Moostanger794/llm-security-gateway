import re
from dataclasses import dataclass

from ai_security_gateway.models.security import Threat


@dataclass(frozen=True)
class Rule:
    threat: Threat
    weight: float
    pattern: re.Pattern[str]
    explanation: str
    recommendation: str


# Bounded gaps accommodate natural phrasing without unbounded wildcard backtracking.
GAP = r"(?:\s+\w+){0,5}\s+"


def rule(threat: Threat, weight: float, pattern: str, why: str, advice: str) -> Rule:
    return Rule(threat, weight, re.compile(pattern), why, advice)


RULES = (
    rule(
        "instruction_override",
        0.8,
        rf"\b(?:ignore|disregard|forget|override|bypass|discard){GAP}"
        r"(?:instructions?|rules?|system|developer|directives?|policies)\b",
        "Instruction-discarding language targets the instruction hierarchy.",
        "Keep system/developer instructions separate from untrusted input.",
    ),
    rule(
        "system_prompt_extraction",
        0.85,
        rf"\b(?:reveal|show|print|repeat|output|disclose|display|return|give|tell){GAP}"
        r"(?:(?:system|developer)\s+(?:prompts?|messages?|instructions?)|"
        r"(?:hidden|initial|original|internal)\s+(?:instructions?|prompts?|rules?))\b",
        "Disclosure language targets privileged prompts or hidden instructions.",
        "Do not disclose privileged instructions or place secrets in prompts.",
    ),
    rule(
        "secret_extraction",
        0.85,
        rf"\b(?:reveal|show|print|output|dump|send|exfiltrate|disclose|give|list|return){GAP}"
        r"(?:secrets?|credentials?|passwords?|api\s+keys?|access\s+tokens?|"
        r"private\s+keys?|environment\s+variables?)\b",
        "Disclosure language targets credentials or sensitive configuration.",
        "Keep credentials outside model context and restrict access to secret stores.",
    ),
    rule(
        "jailbreak",
        0.8,
        rf"\b(?:(?:act|behave|operate){GAP}(?:unrestricted|uncensored|unfiltered)|"
        rf"(?:disable|remove|bypass){GAP}(?:safety|guardrails|restrictions|filters)|"
        r"(?:enable|activate|enter)\s+(?:dan|developer|jailbreak)\s+mode|"
        r"do\s+anything\s+now)\b",
        "Language requests a mode without normal safety constraints.",
        "Do not grant capabilities based on requested personas or modes.",
    ),
    rule(
        "role_manipulation",
        0.65,
        r"\b(?:(?:you\s+are\s+now|act\s+as|i\s+am\s+(?:the|your))\s+"
        r"(?:(?:a|an|the)\s+)?(?:system|developer|administrator|admin|root)|"
        r"(?:system|developer)\s+(?:message|override)\s*(?:starts|begins|here))\b",
        "Text claims a privileged role or attempts to reassign authority.",
        "Accept roles only from trusted application metadata, never from text.",
    ),
    rule(
        "indirect_prompt_injection",
        0.7,
        rf"\b(?:follow|obey|execute|apply){GAP}(?:instructions?|commands?)"
        rf"{GAP}(?:document|page|website|attachment|email|file)\b",
        "Text asks the model to treat external content as instructions.",
        "Treat retrieved documents as data and verify instructions with the user.",
    ),
    rule(
        "prompt_injection",
        0.45,
        r"\b(?:do\s+not\s+tell\s+(?:the\s+)?user|"
        r"(?:this|these)\s+(?:instructions?|message)\s+(?:takes?|has|have)\s+priority|"
        r"respond\s+only\s+with\s+(?:approved|authorized))\b",
        "Text attempts to redirect the response or conceal behavior from the user.",
        "Review the requested behavior against the user's actual task.",
    ),
)

EDUCATIONAL_WEIGHT_FACTOR = 0.15
EDUCATIONAL_PREFIX = re.compile(
    r"\b(?:explain|analy[sz]e|discuss|describe|definition|example|phrase|quote|"
    r"why|meaning|teach|study|detect)\b"
)
EXECUTION_CUE = re.compile(r"\b(?:execute|obey|follow|perform|carry\s+out)\b")
QUOTED = re.compile(
    r""""[^"\n]{1,2000}"|'[^'\n]{1,2000}'|`[^`]{1,2000}`|“[^”]{1,2000}”|‘[^’]{1,2000}’"""
)
ROLE_MARKER = re.compile(
    r"(?:<\|(?:im_start|system|developer)\|>|\[(?:system|developer)\]|<(?:system|developer)>)"
)
EXTERNAL_SOURCE = re.compile(r"\b(?:document|webpage|retrieved|attachment|email|website)\b")
MODEL_ADDRESS = re.compile(r"\b(?:assistant|llm|language\s+model|ai\s+agent)\b")
ROLE_MARKER_WEIGHT = 0.65
INDIRECT_CONTEXT_WEIGHT = 0.65
