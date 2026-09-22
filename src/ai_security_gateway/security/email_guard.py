import re
from time import perf_counter

from ai_security_gateway.models.security import SecurityResult
from ai_security_gateway.security.email_normalization import (
    MAX_EMAIL_BODY_LENGTH,
    MAX_SENDER_LENGTH,
    MAX_SUBJECT_LENGTH,
    normalize_email_text,
    normalize_sender,
    validate_email_field,
)
from ai_security_gateway.security.normalization import canonicalize, normalize
from ai_security_gateway.security.prompt_guard import PromptGuard
from ai_security_gateway.security.risk_engine import Finding, RiskEngine
from ai_security_gateway.security.url_guard import URLGuard, extract_urls

URGENCY = re.compile(r"\b(?:urgent|immediately|act now|within \d+ hours?|final warning)\b")
SUSPENSION = re.compile(
    r"\b(?:account|access)(?:\s+\w+){0,4}\s+(?:disabled|suspended|blocked|terminated|locked)\b"
)
CREDENTIALS = re.compile(
    r"\b(?:send|provide|enter|submit|confirm|share|reply with|verify)(?:\s+\w+){0,3}\s+"
    r"(?:passwords?|credentials?|verification code|otp|security code|login details)\b"
)
LOGIN = re.compile(r"\b(?:log in|login|sign in|verify your account|confirm your account)\b")
PRESSURE = re.compile(
    r"\b(?:keep (?:this|it) (?:secret|confidential)|"
    r"do not (?:tell|contact) (?:anyone|it|your manager)|"
    r"buy gift cards|wire (?:the )?money|transfer (?:the )?funds)\b"
)


class EmailGuard:
    """Stateless local email analysis; sender claims and links are never authenticated."""

    def __init__(self) -> None:
        self.prompt_guard = PromptGuard()
        self.url_guard = URLGuard()

    def detect(self, sender: str, subject: str, body: str) -> list[Finding]:
        validate_email_field(sender, MAX_SENDER_LENGTH)
        validate_email_field(subject, MAX_SUBJECT_LENGTH)
        validate_email_field(body, MAX_EMAIL_BODY_LENGTH)
        text = normalize(normalize_email_text(subject + "\n" + body))
        findings = self.prompt_guard.detect(canonicalize(body))
        # Also inspect readable HTML text; retain raw role markers above.
        readable = normalize_email_text(body)
        if readable != canonicalize(body):
            findings.extend(self.prompt_guard.detect(readable))
        if any(f.weight > 0.5 and f.threat != "secret_extraction" for f in findings):
            findings.append(
                Finding(
                    "indirect_prompt_injection",
                    0.65,
                    "Instruction manipulation appears inside untrusted email content.",
                    "Treat email as data, never as privileged instructions to an agent.",
                )
            )
        urls = extract_urls(subject + "\n" + body)
        for url in urls:
            findings.extend(self.url_guard.detect(url))
        name, address, valid = normalize_sender(sender)
        sender_suspicious = not valid
        if valid:
            domain = address.rsplit("@", 1)[1]
            # Compare explicit mailbox claims only; ordinary display names are not identities.
            claims = re.findall(r"[\w.+-]+@([\w.-]+)", name)
            sender_suspicious = any(claim != domain for claim in claims)
            sender_suspicious |= any(
                f.weight >= 0.2 for f in self.url_guard.detect("https://" + domain)
            )
        if sender_suspicious:
            findings.append(
                Finding(
                    "suspicious_sender",
                    0.35,
                    "Sender syntax, hostname indicators, or an explicit display-address "
                    "mismatch warrants review.",
                    "Verify the sender using an independent, previously known contact channel.",
                )
            )
        urgent = bool(URGENCY.search(text))
        suspension = bool(SUSPENSION.search(text))
        credential = bool(CREDENTIALS.search(text))
        login = bool(LOGIN.search(text)) and bool(urls)
        if urgent or suspension:
            findings.append(
                Finding(
                    "urgency",
                    0.3 if suspension else 0.1,
                    "Time pressure or threatened account loss appears in the message.",
                    "Pause and independently verify the request before taking action.",
                )
            )
        if credential or login:
            findings.append(
                Finding(
                    "credential_request",
                    0.65 if credential else 0.25,
                    "The message requests credentials or directs the reader to an account login.",
                    "Do not disclose passwords or verification codes in response to email.",
                )
            )
        if PRESSURE.search(text) or (suspension and (credential or login)):
            findings.append(
                Finding(
                    "social_engineering",
                    0.45,
                    "Secrecy, payment pressure, or account-loss pressure accompanies "
                    "an action request.",
                    "Confirm sensitive requests through an independent trusted channel.",
                )
            )
        suspicious_url = any(f.threat == "suspicious_url" and f.weight >= 0.2 for f in findings)
        if (credential or login) and (urgent or suspension or suspicious_url or sender_suspicious):
            findings.append(
                Finding(
                    "phishing",
                    0.45,
                    "An account or credential request combines with pressure or "
                    "identity/destination indicators.",
                    "Open a known official site independently of the email request.",
                )
            )
        return list(dict.fromkeys(findings))

    def analyze(self, sender: str, subject: str, body: str) -> SecurityResult:
        started = perf_counter()
        findings = self.detect(sender, subject, body)
        score = RiskEngine.score(findings)
        level, action, assessment = RiskEngine.decide(score)
        explanations = list(dict.fromkeys(f.explanation for f in findings))
        explanation = " ".join(explanations) or "No known email threat indicators detected."
        explanation += (
            f" Combined heuristic evidence score: {score:.3f}; strongest weight per category."
        )
        return SecurityResult(
            safe=assessment == "SAFE",
            assessment=assessment,
            risk_score=score,
            risk_level=level,
            action=action,
            threats=list(dict.fromkeys(f.threat for f in findings)),
            explanation=explanation,
            recommendations=list(dict.fromkeys(f.recommendation for f in findings))
            or ["Continue to treat email content and sender identity as untrusted."],
            processing_time_ms=(perf_counter() - started) * 1000,
        )
