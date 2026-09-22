# Threat model — Phases 1–2

## Assets

Service availability, configuration, diagnostic logs, and HTTP response integrity.
Prompt confidentiality and assessment integrity are also assets. Submitted text
is processed transiently; no user documents, LLM secrets or tool credentials
are persisted by this phase.

## Trust boundaries and attack surfaces

HTTP clients are untrusted; environment configuration is operator-controlled.
Exposed surfaces are `/health`, `/analyze/prompt`, OpenAPI, and interactive API
documentation. The text field may contain external documents, but source identity
and user intent cannot be verified from text. There are no outbound requests,
tool execution or file uploads. The calling application is responsible for
enforcing BLOCK/REQUIRE_CONFIRMATION before sending anything to an LLM.

## Threats and mitigations

Input or exception content could leak through diagnostics. Responses use generic
errors; application logs exclude bodies, headers, paths, query strings, and
exception messages. Request IDs are generated locally, not trusted from clients.
The documented command disables Uvicorn access logs and binds to loopback.
Strict response models reject extra fields and unexpected types. Missing optional
configuration does not prevent startup; invalid explicit settings fail validation.

PromptGuard detects known linguistic indicators of Prompt Injection, instruction
override, Jailbreak, system prompt/Secret extraction and suspicious role claims.
Indirect Prompt Injection indicators combine external-source/model-address
context with actual suspicious instructions, or instructions to obey documents.
Unicode normalization handles some formatting and compatibility obfuscations.
Contextual educational quotations receive reduced weights to limit false positives.
Scores are deterministic heuristic strengths, not calibrated probabilities.

Resource exhaustion is partially constrained by a 20,000-character text limit,
a 128-KiB streamed body limit before JSON parsing, and bounded regex gaps. Large
requests receive 413; invalid schemas receive 422 without echoing input. No raw
prompt or matching substring is copied into explanations, logs or errors.

Phishing, Malicious URL, Tool abuse and actual Privilege escalation enforcement
remain future work. Role-manipulation text detection is not permission enforcement.

## Residual risks

This is an experimental heuristic detector. It has no authentication,
rate limiting, TLS termination, or production deployment hardening. Health success
does not assert input safety. Hosting servers/proxies and third-party libraries
have their own logging policies; application redaction does not configure them.
Coded payloads (including base64), arbitrary homoglyph substitution, punctuation
inside words, paraphrases, non-English instructions, multi-turn attacks and novel
role formats may evade detection. Educational-context spoofing can cause false
negatives; quoted examples cannot be proven harmless. Large collections of examples
can accumulate enough evidence to be flagged. Negated commands, legitimate
administrator roleplay, requests about credentials, and unquoted security analysis
can cause false positives. Pattern matching does not understand intent or semantics.
The small regression fixture does not measure real-world FPR/FNR or coverage.
An ALLOW result must never grant extra privileges or replace isolation and least
privilege. Body limits do not prevent slow clients, concurrent load, oversized
headers or resource use in hosting infrastructure; production controls remain
outside this phase. No claim of comprehensive injection prevention is made.
