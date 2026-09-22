# Threat model — Phase 1

## Assets

Service availability, configuration, diagnostic logs, and HTTP response integrity.
No user documents, LLM secrets, or tool credentials are stored by this phase.

## Trust boundaries and attack surfaces

HTTP clients are untrusted; environment configuration is operator-controlled.
Exposed surfaces are `/health`, OpenAPI, and interactive API documentation.
No outbound requests, tool execution, file uploads, or analysis endpoints exist.

## Threats and mitigations

Input or exception content could leak through diagnostics. Responses use generic
errors; application logs exclude bodies, headers, paths, query strings, and
exception messages. Request IDs are generated locally, not trusted from clients.
The documented command disables Uvicorn access logs and binds to loopback.
Strict response models reject extra fields and unexpected types. Missing optional
configuration does not prevent startup; invalid explicit settings fail validation.

Prompt Injection, Indirect Prompt Injection, Jailbreak, Secret extraction,
Phishing, Malicious URL, Tool abuse, and Privilege escalation are target threats
for later phases. Foundation does not detect or mitigate them through analysis.

## Residual risks

This is an experimental foundation, not a security filter. It has no authentication,
rate limiting, TLS termination, or production deployment hardening. Health success
does not assert input safety. Hosting servers/proxies and third-party libraries
have their own logging policies; application redaction does not configure them.
