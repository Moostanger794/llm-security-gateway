# Architecture — Foundation and Prompt Security

`create_app(Settings)` constructs a FastAPI instance with its own immutable
settings. The module-level `app` is the Uvicorn entrypoint. Settings load from
environment variables and an optional working-directory `.env`; defaults need
no network access, credentials, or database. Invalid configuration fails at startup.

Request flow: server-generated request ID → route → Pydantic response → completion
log with status and elapsed milliseconds. HTTP/validation errors use ErrorResponse;
unexpected route exceptions are redacted at the HTTP middleware boundary.
HealthResponse describes process liveness only. OpenAPI documents the contracts.

The lifespan configures the application logger and records startup/shutdown.
Logging is process-wide (as in Python's logging library); settings are per app.
The application's logger configuration does not replace third-party handlers.
Run Uvicorn with `--no-access-log` to avoid its raw-URL access logs.

## Prompt analysis

`POST /analyze/prompt` uses a strict PromptRequest and the shared SecurityResult
in `models/security.py`. The health/error contracts and service version remain
unchanged. The additive `assessment` field makes SAFE/SUSPICIOUS/DANGEROUS explicit.

Flow: request logging boundary → bounded ASGI body reader → strict validation →
PromptGuard → text-free Findings → RiskEngine → SecurityResult → metadata-only log.
The sync analysis route runs in FastAPI's worker pool. PromptGuard is stateless;
no prompt is retained or sent to another service. Rules and weights are immutable
definitions in `security/rules.py`. No dependencies were added.

Text is limited to 20,000 original Python Unicode characters and must contain
visible content; both direct Python calls and API validate it. Direct calls raise
ValueError/TypeError; HTTP schema violations return the existing redacted 422.
The endpoint's ASGI middleware counts actual bytes before JSON parsing, returning
redacted 413 above 128 KiB even without or with an inaccurate Content-Length.
It also covers the trailing-slash route before redirect handling. This is not
a general server-level header/concurrency/rate limit.

Normalization uses Unicode NFKD, case folding, removal of formatting/combining
marks, and punctuation/whitespace folding. It handles compatibility forms,
zero-width characters and punctuation between words; it is not a general decoder.
Bounded-gap regex rules identify verbs and protected targets. Heuristics recognize
serialized privileged role markers and co-occurrence of an external source,
model address, and strong instruction evidence.

Quoted examples with an explanatory prefix receive weight × 0.15 only for that
span. An execution cue disables the discount. Other spans remain fully scored;
quotation alone is not an exemption. This context heuristic is deliberately
limited and cannot establish the author's true intent.

RiskEngine takes the maximum evidence weight per category, then computes
`round(1 - product(1 - weight), 6)`. Duplicate evidence does not inflate scores.
There is no randomness or learned calibration. Policy has continuous boundaries:
LOW ≤ .20 (ALLOW/SAFE), MEDIUM ≤ .50 (REQUIRE_CONFIRMATION/SUSPICIOUS),
HIGH ≤ .75 (BLOCK/DANGEROUS), otherwise CRITICAL (BLOCK/DANGEROUS).
`safe` is true exactly for SAFE. Explanations and recommendations use only static
rule metadata. Threats can appear even in a SAFE educational assessment.

Finding and RiskEngine separate evidence production from policy: a later classifier
can contribute findings without replacing local rules. No LLM client, orchestrator,
email guard, tool guardian, runtime monitor, evaluation pipeline or UI is implemented.

## Verification

Unit tests cover fixtures, normalization, context, deterministic aggregation,
boundaries, direct-call validation and strict output models. HTTP tests cover
contracts and invalid/oversized input. Integration tests verify privacy and actual
ASGI chunks without trusting Content-Length. `scripts/smoke_prompt.py` starts a
real Uvicorn process and checks health plus safe/dangerous prompts over TCP.
The Phase 1 OpenAPI route-set assertion includes the new endpoint; its other
regression assertions remain unchanged.
