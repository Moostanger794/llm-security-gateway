# Architecture — Phases 1–4

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
SecurityOrchestrator → PromptGuard → text-free Findings → RiskEngine →
SecurityAdvisor → SecurityResult → metadata-only log.
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
can contribute findings without replacing local rules. No LLM client,
tool guardian, runtime monitor, evaluation pipeline or UI is implemented.

## Email analysis (Phase 3)

`POST /analyze/email` is a synchronous worker-pool route using strict EmailRequest
and the existing SecurityResult. EmailGuard validates original field lengths,
normalizes text/sender, collects Findings from email heuristics, URLGuard, and
PromptGuard.detect. SecurityOrchestrator calls detect and then the unchanged
RiskEngine.score/decide and SecurityAdvisor. No LLM integration or alternative
scoring engine is present. Standalone guard analyze methods remain compatible.
All analysis is transient and stateless; no new dependencies are required.

`email_normalization.py` owns shared API/direct-call limits: sender 320, subject
998, body 100,000 original Unicode characters. All fields are required, nonempty
and must have visible content. Malformed sender syntax becomes detector evidence.
NFKC and strict mailbox parsing handle display names; IDNA normalizes the domain.
An explicit email address in the display name with a different domain is a mismatch;
arbitrary brand/person names cannot be verified. Sender domains use URLGuard's
lexical hostname checks. A link domain differing from sender is not itself an alert.

Email prose uses existing NFKD/case folding, invisible mark removal and whitespace
normalization. HTML entities and simple bounded tags are handled; this is not a
browser or MIME parser. PromptGuard.detect checks the entire body, without the
20,000-character prompt endpoint limit. Both raw canonical text and readable HTML
are checked to preserve serialized role markers and detect instructions across tags.
Findings are deduplicated. Strong prompt findings (weight > .5, excluding credential
extraction alone) gain an indirect-injection context Finding (.65), since email is
an external source. PromptGuard rules and its educational quote handling are unchanged.

URLGuard returns static, text-free `suspicious_url` Findings. `extract_urls` returns
first-seen unique links from subject and body, including HTML attributes. Explicit
`scheme://`, protocol-relative, www and selected unsafe scheme forms are recognized;
bare domains/relative paths are not guessed. Entity decoding and trailing prose
punctuation trimming are deterministic; no URL is followed and no link-count cutoff
hides later links. Hostname parsing errors are Findings, not exceptions in the API.

| Evidence | Weight |
| --- | --- |
| Urgency alone / account-loss pressure | .10 / .30 |
| Direct credential request / login request with URL | .65 / .25 |
| Malformed or suspicious sender, explicit display-address mismatch | .35 |
| Secrecy/payment pressure or account-loss + credential/login request | .45 social_engineering |
| Credential/login request + urgency, account loss, sender indicator or URL weight ≥ .20 | .45 phishing |
| HTTP / account-related URL keyword / unusual port | .10 / .20 / .20 |
| URL length >2048 / IDN or punycode / external redirect-like target | .25 / .35 / .35 |
| IP, unusual numeric host, single-label host, deep or domain-like subdomain | .45 |
| Concealed characters or deceptive separators | .45 |
| Invalid hostname pattern / malformed parse or IDNA | .50 / .55 |
| Embedded credentials / unsupported or unsafe scheme | .65 / .70 |

RiskEngine takes only the strongest URL finding across all URLs; duplicating URL
features does not inflate scores. Independent categories combine using the existing
formula and boundaries. Composite phishing evidence deliberately increases urgency
when signals co-occur. Correlated categories make this a conservative policy, not
a calibrated statistical estimate. Explanations preserve all unique reasons and
static advice without echoing sender, subject, body, URLs or query parameters.

RequestBodyLimit extends the previous byte-counting middleware to all HTTP routes:
1280 KiB by default, retaining 128 KiB for `/analyze/prompt`, `/analyze/text` and their slash variants.
The email budget covers worst-case surrogate-pair JSON escaping. Actual received
bytes are counted before JSON parsing regardless of Content-Length. Rejected input
receives existing redacted 413/422 responses with a server-generated request ID.
Application logs contain request metadata and analysis risk/action/time only.

## Verification

Unit tests cover fixtures, normalization, context, deterministic aggregation,
boundaries, direct-call validation and strict output models. HTTP tests cover
contracts and invalid/oversized input. Integration tests verify privacy and actual
ASGI chunks without trusting Content-Length. `scripts/smoke_prompt.py` starts a
real Uvicorn process and checks health plus safe/dangerous prompts, emails and text over TCP, followed by graceful shutdown.
The Phase 1 OpenAPI route-set assertion includes the new endpoint; its other
regression assertions remain unchanged.

## Orchestration service (Phase 4)

```text
Client / direct Python caller
  |
  v
FastAPI strict schemas + byte limit (HTTP only)
  |
  v
SecurityOrchestrator (validates direct calls too)
  |
  +-- prompt/text --> PromptGuard.detect
  |
  +-- email -------> EmailGuard.detect
                       +--> PromptGuard.detect
                       +--> URLGuard.detect
  |
  v
Unique Findings, canonical ordering
  |
  v
RiskEngine.score / decide (one shared policy)
  |
  v
SecurityAdvisor (static metadata, deduplicated reasons/advice)
  |
  v
SecurityResult
```

`orchestration/orchestrator.py` exposes analyze_prompt(text), analyze_text(text),
and analyze_email(sender, subject, body). Constructor injection accepts structural
TextDetector/EmailDetector protocols, RiskEngine and SecurityAdvisor. The HTTP
get_orchestrator dependency creates a service per request and can be overridden
in tests. No request data or findings are stored on instances or in globals.
Injected implementations must be stateless trusted code returning text-free findings.

The orchestrator invokes detect, not legacy analyze wrappers, so email composition
is scored once. It does not run email analysis on plain text or double-run email's
nested detectors. Exact findings are deduplicated before scoring; distinct findings
within a category retain the existing maximum-weight semantics. Sorted threats,
reasons and recommendations are independent of detector traversal order. Only
processing_time_ms is nondeterministic. Existing standalone guard analyze methods
remain for compatibility; the API uses the common service exclusively.

TextRequest inherits PromptRequest validation (strict string, no extra fields,
20,000 original characters). No source/context parameter is introduced. Existing
lexical contextual detection remains unchanged. Shared visible-content validation
now also rejects control-only strings such as NUL for all service entry points.
Direct invalid arguments raise static TypeError/ValueError messages without input;
unexpected internal failures propagate to the HTTP redaction boundary (500).
The advisor only formats trusted findings and the score, never raw input. It is
not a classifier, a second policy engine or an external model.
