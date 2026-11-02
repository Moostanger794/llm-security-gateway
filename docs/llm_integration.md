# Optional LLM classifier — Phase 6

Implemented: one OpenAI Responses SDK adapter, strict output validation, per-call
diagnostics, explicit retries/budget, and local conservative evidence policy.
Verified: **offline** tests use the installed OpenAI **2.54.0** SDK with
`httpx.MockTransport`. This checks request construction, parsing, failures and
policy; it does **not** measure a real model's detection quality. No live requests
were made during implementation, and no account/model access was verified.

`pyproject.toml` pins `openai==2.54.0` because header isolation uses the SDK-private
`_custom_headers` mapping. Updating the SDK requires rerunning the header-isolation,
incompatible-mapping and request-accounting regression tests. This exact SDK pin
does not lock all transitive dependencies; the project does not have a complete
dependency lockfile.

## Consent and configuration

Both `ENABLE_LLM_ANALYSIS=true` and `ALLOW_EXTERNAL_LLM=true` are required, together
with explicitly configured `LLM_MODEL` and `LLM_API_KEY`. Defaults disable external
analysis. The key is a Pydantic `SecretStr`, loaded only from the named environment
variable or optional repository-working-directory `.env`. Empty key/model causes
diagnosed rules fallback, not application failure. Never use ChatGPT/Codex session
tokens or send a key in the analysis payload.

The endpoint is fixed to `https://api.openai.com/v1`; analyzed data cannot choose
the URL, model, prompt or permissions. Ambient `OPENAI_BASE_URL`, organization,
project, API-key and proxy variables do not configure this adapter. The HTTP
client disables ambient proxies and redirects. There are no tools or browsing.

SDK 2.54 also reads `OPENAI_CUSTOM_HEADERS`. The adapter clears that client's
instance-local custom-header mapping before publishing the client, including
arbitrary headers, not only Authorization. It never removes or changes environment
variables, even temporarily, and other SDK clients keep their own headers.
A final transport guard checks Authorization, OpenAI-Project and
OpenAI-Organization after SDK processing and HTTP request hooks. Exactly one
case-insensitively matched value is required for each: the configured Bearer key
and empty project/organization. Conflicting or identical duplicate security headers
are rejected with `invalid_headers` before sending. There are no operator-configurable
project/organization fields in this adapter.

Clearing the mapping uses an SDK-private attribute because `default_headers={}`
does not disable environment inheritance in the installed SDK. An incompatible
mapping or failed final check causes controlled local fallback, never a request
with unverifiable credentials. Keep the final-header regression tests when updating
the SDK; live endpoint/account compatibility remains unverified.

`LLM_MODEL` has no default. The operator must explicitly choose a model available
to their account that supports Responses and Structured Outputs. The compatibility
reference [`gpt-4.1-mini`](https://developers.openai.com/api/docs/models/gpt-4.1-mini)
documents both capabilities, but is marked deprecated in the consulted documentation;
it is not selected or recommended as a new default. No configured model was tested live.
The adapter uses only `model`, `input`, `text.format` with strict JSON Schema,
`max_output_tokens`, and `store=false`. It does not guess temperature, reasoning
or other model-specific controls. Unsupported configurations become a diagnosed
provider failure; they are not retried as a different model. See the official
[Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs)
and [Responses create reference](https://developers.openai.com/api/reference/python/resources/responses/methods/create).

`LLM_TIMEOUT_SECONDS=15` is the HTTP operation timeout (not an overall batch
deadline). `LLM_MAX_RETRIES=0` is the default. Up to three explicitly configured
retries are supported for network errors, timeouts, 408, 429 and 5xx; backoff is
0.25/0.5/1 seconds. SDK retries are always zero. 400/401/403, refusals, invalid
outputs and uncertainty are not retried. An HTTP attempt is a handoff of the completed
request to the underlying HTTP transport, including a handoff that raises a timeout
or connection error. It is not a successful response, confirmed server receipt, or
a billed request. SDK retries and the default HTTP transport's connect retries are zero.

Client creation, input serialization, request construction and final header validation
precede budget consumption. Immediately before transport handoff, the adapter reserves
one slot, then atomically commits it. `RequestBudget.used` counts committed handoffs;
`reserved` counts pending slots. The invariant `used + reserved <= max_requests` holds
under concurrent calls. An unused reservation is released exactly once; after handoff
it is never refunded, since a timed-out request may have been processed.
Exhausted budget emits `budget_exhausted`, never fabricated predictions.

Per-call `reservations` counts acquired slots and `released_reservations` counts unused
slots released before handoff. Without an explicit budget both are zero while
`requests` still counts actual handoffs. Invalid non-ASCII/control/whitespace keys
produce `invalid_configuration`; other local construction failures produce
`request_preparation_error`. These and final-header failures have zero handoffs,
consume no used budget, and are not classified as invalid provider responses or
automatically retried. The post-reservation cleanup path is covered by an injected
commit failure test. No exception message or key is exposed in these statuses.

`LLM_MAX_INPUT_CHARS=12000` counts the complete original text or the sum of email
sender + subject + body, before serialization. Exceeding it skips the entire LLM
call with `skipped_too_large`; complete rules analysis still runs. Nothing is
silently truncated, chunked or multiplied into paid calls.
`LLM_MAX_OUTPUT_TOKENS=512` bounds output, including any model reasoning tokens;
an insufficient limit may produce `incomplete`. Change it only deliberately.

## Classifier and local policy

`ClassifierInput` admits only source type (`prompt`, `document`, `email`) and
matching original fields. Labels, expected actions, scores, provider options
and purported trusted tasks are excluded. The original user task is unavailable;
task-dependent authorization therefore cannot be established by this classifier.

`indirect-injection-v1` is the fixed classifier prompt version. It asks for
analysis of untrusted JSON data, including sender and subject, English/Russian
instructions, verdict manipulation, disguised roles, quotations and negations.
It does not request chain-of-thought. Source role markers stay inside one user
message. JSON separation and the prompt are mitigations, not guarantees against
injection. No claims of language coverage or multilingual quality were measured.

The only output fields are `verdict`, `threat_types`, and `reason_codes`.
Verdict is `attack`, `no_attack_detected`, or `uncertain`. Threats are limited to
the existing injection categories. The strict model rejects extra fields,
unknown enum values, duplicate entries, inconsistent reasons, and unsupported
threat/reason combinations. JSON is parsed as a whole, rejecting duplicate keys;
no regex extracts JSON from surrounding prose. Refusal/incomplete envelopes
cannot become benign. Provider free text is never returned in findings.

Local `llm-findings-v1` policy assigns named `LLM_ATTACK_WEIGHT=0.80` to each
distinct validated attack category. This is an engineering policy weight, not
calibrated model confidence. Reason codes map to fixed explanations. A successful
`no_attack_detected` adds no findings. `uncertain` adds no findings and explicitly
falls back. Existing RiskEngine selects strongest evidence per category, so the
same category is not counted twice. Combining only additional nonnegative
findings cannot lower rules scores/decisions or lower FPR on the same corpus.

## Diagnostics and privacy

`ClassificationOutcome` belongs to one call, containing validated result or none,
status, fallback reason, configured model ID, HTTP attempt count, available token
usage and elapsed time. There is no mutable global last status. The configured
model ID identifies the requested model; alias resolution is not asserted.
Tokens are reported only when returned, including incomplete/invalid model
outputs with a usable envelope. Unknown usage remains null, not zero. HTTP error
attempts may have unknown billed usage; attempt counts are not a price quote.

Statuses: `success`, `disabled`, `external_not_allowed`, `missing_key`,
`missing_model`, `unsupported_provider`, `uncertain`, `skipped_too_large`,
`timeout`, `network_error`, `unauthorized`, `forbidden`, `rate_limited`,
`provider_error`, `refusal`, `incomplete`, `invalid_response`, `budget_exhausted`,
`invalid_configuration`, `invalid_headers`, `request_preparation_error`, `closed`.
Only `success` is a completed resolved LLM check. Other hybrid statuses
preserve complete rules findings. API headers and evaluation metadata expose
the effective mode/status; see [architecture.md](architecture.md).

The existing successful SecurityResult JSON is unchanged. On analysis HTTP 200,
these headers describe that call (validation/size/internal errors do not claim
a completed analysis):

| Header | Meaning |
| --- | --- |
| `X-Requested-Analysis-Mode` | `rules` or `hybrid` from trusted application settings |
| `X-Analysis-Mode` | `rules`, `hybrid`, or `fallback_rules` |
| `X-LLM-Status` | Closed status code listed above |
| `X-LLM-Fallback-Reason` | Failure/skip code; absent on successful analysis or default rules |
| `X-LLM-Model` | Configured model ID when available; no alias resolution claim |
| `X-LLM-Requests` | Underlying HTTP transport handoffs for this call, including retries/timeouts |
| `X-LLM-Reservations` | Acquired request-budget slots; zero without an explicit budget |
| `X-LLM-Released-Reservations` | Unused slots released before handoff |
| `X-LLM-Input-Tokens` / `X-LLM-Output-Tokens` | Returned usage; absent when unknown |

`X-Request-ID` remains the existing locally generated request identifier.
No raw response, provider exception text or submitted field is included in these headers.

SDK/HTTP logging namespaces (`openai`, `httpx`, `httpcore`) are explicitly silenced,
including debug logging, without changing environment variables. This logging
configuration is process-wide. Exceptions are classified without logging their
messages, tracebacks, headers, request/response bodies or provider request IDs.
Application diagnostics contain only local codes and bounded model metadata.

`store=false` disables response storage through that API option; it is **not** a
Zero Data Retention guarantee. External transmission remains a privacy boundary.
Only authorized public/synthetic inputs should be used for manual evaluation.
Fallback rules can miss attacks a model might detect. Callers must examine status
and enforce the returned action; this gateway does not stop a real agent itself.

## Offline and manual checks

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/test_llm_provider.py -q
```

All ordinary tests block external network and use mocks, even if a real key is
present. Settings and transport injection are trusted application/test seams,
not remotely exposed parameters. The existing Uvicorn smoke uses rules mode;
hybrid API tests inject a fake provider. For explicit bounded live/manual setup
and evaluation commands, see [evaluation.md](evaluation.md). Live quality,
provider availability and costs remain unverified until the operator authorizes
and executes those commands.
