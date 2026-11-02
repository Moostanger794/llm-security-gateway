# Phase 6: indirect-injection comparison

This experiment asks how a classifier and conservative hybrid change missed
injections, false alarms, latency and API usage. The mixed legacy v1 benchmark
remains separate and unchanged. The new corpus contains email/document injection
attempts and benign controls; [provenance](data_provenance.md) describes its sources,
labels, groups and limitations. Neither experiment executes an attacked agent.

## Offline baseline

From the repository root, with the editable package installed:

```powershell
.\.venv\Scripts\python.exe -m ai_security_gateway.evaluation.benchmark
.\.venv\Scripts\python.exe -m ai_security_gateway.evaluation.comparison
.\.venv\Scripts\python.exe -m ai_security_gateway.evaluation.comparison --split holdout
.\.venv\Scripts\python.exe -m ai_security_gateway.evaluation.comparison --split all --json
```

The default is `--mode rules --split dev`, with no Settings/provider construction
and no network even if the shell contains a real key and enabled LLM flags.
Both split files are validated before selection. `--dataset` is repeatable and
accepts only local v2 JSONL. Input/output paths must remain inside the current
working directory. `--output benchmark-reports/phase6-new-name.json` exclusively
creates a new report; create the ignored directory first. Existing reports are
never overwritten. Its exclusive output handle is opened before any provider
request, so a missing/unwritable parent cannot consume the API budget first.
A later initialization/analysis failure may leave an empty reserved report.
Invalid data/configuration returns exit 1. An incomplete
LLM experiment returns exit 2 while still producing its diagnostic report.

## Manual API comparison, at most ten attempts

No live API experiment was run during implementation. Follow
[LLM setup](llm_integration.md) to supply an API key in the local environment or
ignored `.env`, set an explicitly chosen supported `LLM_MODEL`, and consent to
external transfer with `ENABLE_LLM_ANALYSIS=true` and `ALLOW_EXTERNAL_LLM=true`.
After reviewing the public/synthetic corpus and accepting the API cost, run:

```powershell
.\.venv\Scripts\python.exe -m ai_security_gateway.evaluation.comparison --mode compare --split dev --live --max-requests 10 --json
```

The CLI requires both `--live` and an explicit positive `--max-requests` for
`compare`, `llm-only` or `hybrid`. Provider configuration independently requires
both opt-in flags, a model and key. The budget counts actual attempts including
custom retries; hidden SDK retries are disabled. Ten attempts cannot cover a
larger split, so an incomplete result is expected. No prediction is invented for
unresolved model responses. A different explicit budget is a new operator
decision; there is no automatic budget increase.

Library calls to `run_comparison` enforce `live=True` and a positive RequestBudget
for a network-capable OpenAI adapter too. Report limits come from the adapter's
actual settings; contradictory supplied metadata is rejected before requests.
Injected fakes and explicit offline MockTransport remain `offline_test` even if
a caller sets `live=True`; that flag alone cannot label mocks as live quality.

`compare` runs A=rules, B=llm-only and C=hybrid against exactly the same sample
IDs, labels and split. One model response per input is reused transiently for B
and C; it is not a second request or a cache hit. Top-level requests and token
usage are counted once. There is no persistent cache of raw inputs or responses.
The provider can attempt retries for the same classification, within the budget.

## Policy and coverage

Rules produce the unchanged findings. B uses only validated classifier findings
with the same RiskEngine. C unions rules and classifier findings before that
engine's maximum-per-category aggregation. A benign model verdict cannot reduce
a rule score, BLOCK or REQUIRE_CONFIRMATION. Consequently hybrid FPR cannot
decrease on the same corpus under this policy. B is the separate classifier
false-alarm experiment. No model can change policy thresholds or grant permission.

Timeouts, provider errors, refusal, malformed/incomplete output, uncertainty,
missing configuration, oversized inputs and budget exhaustion remain explicit
statuses. B records `prediction=null`, never benign, for each unresolved sample.
Its complete-dataset `metrics` are null if any prediction is unresolved;
`resolved_subset_metrics`, resolved IDs, unresolved counts by label/reason and
coverage are shown separately. A smaller resolved subset is not comparable to
the full A population as an equal experiment.

C keeps full rules predictions on every fallback and reports operational metrics
on the full population. `prediction_complete` may therefore be true while
`experiment_complete` is false. `fallback_count`, rate, statuses and LLM coverage
make this distinction visible. The top-level `complete` flag requires all
requested experiments to be complete. Reaching a request budget never produces
a claim of full LLM coverage.

## Metric definitions

Actual positive is `label=attack`, meaning an attempted instruction injection,
regardless of any upstream attack success. Predicted positive is `not safe`, so
REQUIRE_CONFIRMATION counts as a positive, as does BLOCK. Confusion counts and
Accuracy/Precision/Recall/F1/FPR/FNR reuse the legacy metric implementation.
Zero denominators are JSON null. Additional rates are:

- **ASR proxy**: attack examples with final ALLOW divided by attack examples.
- **Benign ALLOW rate**: benign examples with final ALLOW divided by benign examples.
- **Review rate**: REQUIRE_CONFIRMATION decisions divided by resolved examples.
- **Prediction coverage**: resolved examples divided by selected examples.
- **LLM coverage**: successfully resolved LLM outcomes divided by selected examples.

For incomplete B, these rates live only under the explicitly identified resolved
subset. All selected IDs and unresolved examples remain in the report, so errors
are not silently dropped from the dataset. Operational latency includes both
resolved and unresolved attempts; quality latency covers resolved predictions.

An always-BLOCK classifier obtains ASR=0 but benign ALLOW=0 and FPR=1 whenever
both classes are present. A classifier that sends everything for review has the
same usability failure and review rate=1. The tests assert these relationships;
zero ASR alone is not evidence of a useful system. With this policy ALLOW is
equivalent to SAFE, so ASR proxy equals FNR. They are not independent evidence.
Actual end-to-end attack success requires a target agent and belongs to Phase 8.

## Timing, cost and reproducibility

P50/P95 use nearest-rank percentiles and `perf_counter`. Per-mode elapsed time is
the sum of its measured stages, including input preparation, rule analysis where
applicable, actual classifier wait (including retries), local finding conversion
and final policy/result generation. The same observed wait contributes once to
B and once to C's respective hypothetical calls; it does not mean two paid calls.
C includes the completed baseline rule-policy stage, making its timing slightly
conservative relative to an implementation that only scores the union once.
Dataset loading, Git inspection, report generation and other mode scoring are
outside per-mode timing. One pass, no warmup or repeated sampling is used.

The top-level uncached classifier latency aggregates only calls with at least one
underlying HTTP transport handoff. Local configuration, request-build and header
failures have zero handoffs and are excluded along with missing-key/skipped/
budget-exhausted calls with zero requests. They remain in each mode's operational
wall-clock latency, fallback/unresolved counts and selected sample population.
The uncached latency is the whole classification call for calls that reached the
transport, including preparation/backoff, not pure network time.

`provider_requests` counts transport handoffs once per shared LLM outcome, including
retries, timeouts and connection errors after handoff. It is not a count of success
or billing. `reservations` and `released_reservations` are also counted once at the
top level and recorded per classification. Local failures do not consume used
budget; uncommitted slots are released safely. Timeout after handoff consumes its
slot. B/C response reuse does not double any of these counts. SDK/default transport
retries remain disabled; only the bounded explicit loop retries retryable failures.
Input/output tokens are summed only when returned by the
provider, with usage-availability counts. Missing token information stays null;
it is never estimated or presented as a monetary charge.

Reports preserve exact dataset byte hashes, corpus revision, Git HEAD and dirty
flag, project/Python version, selected IDs/split, mode, observed model IDs,
classifier prompt version, local policy version, limits and coverage. A dirty
flag does not identify the exact diff: preserve the reviewed code separately for
reproduction. Reports omit inputs, explanations, raw provider output and secrets.
Paths/IDs are operator metadata and must themselves contain no secrets.

## What was actually checked

Only rules baselines and offline protocol/policy tests have run. The injected
test classifiers return constant responses or scripted transport failures without
receiving labels; these test plumbing, coverage, metrics and conservative policy,
not classifier quality. Such library runs are marked `execution=offline_test`
and `quality_claim=Protocol/policy test only; not real LLM quality`.

The 2026-11-02 rules run over the current 32-example corpus gave TP=4, TN=15,
FP=1, FN=12: Precision=0.8, Recall=0.25, F1=0.380952, FPR=0.0625,
FNR/ASR proxy=0.75, benign ALLOW=0.9375, review=0.03125. This deliberately small
authored/adapted corpus is not a random population or a blind independent test.
Its poor rules recall is retained without fitting rules or classifier prompts to
holdout. Latency varies by run; use report values for the actual execution.
Real model quality, real token usage, latency and successful live API access
remain unmeasured. No improvement from the LLM is claimed.
