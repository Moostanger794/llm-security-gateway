# Local evaluation — Phase 5

This phase measures the existing heuristic gateway. It does not execute attacks
against an LLM, agent, browser or tool. There is no network access, model provider,
DNS, WHOIS, database, active red-team runner, UI or new HTTP endpoint.
Detection rules and Phase 1–4 application behavior are unchanged.

## Run

From the repository root, after the ordinary editable installation:

```powershell
.\.venv\Scripts\python.exe -m ai_security_gateway.evaluation.benchmark
.\.venv\Scripts\python.exe -m ai_security_gateway.evaluation.benchmark --help
.\.venv\Scripts\python.exe -m ai_security_gateway.evaluation.benchmark --kind email --json
New-Item -ItemType Directory -Force benchmark-reports
.\.venv\Scripts\python.exe -m ai_security_gateway.evaluation.benchmark --output benchmark-reports/run-001.json
```

Use the next unused filename for subsequent reports. No files are written by
default. `benchmark-reports/` is ignored by Git. `--output` exclusively creates a
new .json file and refuses overwriting; its parent directory must exist.
`--dataset path.jsonl` can be repeated; when supplied it replaces the three default
files. `--kind prompt|text|email|url` filters after validation. `--json` writes the
complete machine-readable report to stdout instead of the readable summary.
CLI input/output paths must resolve inside cwd; UNC and escaping symlink paths
are rejected. Paths are operator metadata and must not contain secrets. This is
a local CLI, not a sandbox for concurrent hostile filesystem manipulation.
Library callers control their own paths and must use local files.

Exit 0 means measurement succeeded, regardless of score. Invalid data, empty
selection, analysis failure or output failure returns nonzero without a traceback
or raw input. There are no score thresholds or CI security SLA gates.

## Architecture and leakage boundary

`evaluation/dataset.py` loads strict [versioned JSONL](../datasets/README.md).
`evaluation/benchmark.py` passes only kind + validated input to EvaluationAdapter:

```text
Dataset -> schema validation -> EvaluationAdapter -> prediction
                                  |                    |
                prompt/text/email: orchestrator        |
                url: URLGuard -> RiskEngine            |
                                                       v
                    ground truth -----------------> metrics -> report
```

Prompt/text/email use the existing SecurityOrchestrator, including validation,
normalization, detection, scoring and advisor. URL uses URLGuard.detect followed
by RiskEngine.score/decide; it has no advisor or HTTP overhead. No private
orchestrator methods are used. Ground truth is read for comparison only after
the prediction has returned. Labels, IDs and expected actions never reach a guard.
Production modules never import evaluation code or datasets. Tests enforce both
the import direction and annotation-independent arguments at the adapter boundary.

## Binary semantics and metrics

Actual positive: `label == attack`; actual negative: `label == safe`.
Predicted positive: `not SecurityResult.safe`; predicted negative: `safe`.
For URLs, positive means RiskEngine assessment is not SAFE. Thus SUSPICIOUS is
positive even though it asks for confirmation rather than blocking. Nonempty
threats alone do not define a positive (educational examples may remain SAFE).
No second threshold policy is introduced.

| | Predicted positive | Predicted negative |
| --- | --- | --- |
| Actual attack | TP | FN |
| Actual safe | FP | TN |

- Accuracy = (TP + TN) / N.
- Precision = TP / (TP + FP).
- Recall = TP / (TP + FN).
- F1 = 2TP / (2TP + FP + FN), equivalent to 2PR/(P+R) when defined.
- False Positive Rate = FP / (FP + TN): benign samples requiring intervention.
- False Negative Rate = FN / (FN + TP): attack samples assessed SAFE.
- Action accuracy = exact expected_action matches / N; report includes mismatch
  counts (list lengths) and IDs, independently of binary detection accuracy.

Zero denominator yields JSON `null` and summary `undefined`, never NaN/Infinity.
F1 uses the count formula: it is zero for missed attacks even if precision is
undefined, and null for a set containing only true negatives. Empty aggregation
is supported in metric tests; an empty benchmark selection is an error.

**Attack Success Rate Proxy** = attack-labeled samples with action ALLOW / all
attack-labeled samples. SANITIZE, REQUIRE_CONFIRMATION and BLOCK do not count as
automatic passage. The current policy makes this numerically equal to FNR, but
it is computed independently from actions. This is gateway policy passage,
not actual exploit success or a measure of downstream enforcement. No target
executes these requests. True active attack success measurement is future Phase 8.

## Latency and reproducibility

One `perf_counter()` interval surrounds each complete adapter prediction call.
Dataset reading, schema loading, model initialization, annotation comparison and
report construction are excluded. Service validation/normalization and result
creation are included. One call per sample; no warmup, repeats, randomness or
network. First-use costs remain in the measurements. Average is arithmetic mean;
P95 is nearest rank: sorted latencies at one-based index ceil(0.95 * N), without
interpolation. URL timings cover a shorter path than orchestrator timings.

Report metadata includes file paths, SHA-256 of exact file bytes, loaded record
counts, project/Python versions and configuration. Record order and classification
are deterministic for fixed data/code. JSON key order is stable, but latency varies
with machine, process state and load; serialized reports from separate runs are
not byte-identical. Preserve the repository revision/diff and environment when
comparing runs; app version alone does not distinguish uncommitted changes.

The report includes per-kind and per-primary-attack-type aggregations and
per-sample IDs, annotations, predicted positive/action, score and latency. No raw
prompt, email, URL, explanation or credentials are included. IDs/paths are metadata;
do not put sensitive content in them. Exception messages from analyzers are redacted.

## Measured v1 snapshot

Measured locally on Windows / Python 3.12.13, app 0.1.0, 2026-09-22 with:

```powershell
.\.venv\Scripts\python.exe -m ai_security_gateway.evaluation.benchmark --output benchmark-reports/phase5.json
```

64 project-authored samples: 32 safe, 32 attack. Dataset breakdown:

SHA-256 of the measured file bytes:

```text
prompts/v1.jsonl a8cce8f7c061e66fc83d8ce342c9877dd53793ccd6ccb27e43b3fd61490c67f6
emails/v1.jsonl  6bc027b67c91cfde79c366c21877ba9fd117ef416e1aac654fa0e4533c9b4164
urls/v1.jsonl    be1a354543ef4ba5284b01baae6c85d0ed5082d524fc2bfa16e0ff0e26e66383
```

| Kind | Total | Safe | Attack |
| --- | ---: | ---: | ---: |
| prompt | 16 | 8 | 8 |
| text | 8 | 2 | 6 |
| email | 20 | 10 | 10 |
| url | 20 | 12 | 8 |

TP=27, TN=19, FP=13, FN=5. Accuracy **0.718750**, precision **0.675000**,
recall **0.843750**, F1 **0.750000**, FPR **0.406250**, FNR **0.156250**,
ASR proxy **0.156250**. Action accuracy **0.703125** (19 mismatches).
Average latency **0.159348 ms**, P95 **0.355100 ms** for this run only.

Detection false negatives: p-022, p-023, p-024, e-020, u-019.
False positives: p-005, p-006, p-008, e-004, e-005, e-006, e-007, e-008,
u-005, u-008, u-010, u-011, u-012. p-014 is detected but requests confirmation
instead of the desired BLOCK. These outcomes are retained, not fitted away.

## Interpretation limits

This is a deliberately small diagnostic corpus with hand-selected difficult
cases, not a random population sample or a hidden independently collected test
set. The authors know the architecture; separate files and leakage tests do not
prove statistical independence. Labels and desired actions are subjective,
especially for URLs without ownership/context. URL positive labels also include
invalid/unsafe inputs, so pooled figures mix policy risk and attack intent.
Per-category sets are too small for strong conclusions. No confidence bounds,
production detection rates, adversarial robustness guarantees or calibrated risk
probabilities are claimed. HTTP overhead, throughput and concurrent load are not
measured. Missing multilingual/paraphrase coverage and benign lexical alerts are
results to investigate separately, not reasons to tune rules to this corpus.

## Implementation verification

Before changes: 345 regression tests passed. After Phase 5: 403 tests passed
(58 new evaluation tests), with the same two dependency deprecation warnings.
New tests cover formulas and zero denominators, ASR action distinctions, timing,
strict data validation, duplicate IDs/keys, Unicode JSONL delimiters, routing,
annotation separation, filtering, serialization, CLI failures, offline execution,
privacy and separation from fixtures/production imports. They check pipeline
correctness rather than requiring a target benchmark score.

`ruff check .`, `ruff format --check .` and `pip check` passed. The existing real
Uvicorn smoke script passed health plus safe/malicious prompt, email and text
requests and shut down gracefully with exit 0. No detector rules were changed.
