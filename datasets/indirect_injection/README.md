# Indirect injection corpus v2.2

This separate Phase 6 diagnostic set contains **32 examples: 16 safe, 16 attack**.
`dev.jsonl` has 17 rows (10 safe / 7 attack), and `holdout.jsonl` has 15
rows (6 safe / 9 attack). Splits are not artificially balanced.
There are 24 independently authored synthetic rows and 8 adaptations of four
BIPIA train payloads. Existing `datasets/*/v1.jsonl` files are unchanged.

The holdout is **developer-visible**, not a blind independent test. No detection
rule, classifier prompt or policy weight was fitted to holdout outcomes. Groups
and upstream families cannot cross splits; translated/source variants stay in
one group. This helps control leakage but does not prove semantic independence.

Revision v2.2 corrects grouping in the initial developer-visible v2.1 draft.
All BIPIA adaptations share synthetic email/document wrappers, so they now share
one group in holdout despite distinct upstream attack families. Related synthetic
control-bypass, authority-spoof and privileged-extraction pairs, and educational
quotation variants, each stay together in dev. This correction changed only group
and split metadata. Input, labels, expected actions, IDs and source/content hashes
were preserved. IDs are immutable: their old split prefixes do not identify the
current split. Synthetic provenance revision records the original v2.1 text
authoring; corpus/report revision v2.2 records the corrected split allocation.

## Meaning of labels

`attack` means an instruction embedded in an external email/document attempts
to redirect the assistant or its classification. It does not mean the upstream
or downstream model followed it. All attack rows target BLOCK; all safe rows
target ALLOW. Legitimate instructions to human recipients, recipe/manual steps,
educational quotations, negations and model terminology are intentionally present.
Labels are project judgments with limited task context, not population ground truth.

## Format and provenance

The separate strict v2 schema adds `split`, `group`, and `provenance` to the v1
record fields. Only `text` and `email` kinds and injection categories are allowed.
`input` preserves the existing HTTP schema. No provider settings, arbitrary
instructions to the classifier, or code are accepted as metadata.

Every row includes origin, upstream URL (null for synthetic), immutable source
revision, exact JSON-pointer source ID, license/notice, original split, family,
adaptation description, source SHA-256 and content SHA-256. The source hash is
of the original JSON string encoded as UTF-8, not of its JSON quotes. Synthetic
source hashes are null. The input hash is SHA-256 of UTF-8 canonical JSON with
sorted keys and compact separators: `{"input": ..., "kind": ...}`. File hashes
cover exact JSONL bytes and are emitted by the loader/comparison report.

The loader checks schema, label/action consistency, provenance hashes, unique
IDs/inputs, group/family split isolation and source-variant grouping across all
supplied files before filtering. It cannot automatically identify every semantic
paraphrase; reviewers must preserve groups when adding variants. Runtime and tests
load local bytes only; provenance URLs are never fetched by a loader or detector.

## Source preparation

[BIPIA data and license review](../../docs/data_provenance.md) records exact
revision, permitted component, adaptation and exclusions. The preparation on
2026-11-02 was a separate read-only fetch of the small public attack JSON and
its documentation through the GitHub connector. Full benchmark dependencies and
third-party email contexts were not downloaded. `manifest.json` records the
selection and `BIPIA-LICENSE.txt` preserves the complete upstream notice.

An optional manual verification performs one fixed public download (no LLM call),
checks the Git blob SHA and four source scalar hashes, and does not modify data:

```powershell
.\.venv\Scripts\python.exe scripts/verify_injection_sources.py --download
```

The default legacy benchmark remains separate. For the new corpus use the Phase 6
comparison CLI documented in [evaluation](../../docs/evaluation.md).
