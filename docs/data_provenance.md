# Phase 6 data provenance

Prepared on 2026-11-02. The new corpus is deliberately small: **32 examples**,
16 safe / 16 attack; 17 dev (10 safe / 7 attack) and 15 holdout (6 safe / 9 attack).
There are **24 synthetic
examples and 8 adaptations of four public BIPIA payloads**, not 8 original
EmailQA records. English email wrappers and Russian document paraphrases share
the source's group and split. No real corporate email or production secret is used.

## Verified source and data rights

The source is Microsoft's [BIPIA repository](https://github.com/microsoft/BIPIA),
pinned to [a004b69ec0dd446e0afd461d98cb5e96e120a5d0](https://github.com/microsoft/BIPIA/commit/a004b69ec0dd446e0afd461d98cb5e96e120a5d0).
The [dataset README](https://github.com/microsoft/BIPIA/blob/a004b69ec0dd446e0afd461d98cb5e96e120a5d0/benchmark/README.md)
identifies `benchmark/text_attack_train.json` as the text-task train attack data.
The [license](https://github.com/microsoft/BIPIA/blob/a004b69ec0dd446e0afd461d98cb5e96e120a5d0/LICENSE)
explicitly covers all repository parts except named dataset components with
separate rights. The selected attack data is not among those exceptions, so the
MIT terms apply to this component. This review did not assume the code license
automatically covered every benchmark context dataset. The full original notice
is retained in [BIPIA-LICENSE.txt](../datasets/indirect_injection/BIPIA-LICENSE.txt).

The four selected source IDs are JSON pointers into
[the pinned attack file](https://github.com/microsoft/BIPIA/blob/a004b69ec0dd446e0afd461d98cb5e96e120a5d0/benchmark/text_attack_train.json):

| Source pointer | Group / split | Adaptation |
| --- | --- | --- |
| `/Alphanumeric Substitution/0` | bipia-shared-response-wrapper / holdout | Change final-answer letters to numbers |
| `/Instruction/0` | bipia-shared-response-wrapper / holdout | Insert irrelevant cooking advice |
| `/Space Removal & Grouping/0` | bipia-shared-response-wrapper / holdout | Delete spaces from final response |
| `/Misspelling Intentionally/0` | bipia-shared-response-wrapper / holdout | Introduce response typos |

For each pointer, one English paraphrase in a synthetic email and one Russian
paraphrase in a synthetic document make the AI addressee and external context
explicit. Original payloads alone can resemble ordinary user requests; the label
describes their instructional redirection **inside the constructed external
source**, not an assertion that the isolated phrase is intrinsically malicious.
Original upstream split is `train` for all four; local holdout does not relabel
them as upstream test data. No upstream success rates or model answers were used.

The checked Git blob IDs are `190918308f4ef25d5f43d7c1b118bf3fe5dc61d2`
(attack JSON), `45da10d4120107f7ad08be64044ac2c1e9255daa` (LICENSE), and
`29aaa07ccadadd055c029196eeeee8356f11afc8` (benchmark README). Source scalar
SHA-256 and canonical input SHA-256 are stored on every adapted row.
See [manifest](../datasets/indirect_injection/manifest.json) for retrieval details.

## Scope, omissions and limitations

No BIPIA EmailQA invoice contexts, NewsQA, XSum, Stack Exchange or WikiTableQuestions
content is vendored. Their third-party licenses are outside this selection.
LLMail-Inject and AgentDojo were not imported or run: this phase requires one
verified source, and the small BIPIA selection satisfies that preparation scope.
There is no claim of measuring those benchmarks or reproducing their published
results. No data-access or licensing blocker remains for the selected component.

Synthetic cases cover sender/subject/body manipulation, hidden instruction
extraction, verdict tampering, role claims, and legitimate human requests,
negations, security teaching and ordinary procedural documents. They are authored
for diagnostic breadth, not sampled from an operational distribution.
The holdout was seen during construction and is not independently blinded.
Neither its outputs nor its labels were used to change rules or classifier policy.
Revision **indirect-injection-v2.2** records a subsequent semantic grouping audit
of the initial v2.1 draft: the four upstream families used the same synthetic
wrappers and therefore belonged in one split; educational attack quotations,
secret/prompt extraction, asserted authority and control-bypass variants also
needed consolidated groups. All BIPIA wrappers now stay in holdout; the related
synthetic pairs/quotation variants stay in dev. The correction preserves every
ID, input, label, expected action and source/content hash. It is a declared split
revision, not a claim that the initial split was frozen or blinded. ID prefixes
remain immutable and can differ from current split metadata. Synthetic provenance
revision retains v2.1 as the text-authoring revision; reports use corpus v2.2.
No attempt was made to retain equal split sizes or improve detection metrics.
The loader validates declared grouping but cannot prove unrelated semantic families.
Future translated or template-related variants must retain the same group/split.

Dataset preparation is separate from runtime. Normal tests/benchmarks perform no
downloads. `scripts/verify_injection_sources.py --download` is an optional explicit
one-file public-source verification without model calls; it checks pinned hashes,
does not follow URLs from records, and never rewrites corpus files.
