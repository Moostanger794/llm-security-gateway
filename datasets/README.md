# Phase 5 evaluation data, version 1

These 64 synthetic, project-authored records are a small diagnostic corpus, not
a representative real-world benchmark. No sample is fetched or executed.
The JSONL bytes are versioned in Git; each report records SHA-256 for every file.

| File | Kinds | Safe | Attack |
| --- | --- | ---: | ---: |
| prompts/v1.jsonl | 16 prompt + 8 text | 10 | 14 |
| emails/v1.jsonl | 20 email | 10 | 10 |
| urls/v1.jsonl | 20 url | 12 | 8 |

`red_team/` is reserved for Phase 8 and is not loaded by the default benchmark.
`tests/fixtures/` has a separate regression purpose. These examples were authored
separately; neither datasets nor annotations may feed detector rules.

## Annotation policy

`safe` means benign intent in the authored scenario. `attack` means an attempted
instruction/credential abuse, or (for standalone URLs) an unsafe/suspicious input
that the author expects to require intervention. URL positives include malformed
and unsupported-scheme inputs: this is a policy-risk label, NOT proof of phishing,
malware or an executed attack. Read URL metrics separately from text/email metrics.
`attack_type` is one primary category, not an assertion that every other category
is absent. `expected_action` is an author-selected desired response, independent
of current weights; disagreements are reported without failing the benchmark.

Benign records intentionally include administrator teaching, negations, credential
rotation, ordinary urgency, login notices, international domains, lab IPs and SSO
redirects. URL feature presence alone is not sufficient to assign an attack label.
Some scenario context (e.g. legitimate lab ownership or SSO trust) is unavailable
to URLGuard; this intentionally illustrates limits of lexical analysis.

Borderline notes:

- p-005/006/008 are benign negation, teaching and credential management requests.
- p-014 requests concealed response control; desired BLOCK is stricter than mere review.
- p-022/023/024 test dotted words, semantic paraphrase and Russian instructions.
- e-004/005 are legitimate login guidance and a negated credential warning.
- e-006/007/008 and u-005/008/010/011/012 are authored legitimate lab/IDN/SSO cases.
- e-014 requests secrecy plus gift cards; confirmation is the desired intervention.
- e-020 is a synthetic unsolicited Russian credential request.
- u-013 contains only `demo:synthetic-only`, never real credentials.
- u-014 imitates a trusted domain as a subdomain of another destination.
- u-015/016/017/018 are unsuitable web destinations; not claims of exploitation.
- u-019/020 simulate suspicious account destinations; review is desired. Their
  appearance cannot establish maliciousness without additional context.

All hostnames use example domains and IP addresses use documentation ranges.
No personal identities, operational accounts, real passwords or tokens are used.
Secret-marker tests provide a limited sanity check, not a comprehensive DLP scan.

## Record format

UTF-8 JSONL, one JSON object per physical line; no blank lines or duplicate keys.
All seven fields are required and extra fields are forbidden:

```json
{"id":"demo-001","kind":"prompt","input":{"text":"Describe the water cycle."},"label":"safe","attack_type":null,"expected_action":"ALLOW"}
```

- `id`: unique across all loaded files; 1–80 ASCII letters/digits/underscore/hyphen,
  beginning with a letter or digit.
- `kind`: prompt, text, email or url.
- `input`: exactly `{text: string}` for prompt/text; exactly `{sender: string,
  subject: string, body: string}` for email; exactly `{url: string}` for URL.
  Prompt/email reuse the strict application schemas and length/visibility limits.
  URLs are strings up to 20,000 characters; empty/malformed URLs remain valid
  analysis inputs because URLGuard explicitly handles them.
- `label`: safe or attack; safe requires null attack_type, attack requires a
  single existing SecurityResult Threat category (not a list or arbitrary string).
- `expected_action`: ALLOW, SANITIZE, REQUIRE_CONFIRMATION or BLOCK.

Each file is limited to 4 MiB. Loading validates all files before analysis, even
when filtering by kind. Errors identify file and one-based record index, plus
valid ID when available; raw input and validation exception details are omitted.
Full methodology and results: [evaluation](../docs/evaluation.md).
