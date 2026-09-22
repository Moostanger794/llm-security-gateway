# Threat model — Phases 1–5

## Assets

Service availability, configuration, diagnostic logs, and HTTP response integrity.
Prompt/email confidentiality and assessment integrity are also assets. Submitted text
is processed transiently; no user documents, LLM secrets or tool credentials
are persisted by this phase.

## Trust boundaries and attack surfaces

HTTP clients are untrusted; environment configuration is operator-controlled.
Exposed surfaces are `/health`, `/analyze/prompt`, `/analyze/email`, `/analyze/text`, OpenAPI, and interactive API
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

EmailGuard detects local indicators of phishing, credential requests, social
engineering, urgency and suspicious sender syntax/claims. It reuses PromptGuard
for indirect injection inside emails. Weak evidence combines through the shared
RiskEngine; urgent language or a normal HTTPS link alone does not imply phishing.
URLGuard detects potentially unsafe schemes, credentials in authority, unusual
hosts/IP/IDN, deep subdomains, long URLs and external redirect-like parameters.
These are suspicious lexical features, not evidence of malware or reputation.
No URL is fetched, resolved or followed, avoiding detector-induced SSRF. Sender
identity, SPF, DKIM and DMARC are not verified. Headers beyond sender, MIME and
attachments are outside this API's scope.

Email fields are bounded before normalization: sender 320, subject 998, body
100,000 characters. All HTTP bodies have a 1280-KiB limit; prompt/text keep their 128-KiB
limit. Streamed bodies are counted before parsing even if Content-Length is absent
or inaccurate. All extracted URLs are inspected; repetitions are deduplicated.
Application logs and responses never echo email fields, URL values, embedded
credentials, query parameters, validation input or exception messages. Tests cover
successful analysis and 422/413/500 failures. Disable hosting access logs separately.

Tool abuse and actual Privilege escalation enforcement remain future work.
Role-manipulation text detection is not permission enforcement.

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

Email/URL false positives include legitimate IDNs, internal IP addresses, deep
corporate domains, SSO redirect parameters, administrative account notices,
security training and negated credential commands. Sender mismatch heuristics only
compare explicit mailbox domains, not organizational ownership. Email prose rules
are predominantly English and cannot reliably distinguish quoted/social contexts.
False negatives include paraphrased or multilingual phishing, compromised normal
domains, URL shorteners, bare domains, relative links, heavily encoded/obfuscated
HTML/URLs, attachment-based attacks, image-only phishing and homograph variants.
Simple HTML stripping is not equivalent to browser rendering. No DNS, WHOIS,
reputation service, external API or malware inspection is used. A LOW/ALLOW result
is not proof of sender authenticity or URL safety. Fixtures check regressions;
they do not establish real-world detection rates.

## Phase 4 service boundary review

All HTTP analysis passes through SecurityOrchestrator. Direct callers receive the
same type, visibility and length validation before any injected detector executes.
Control-only content is rejected in addition to whitespace/formatting-only input.
No optional source claim is accepted; text uses PromptGuard only. Email's existing
untrusted context stays in EmailGuard. No network, database, model provider or
agent execution is introduced.

Duplicate findings cannot multiply category weights. Canonical sorting keeps
threats and advice stable under reordered evidence. RiskEngine remains the only
scoring policy. SecurityAdvisor accepts trusted detector metadata, not user text.
Dependency injection is a code trust boundary, not an untrusted plugin interface:
a custom detector that emits raw input in findings violates the privacy contract.
Unexpected HTTP failures are redacted; Python callers must avoid logging arbitrary
exceptions from their own custom dependencies.

Tests exercise routing, fake guards, aggregation permutations, direct validation,
Unicode/control-only input, byte limits with absent/false Content-Length, and
redaction on success and 422/413/500. Application logs exclude submitted text,
URLs and query strings. Uvicorn access logs must still be disabled separately.
Generic text does not assess URL reputation or email phishing. Timing varies
between requests; all decision fields are deterministic for fixed trusted detectors.
The Phase 4 tests are regression checks, not a benchmark or a detection guarantee.

## Phase 5 evaluation boundary

Additional assets are annotation integrity, dataset provenance and report privacy.
The CLI loads local untrusted JSONL with strict field/type/size validation and
duplicate-ID/key rejection. It never executes examples or fetches URLs. Ground
truth does not cross the input-only analysis boundary; production detectors do
not import datasets/evaluation. Rules remain unchanged. Tests block socket/DNS
access during a real benchmark and check label separation and output redaction.

Reports omit input, sender/body, complete URLs and analyzer exception messages.
Only sample IDs, category, expected/predicted decisions, scores, timing and metadata
are emitted. IDs/paths are operator-controlled metadata and must not contain
secrets. CLI paths resolve inside cwd (including symlink checks), UNC is rejected,
and output uses exclusive creation. This does not defend against a concurrent
hostile local filesystem actor; library path handling is the caller's responsibility.
Files are bounded to 4 MiB each; CLI operators control total files and run size.

The corpus uses example domains, documentation IP ranges and explicit synthetic
credential placeholders. Secret-marker checks are not proof that arbitrary user
datasets contain no secrets. Versioned hashes identify bytes, not label correctness.
Small hand-authored data, subjective labels and unavailable URL trust context
limit interpretation. Observed v1 FPR=40.625% and FNR=15.625% are diagnostic only,
not population estimates. ASR proxy measures ALLOW decisions, not actual exploit
success or enforcement. Details: [evaluation.md](evaluation.md). No Phase 6+
component or execution capability is introduced.
