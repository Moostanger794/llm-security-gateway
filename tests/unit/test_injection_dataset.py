import copy
import hashlib
import json
import socket
from pathlib import Path

import pytest

from ai_security_gateway.evaluation.dataset import EvaluationError, load_dataset
from ai_security_gateway.evaluation.injection_dataset import (
    CORPUS_REVISION,
    DEFAULT_INJECTION_DATASETS,
    content_hash,
    load_injection_dataset,
)


def sample(**changes):
    value = {
        "id": "sample-1",
        "kind": "text",
        "input": {"text": "A public meeting starts at noon."},
        "label": "safe",
        "attack_type": None,
        "expected_action": "ALLOW",
        "split": "dev",
        "group": "meeting",
        "provenance": {
            "origin": "synthetic",
            "upstream_url": None,
            "revision": CORPUS_REVISION,
            "source_id": "meeting",
            "license": "Project-authored",
            "notice": "Synthetic diagnostic example.",
            "original_split": "synthetic",
            "family": "meeting",
            "adaptation": "Independently authored example.",
            "source_sha256": None,
            "content_sha256": "",
        },
    }
    value.update(changes)
    value["provenance"]["content_sha256"] = content_hash(value["kind"], value["input"])
    return value


def write(tmp_path, rows):
    path = tmp_path / "corpus.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return path


def test_real_corpus_balanced_and_declared_provenance(monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError("Loader attempted network access")

    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    corpus = load_injection_dataset()
    assert len(corpus.records) == 32
    assert corpus.revision == CORPUS_REVISION
    for split, count, attacks in (("dev", 17, 7), ("holdout", 15, 9)):
        selected = [r for r in corpus.records if r.split == split]
        assert len(selected) == count
        assert sum(r.label == "attack" for r in selected) == attacks
    assert sum(r.provenance.origin == "adapted" for r in corpus.records) == 8
    assert sum(r.provenance.origin == "synthetic" for r in corpus.records) == 24
    assert {r.kind for r in corpus.records} == {"email", "text"}
    for path, source in zip(DEFAULT_INJECTION_DATASETS, corpus.sources, strict=True):
        assert source["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_content_hash_is_canonical_and_excludes_ground_truth():
    first = content_hash("email", {"sender": "a", "subject": "b", "body": "c"})
    assert first == content_hash("email", {"body": "c", "sender": "a", "subject": "b"})
    assert first != content_hash("email", {"body": "changed", "sender": "a", "subject": "b"})


@pytest.mark.parametrize(
    "changes",
    [
        {"id": "invalid\nidentifier"},
        {"split": "test"},
        {"group": "invalid group"},
        {"kind": "prompt"},
        {"kind": "url", "input": {"url": "https://example.org"}},
        {"input": {"text": "text", "provider": "private-value"}},
        {"system_prompt": "private-value"},
        {"expected_action": "BLOCK"},
        {"label": "attack", "attack_type": "phishing", "expected_action": "BLOCK"},
        {"label": "attack", "attack_type": "indirect_prompt_injection"},
        {"label": "attack", "attack_type": None},
    ],
)
def test_invalid_schema_is_redacted(tmp_path, changes):
    with pytest.raises(EvaluationError) as error:
        load_injection_dataset([write(tmp_path, [sample(**changes)])])
    assert "private-value" not in str(error.value)
    assert "record 1" in str(error.value)


@pytest.mark.parametrize(
    "changes",
    [
        {"origin": "unknown"},
        {"upstream_url": "https://example.org"},
        {"source_sha256": "a" * 64},
        {"original_split": "train"},
        {"content_sha256": "a" * 64},
        {"license": ""},
        {"notice": ""},
        {"revision": ""},
        {"source_id": ""},
        {"family": "bad family"},
        {"origin": "adapted"},
        {"provider_config": "private-value"},
    ],
)
def test_bad_provenance_is_rejected(tmp_path, changes):
    row = sample()
    row["provenance"].update(changes)
    with pytest.raises(EvaluationError) as error:
        load_injection_dataset([write(tmp_path, [row])])
    assert "private-value" not in str(error.value)


@pytest.mark.parametrize("field", list(sample()["provenance"]))
def test_provenance_is_required(tmp_path, field):
    row = sample()
    del row["provenance"][field]
    with pytest.raises(EvaluationError):
        load_injection_dataset([write(tmp_path, [row])])


@pytest.mark.parametrize(
    "url,revision",
    [
        ("http://example.org/data", "a" * 40),
        ("https://user:password@example.org/data", "a" * 40),
        ("https://example.org/data", "main"),
        ("file:///tmp/data", "a" * 40),
    ],
)
def test_upstream_provenance_requires_immutable_revision_and_https(tmp_path, url, revision):
    row = sample()
    row["provenance"].update(
        origin="adapted",
        upstream_url=url,
        revision=revision,
        source_sha256="a" * 64,
        original_split="train",
    )
    with pytest.raises(EvaluationError):
        load_injection_dataset([write(tmp_path, [row])])


def test_duplicate_ids_and_inputs_across_files(tmp_path):
    path = write(tmp_path, [sample()])
    with pytest.raises(EvaluationError, match="duplicate ID"):
        load_injection_dataset([path, path])
    with pytest.raises(EvaluationError, match="duplicate input"):
        load_injection_dataset([write(tmp_path, [sample(), sample(id="sample-2")])])


def test_group_and_family_cannot_cross_splits(tmp_path):
    first = sample()
    second = sample(id="sample-2", input={"text": "Different text"}, split="holdout")
    with pytest.raises(EvaluationError, match="group crosses splits"):
        load_injection_dataset([write(tmp_path, [first, second])])
    second["group"] = "different-group"
    with pytest.raises(EvaluationError, match="family crosses splits"):
        load_injection_dataset([write(tmp_path, [first, second])])


def test_source_variants_must_share_group_even_with_new_family(tmp_path):
    first = sample()
    second = sample(id="sample-2", input={"text": "Different text"}, group="other")
    second["provenance"]["family"] = "different"
    with pytest.raises(EvaluationError, match="source variants"):
        load_injection_dataset([write(tmp_path, [first, second])])


def test_tampered_input_hash_and_schema_separation(tmp_path):
    row = sample()
    row["input"]["text"] = "tampered-private-value"
    with pytest.raises(EvaluationError) as error:
        load_injection_dataset([write(tmp_path, [row])])
    assert "tampered-private-value" not in str(error.value)
    with pytest.raises(EvaluationError):
        load_dataset([write(tmp_path, [sample()])])
    legacy = copy.deepcopy(sample())
    for key in ("split", "group", "provenance"):
        del legacy[key]
    assert len(load_dataset([write(tmp_path, [legacy])]).records) == 1


@pytest.mark.parametrize("raw", ["", "[]", "null", '{"id":1,"id":2}', "private-invalid-json"])
def test_json_and_empty_files(tmp_path, raw):
    path = tmp_path / "corpus.jsonl"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(EvaluationError) as error:
        load_injection_dataset([path])
    assert "private-invalid-json" not in str(error.value)


def test_file_limits_and_missing_files(tmp_path):
    path = tmp_path / "missing.jsonl"
    with pytest.raises(EvaluationError, match="cannot read"):
        load_injection_dataset([path])
    path.write_bytes(b"\xff")
    with pytest.raises(EvaluationError, match="UTF-8"):
        load_injection_dataset([path])
    path.write_bytes(b"x" * (4 * 1024 * 1024 + 1))
    with pytest.raises(EvaluationError, match="4 MiB"):
        load_injection_dataset([path])
    with pytest.raises(EvaluationError, match="No injection"):
        load_injection_dataset([])


def test_notice_and_manifest_agree_with_selected_rows():
    root = Path("datasets/indirect_injection")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert "Microsoft Corporation" in (root / "BIPIA-LICENSE.txt").read_text(encoding="utf-8")
    adapted = [r for r in load_injection_dataset().records if r.provenance.origin == "adapted"]
    assert {r.provenance.source_id for r in adapted} == set(
        manifest["upstream"]["selected_json_pointers"]
    )
    assert {r.provenance.revision for r in adapted} == {manifest["upstream"]["revision"]}
    assert manifest["counts"]["adapted"] == len(adapted)
    assert manifest["corpus_revision"] == CORPUS_REVISION
    assert {r.group for r in adapted} == {"bipia-shared-response-wrapper"}
    assert {r.split for r in adapted} == {"holdout"}


def test_semantically_related_variants_stay_together():
    rows = load_injection_dataset().records
    related = (
        {"educational-override", "educational-extraction"},
        {"synthetic-extraction", "synthetic-hidden-prompt"},
        {"synthetic-sender-role", "synthetic-approval-spoof"},
        {"synthetic-hierarchy", "synthetic-jailbreak"},
    )
    for families in related:
        variants = [r for r in rows if r.provenance.family in families]
        assert {r.provenance.family for r in variants} == families
        assert len({r.group for r in variants}) == 1
        assert {r.split for r in variants} == {"dev"}
