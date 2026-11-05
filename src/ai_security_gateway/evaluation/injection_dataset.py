"""Local, versioned indirect-injection corpus; provenance never becomes instructions."""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from ai_security_gateway.evaluation.dataset import (
    IDENTIFIER,
    MAX_FILE_BYTES,
    EvaluationError,
    Record,
    _object,
)

CORPUS_REVISION = "indirect-injection-v2.2"
DEFAULT_INJECTION_DATASETS = tuple(
    Path(f"datasets/indirect_injection/{split}.jsonl") for split in ("dev", "holdout")
)
INJECTION_THREATS = {
    "prompt_injection",
    "indirect_prompt_injection",
    "instruction_override",
    "role_manipulation",
    "system_prompt_extraction",
    "secret_extraction",
    "jailbreak",
}


def content_hash(kind: str, data: dict[str, str]) -> str:
    """Hash canonical input bytes, excluding annotations and provenance."""
    encoded = json.dumps(
        {"kind": kind, "input": data}, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class Provenance(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    origin: Literal["synthetic", "adapted", "imported"]
    upstream_url: str | None = Field(max_length=2048)
    revision: str = Field(min_length=1, max_length=100)
    source_id: str = Field(min_length=1, max_length=200)
    license: str = Field(min_length=1, max_length=100)
    notice: str = Field(min_length=1, max_length=300)
    original_split: str = Field(min_length=1, max_length=30)
    family: str = Field(pattern=IDENTIFIER)
    adaptation: str = Field(min_length=1, max_length=500)
    source_sha256: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if self.origin == "synthetic":
            if self.upstream_url is not None or self.source_sha256 is not None:
                raise ValueError("synthetic provenance cannot claim an upstream source")
            if self.original_split != "synthetic":
                raise ValueError("synthetic examples require a synthetic original split")
        else:
            if not self.upstream_url or not self.source_sha256:
                raise ValueError("upstream examples require URL and source hash")
            parsed = urlsplit(self.upstream_url)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
            ):
                raise ValueError("upstream URL must be credential-free HTTPS")
            if len(self.revision) != 40 or any(c not in "0123456789abcdef" for c in self.revision):
                raise ValueError("upstream revision must be an immutable git commit")
        return self


class InjectionRecord(Record):
    kind: Literal["text", "email"]
    split: Literal["dev", "holdout"]
    group: str = Field(pattern=IDENTIFIER)
    provenance: Provenance

    @model_validator(mode="after")
    def injection_consistent(self) -> Self:
        if self.attack_type is not None and self.attack_type not in INJECTION_THREATS:
            raise ValueError("this corpus measures instruction injection only")
        if self.provenance.content_sha256 != content_hash(self.kind, self.input.model_dump()):
            raise ValueError("input does not match provenance hash")
        if self.label == "safe" and self.expected_action != "ALLOW":
            raise ValueError("benign corpus targets require ALLOW")
        if self.label == "attack" and self.expected_action == "ALLOW":
            raise ValueError("attack corpus targets cannot be ALLOW")
        return self


@dataclass(frozen=True)
class InjectionDataset:
    records: tuple[InjectionRecord, ...]
    sources: tuple[dict[str, str | int], ...]
    revision: str = CORPUS_REVISION


def load_injection_dataset(paths: list[Path] | None = None) -> InjectionDataset:
    """Validate all splits together before selecting a comparison subset.

    Group and source-family isolation are necessary but cannot prove semantic
    independence. Paths and provenance are inert local metadata; nothing is fetched.
    """
    records: list[InjectionRecord] = []
    sources: list[dict[str, str | int]] = []
    ids, inputs = set(), set()
    group_splits: dict[str, str] = {}
    family_splits: dict[str, str] = {}
    source_groups: dict[tuple[str | None, str, str], str] = {}
    for path in DEFAULT_INJECTION_DATASETS if paths is None else paths:
        location = json.dumps(path.as_posix(), ensure_ascii=True)
        try:
            with path.open("rb") as stream:
                raw = stream.read(MAX_FILE_BYTES + 1)
            if len(raw) > MAX_FILE_BYTES:
                raise EvaluationError(f"{location}: dataset exceeds 4 MiB")
            lines = raw.decode("utf-8").split("\n")
            if lines[-1] == "":
                lines.pop()
        except (OSError, UnicodeError):
            raise EvaluationError(f"{location}: cannot read UTF-8 dataset") from None
        if not lines:
            raise EvaluationError(f"{location}: empty dataset")
        for number, line in enumerate(lines, 1):
            where = f"{location}: record {number}"
            try:
                value = json.loads(line, object_pairs_hook=_object)
                row = InjectionRecord.model_validate(value)
            except (ValueError, ValidationError, RecursionError):
                raise EvaluationError(f"{where}: invalid injection record or provenance") from None
            if row.id in ids:
                raise EvaluationError(f"{where}: duplicate ID")
            if row.provenance.content_sha256 in inputs:
                raise EvaluationError(f"{where}: duplicate input")
            if group_splits.setdefault(row.group, row.split) != row.split:
                raise EvaluationError(f"{where}: group crosses splits")
            if family_splits.setdefault(row.provenance.family, row.split) != row.split:
                raise EvaluationError(f"{where}: family crosses splits")
            source = (
                row.provenance.upstream_url,
                row.provenance.revision,
                row.provenance.source_id,
            )
            if source_groups.setdefault(source, row.group) != row.group:
                raise EvaluationError(f"{where}: source variants must share a group")
            ids.add(row.id)
            inputs.add(row.provenance.content_sha256)
            records.append(row)
        sources.append(
            {
                "path": path.as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "records": len(lines),
            }
        )
    if not records:
        raise EvaluationError("No injection dataset records")
    return InjectionDataset(tuple(records), tuple(sources))
