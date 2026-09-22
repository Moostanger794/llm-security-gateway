"""Strict JSONL data loading with input-free diagnostics."""

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from ai_security_gateway.api.schemas import EmailRequest, PromptRequest
from ai_security_gateway.models.security import SecurityAction, Threat

Kind = Literal["prompt", "text", "email", "url"]
Label = Literal["safe", "attack"]
MAX_FILE_BYTES = 4 * 1024 * 1024
IDENTIFIER = re.compile(r"\A[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}\Z")


class EvaluationError(ValueError):
    """Controlled, redacted CLI failure."""


class URLInput(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)
    # Invalid URL syntax is evaluation input, not a schema failure.
    url: str = Field(max_length=20_000)


class Record(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    id: str = Field(pattern=IDENTIFIER)
    kind: Kind
    input: PromptRequest | EmailRequest | URLInput
    label: Label
    attack_type: Threat | None
    expected_action: SecurityAction

    @model_validator(mode="after")
    def consistent(self) -> Self:
        expected = {
            "prompt": PromptRequest,
            "text": PromptRequest,
            "email": EmailRequest,
            "url": URLInput,
        }[self.kind]
        if not isinstance(self.input, expected):
            raise ValueError("input schema does not match kind")
        if (self.label == "safe") != (self.attack_type is None):
            raise ValueError("safe requires null attack_type; attack requires a threat category")
        return self


@dataclass(frozen=True)
class Dataset:
    records: tuple[Record, ...]
    sources: tuple[dict[str, str | int], ...]


def _object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def load_dataset(paths: list[Path]) -> Dataset:
    records, sources, seen = [], [], set()
    for path in paths:
        location = json.dumps(path.as_posix(), ensure_ascii=True)
        try:
            with path.open("rb") as stream:
                raw = stream.read(MAX_FILE_BYTES + 1)
            if len(raw) > MAX_FILE_BYTES:
                raise EvaluationError(f"{location}: dataset exceeds 4 MiB")
            # JSONL uses LF delimiters. Unicode line separators can occur inside JSON strings.
            lines = raw.decode("utf-8").split("\n")
            if lines[-1] == "":
                lines.pop()
        except (OSError, UnicodeError):
            raise EvaluationError(f"{location}: cannot read UTF-8 dataset") from None
        if not lines:
            raise EvaluationError(f"{location}: empty dataset")
        for index, line in enumerate(lines, 1):
            where = f"{location}: record {index}"
            try:
                value = json.loads(line, object_pairs_hook=_object)
            except (ValueError, RecursionError):
                raise EvaluationError(f"{where}: invalid JSON or duplicate key") from None
            sample_id = value.get("id") if isinstance(value, dict) else None
            if isinstance(sample_id, str) and IDENTIFIER.fullmatch(sample_id):
                where += f" (id={sample_id})"
            try:
                record = Record.model_validate(value)
            except ValidationError:
                # Pydantic errors can contain submitted text, even in field locations.
                raise EvaluationError(f"{where}: invalid record schema") from None
            if record.id in seen:
                raise EvaluationError(f"{where}: duplicate ID")
            seen.add(record.id)
            records.append(record)
        sources.append(
            {
                "path": path.as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "records": len(lines),
            }
        )
    if not records:
        raise EvaluationError("No dataset records")
    return Dataset(tuple(records), tuple(sources))
