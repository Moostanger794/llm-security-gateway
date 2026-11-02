"""Explicit optional preparation check; never imported by runtime or ordinary tests."""

import argparse
import hashlib
import json
import sys
from urllib.error import URLError
from urllib.request import urlopen

from ai_security_gateway.evaluation.dataset import EvaluationError
from ai_security_gateway.evaluation.injection_dataset import load_injection_dataset

REVISION = "a004b69ec0dd446e0afd461d98cb5e96e120a5d0"
SOURCE_URL = (
    f"https://raw.githubusercontent.com/microsoft/BIPIA/{REVISION}/benchmark/text_attack_train.json"
)
EXPECTED_BLOB = "190918308f4ef25d5f43d7c1b118bf3fe5dc61d2"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--download", action="store_true", help="Allow one small public HTTPS download; no LLM API"
    )
    args = parser.parse_args(argv)
    if not args.download:
        parser.error("upstream verification requires explicit --download")
    try:
        rows = load_injection_dataset().records
        # The destination is fixed in trusted code, never read from a corpus entry.
        with urlopen(SOURCE_URL, timeout=15) as response:
            raw = response.read(128 * 1024 + 1)
        if len(raw) > 128 * 1024:
            raise ValueError("size limit")
        digest = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
        if digest != EXPECTED_BLOB:
            raise ValueError("upstream revision mismatch")
        source = json.loads(raw)
        checked = set()
        for row in rows:
            provenance = row.provenance
            if provenance.origin != "adapted":
                continue
            _, family, index = provenance.source_id.split("/")
            original = source[family][int(index)]
            if hashlib.sha256(original.encode("utf-8")).hexdigest() != provenance.source_sha256:
                raise ValueError("source hash mismatch")
            checked.add(provenance.source_id)
    except (URLError, OSError, ValueError, KeyError, IndexError, EvaluationError):
        print("Upstream verification failed; no corpus files changed.", file=sys.stderr)
        return 1
    print(f"Verified {len(checked)} source payloads at {REVISION}; no corpus files changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
