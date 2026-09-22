import re
import unicodedata

MAX_PROMPT_LENGTH = 20_000
# Allows JSON escaping of every character, plus modest envelope overhead.
MAX_PROMPT_BODY_BYTES = 128 * 1024


def canonicalize(text: str) -> str:
    """Fold compatibility characters and remove invisible formatting/combining marks."""
    folded = unicodedata.normalize("NFKD", text).casefold()
    return "".join(c for c in folded if unicodedata.category(c) not in {"Cf", "Mn", "Me"})


def normalize(text: str) -> str:
    return " ".join(re.sub(r"[\W_]+", " ", canonicalize(text)).split())


def validate_text(text: str) -> str:
    """Use the same bounds for direct Python callers and HTTP requests."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if not 1 <= len(text) <= MAX_PROMPT_LENGTH:
        raise ValueError(f"text must contain 1 to {MAX_PROMPT_LENGTH} characters")
    if not canonicalize(text).strip():
        raise ValueError("text must contain visible content")
    return text
