import html
import re
import unicodedata
from email.utils import parseaddr

from ai_security_gateway.security.normalization import canonicalize

MAX_SENDER_LENGTH = 320
MAX_SUBJECT_LENGTH = 998
MAX_EMAIL_BODY_LENGTH = 100_000
MAX_EMAIL_REQUEST_BYTES = 1280 * 1024


def validate_email_field(value: str, limit: int) -> str:
    """Bound original input for both API and direct callers, without echoing it."""
    if not isinstance(value, str):
        raise TypeError("email field must be a string")
    if not 1 <= len(value) <= limit or not canonicalize(value).strip():
        raise ValueError("email field is empty or exceeds its character limit")
    return value


def normalize_email_text(text: str) -> str:
    # Decode entities and remove markup without concatenating separate words.
    return canonicalize(re.sub(r"<[^>]{0,2048}>", " ", html.unescape(text)))


def normalize_sender(sender: str) -> tuple[str, str, bool]:
    """Return display name, normalized address, and syntax validity; no authentication."""
    folded = unicodedata.normalize("NFKC", sender).strip()
    if any(unicodedata.category(c).startswith("C") for c in folded):
        return "", "", False
    try:
        name, address = parseaddr(folded, strict=True)
    except (ValueError, TypeError):
        return "", "", False
    if address.count("@") != 1:
        return name.casefold(), "", False
    local, domain = address.rsplit("@", 1)
    try:
        domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return name.casefold(), "", False
    valid = bool(
        re.fullmatch(r"[^\s<>@,;:]+", local)
        and len(local) <= 64
        and "." in domain
        and len(domain) <= 253
        and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in domain.split("."))
    )
    return name.casefold(), f"{local.casefold()}@{domain}", valid
