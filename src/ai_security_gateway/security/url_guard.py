"""Deterministic lexical URL checks. Never resolves hosts or follows links."""

import html
import ipaddress
import re
import unicodedata
from urllib.parse import parse_qsl, unquote, urlsplit

from ai_security_gateway.security.risk_engine import Finding

MAX_URL_LENGTH = 2048
URL_PATTERN = re.compile(
    r"(?i)(?<![\w@])(?:[a-z][a-z0-9+.-]{0,31}://|www\.|"
    r"javascript:|data:|vbscript:|file:|//)[^\s<>\"']+"
)
KEYWORDS = re.compile(
    r"(?:^|[./_?=&-])(?:login|signin|verify|password|credential|account)(?:$|[./_?=&-])"
)
REDIRECT_KEYS = frozenset(
    {
        "url",
        "redirect",
        "redirect_url",
        "redirect_uri",
        "next",
        "target",
        "continue",
        "return",
        "returnurl",
    }
)


def extract_urls(text: str) -> list[str]:
    """Extract explicit schemes, protocol-relative and www links in first-seen order.

    HTML entities are decoded; trailing prose punctuation is removed. Bare domains
    and relative links are deliberately not guessed. No URL count truncation.
    """
    text = html.unescape(text)
    urls = []
    for match in URL_PATTERN.finditer(text):
        url = match.group().rstrip(".,;!?")
        excess = max(0, url.count(")") - url.count("("))
        trailing = len(url) - len(url.rstrip(")"))
        trim = min(excess, trailing)
        if trim:
            url = url[:-trim]
        urls.append(url)
    return list(dict.fromkeys(urls))


def url_finding(weight: float, reason: str) -> Finding:
    return Finding(
        "suspicious_url",
        weight,
        reason,
        "Inspect the destination independently; use a known official address before entering data.",
    )


class URLGuard:
    """Return text-free Findings for the shared RiskEngine, not malware verdicts."""

    def detect(self, url: str) -> list[Finding]:
        if not isinstance(url, str):
            raise TypeError("URL must be a string")
        findings: list[Finding] = []

        def add(weight: float, reason: str) -> None:
            findings.append(url_finding(weight, reason))

        if len(url) > MAX_URL_LENGTH:
            add(0.25, "An unusually long URL is a potential concealment indicator.")
        if not url or any(c.isspace() or unicodedata.category(c).startswith("C") for c in url):
            add(0.45, "A URL contains invalid or concealed characters.")
        candidate = "https:" + url if url.startswith("//") else url
        if candidate.lower().startswith("www."):
            candidate = "https://" + candidate
        try:
            parts = urlsplit(candidate)
            host = parts.hostname or ""
            port = parts.port
        except ValueError:
            add(0.55, "A malformed URL cannot be reliably interpreted.")
            return findings
        if parts.scheme.lower() not in {"https", "http"}:
            add(0.7, "A potentially unsafe or unsupported URL scheme was detected.")
        elif parts.scheme.lower() == "http":
            add(0.1, "A URL uses unencrypted HTTP.")
        if parts.username is not None or parts.password is not None:
            add(0.65, "Embedded URL credentials can conceal the actual destination.")
        if not host:
            add(0.45, "A URL has no valid hostname.")
            return findings
        try:
            ascii_host = host.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError:
            add(0.55, "A URL hostname has invalid internationalized encoding.")
            return findings
        try:
            ipaddress.ip_address(ascii_host)
        except ValueError:
            labels = ascii_host.split(".")
            if len(ascii_host) > 253 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in labels
            ):
                add(0.5, "A URL has a nonstandard hostname pattern.")
            if len(labels) == 1 or re.fullmatch(r"(?:0x[0-9a-f]+|[0-9.]+)", ascii_host):
                add(0.45, "A URL uses a single-label or numeric hostname representation.")
            if any(p.startswith("xn--") for p in labels):
                add(0.35, "An internationalized hostname warrants visual identity verification.")
            if len(labels) >= 5 or any(p in {"com", "net", "org"} for p in labels[:-2]):
                add(0.45, "A deep or domain-like subdomain may disguise the destination.")
            if ascii_host.count("-") >= 3 or "%" in host or "\\" in parts.netloc:
                add(0.45, "A hostname contains potentially deceptive separators or encoding.")
        else:
            add(0.45, "A URL uses an IP address rather than a named domain.")
        if port is not None and port not in {80, 443}:
            add(0.2, "A URL uses a nonstandard service port.")
        if KEYWORDS.search(unquote(ascii_host + parts.path).lower()):
            add(0.2, "A URL contains account or credential-related keywords.")
        # A redirect parameter alone is routine; an external/unsafe target is a signal.
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            if key.casefold() not in REDIRECT_KEYS:
                continue
            target = unquote(value).strip()
            try:
                redirect = urlsplit(target)
                external = bool(redirect.netloc and redirect.hostname != host)
            except ValueError:
                external = True
            if external or target.lower().startswith(("javascript:", "data:", "vbscript:")):
                add(
                    0.35,
                    "A redirect-like parameter points outside the current hostname "
                    "or uses an unsafe scheme.",
                )
                break
        return findings
