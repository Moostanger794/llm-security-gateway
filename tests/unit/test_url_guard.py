import pytest

from ai_security_gateway.security.risk_engine import RiskEngine
from ai_security_gateway.security.url_guard import URLGuard, extract_urls


@pytest.mark.parametrize(
    ("url", "minimum"),
    [
        ("http://example.com", 0.1),
        ("https://192.0.2.1", 0.45),
        ("https://[2001:db8::1]/", 0.45),
        ("https://user:demo@example.com", 0.65),
        ("https://xn--pple-43d.example", 0.35),
        ("https://пример.рф", 0.35),
        ("https://example.com.other.example", 0.45),
        ("https://a.b.c.d.example.com", 0.45),
        ("https://example.com/" + "x" * 2048, 0.25),
        ("https://example-login.com", 0.2),
        ("javascript:alert(1)", 0.7),
        ("file:///etc/passwd", 0.7),
        ("data:text/html,test", 0.7),
        ("ftp://example.com/file", 0.7),
        ("https://example.com/?next=https%3A%2F%2Fother.example", 0.35),
        ("https://example.com/?redirect=javascript%3Aalert(1)", 0.35),
        ("https://2130706433", 0.45),
        ("https://0x7f000001", 0.45),
        ("https://127.1", 0.45),
        ("https://bad_host.example", 0.5),
        ("https://example.com:8443", 0.2),
        ("https://-bad.example", 0.5),
        ("https://exa\u200bmple.com", 0.45),
        ("https://%65xample.com", 0.45),
        ("https://a-b-c-d.example", 0.45),
    ],
)
def test_url_indicators(url: str, minimum: float) -> None:
    findings = URLGuard().detect(url)
    assert RiskEngine.score(findings) >= minimum
    assert all(f.threat == "suspicious_url" for f in findings)
    assert all(url not in f.explanation + f.recommendation for f in findings)
    assert all("malware" not in f.explanation for f in findings)


@pytest.mark.parametrize(
    "url",
    [
        "",
        "https://",
        "https://[oops",
        "https://example.com:abc",
        "https://example.com:99999",
        "https://\ud800.example",
        "https://example.com／evil",
    ],
)
def test_malformed_urls_do_not_crash(url: str) -> None:
    assert URLGuard().detect(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "HTTPS://EXAMPLE.COM/docs",
        "https://docs.example.com/guide",
        "https://example.com/?next=/guide",
        "https://example.com/?next=https://example.com/guide",
        "www.example.com",
        "//example.com/path",
    ],
)
def test_benign_urls(url: str) -> None:
    assert URLGuard().detect(url) == []


def test_extraction() -> None:
    text = (
        'See (https://example.com/a_(b)). <a href="https://other.example/?a=1&amp;b=2">go</a> '
        "https://example.com/a_(b) www.example.com //cdn.example.com/a javascript:alert(1)"
    )
    assert extract_urls(text) == [
        "https://example.com/a_(b)",
        "https://other.example/?a=1&b=2",
        "www.example.com",
        "//cdn.example.com/a",
        "javascript:alert(1)",
    ]
    assert extract_urls("Plain email a@example.com and example.com, /relative") == []


def test_extraction_does_not_truncate_later_urls() -> None:
    text = " ".join(f"https://example.com/{i}" for i in range(1000)) + " https://192.0.2.1"
    assert len(extract_urls(text)) == 1001
    assert extract_urls(text)[-1] == "https://192.0.2.1"


def test_many_trailing_parentheses() -> None:
    assert extract_urls("https://example.com" + ")" * 50_000) == ["https://example.com"]
