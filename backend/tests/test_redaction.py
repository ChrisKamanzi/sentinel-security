"""Secret redaction applied before anything is sent to the Claude API."""

import pytest

from app.services.redaction import REDACTED, redact


@pytest.mark.parametrize("text, secret", [
    ("Authorization: Bearer abcdef123456789", "abcdef123456789"),
    ("authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA=="),
    ("Cookie: session=s3cr3tvalue; theme=dark", "s3cr3tvalue"),
    ("Set-Cookie: token=abc123def456; HttpOnly", "abc123def456"),
    ("curl -H 'Cookie: sid=zzz999yyy' http://x", "zzz999yyy"),
    ("x-api-key: live_ABCDEF1234567890", "live_ABCDEF1234567890"),
    ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "dozjgNryP4J3jVmNHl0w5N"),
    ("key AKIAIOSFODNN7EXAMPLE here", "AKIAIOSFODNN7EXAMPLE"),
    ("anthropic sk-ant-api03-abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"),
    ("github ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_abcdefghij"),
    ("slack xoxb-1234567890-abcdefghij", "xoxb-1234567890"),
    ("http://admin:hunter2@127.0.0.1:3000/login", "hunter2"),
    ("http://127.0.0.1/reset?token=abc123&user=bob", "abc123"),
    ('{"email":"a@b.c","password":"Sup3rS3cret!"}', "Sup3rS3cret!"),
    ("api_key=0123456789abcdef", "0123456789abcdef"),
    ("PHPSESSID=deadbeefcafe", "deadbeefcafe"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----", "MIIEow"),
])
def test_secrets_are_redacted(text, secret):
    out, n = redact(text)
    assert secret not in out
    assert REDACTED in out
    assert n >= 1


@pytest.mark.parametrize("text", [
    "matched-at: http://127.0.0.1:3000/metrics\ntemplate: prometheus-metrics",
    "Missing header: x-frame-options",
    "port: 3000/tcp\nservice: http",
    "CWE-200 information exposure",
])
def test_ordinary_evidence_untouched(text):
    out, n = redact(text)
    assert out == text and n == 0


def test_none_and_empty():
    assert redact(None) == (None, 0)
    assert redact("") == ("", 0)
