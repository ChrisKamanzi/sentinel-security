"""Redact secrets from text before it leaves the server (e.g. to the Claude API).

Conservative by design: it may over-redact, which is preferable to leaking.
"""

import re

REDACTED = "[REDACTED]"

_SECRET_KEYS = (
    r"password|passwd|pwd|pass|secret|client[_-]?secret|token|access[_-]?token|refresh[_-]?token|"
    r"id[_-]?token|api[_-]?key|apikey|x-api-key|auth[_-]?token|session[_-]?id|sessionid|sid|jsessionid|"
    r"phpsessid|csrf[_-]?token|xsrf[_-]?token|private[_-]?key|aws_secret_access_key|signature"
)

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # PEM private keys
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), REDACTED),
    # Whole header lines carrying credentials or session state
    (re.compile(r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token)\s*:\s*).+$"),
     r"\1" + REDACTED),
    # Inline header-style occurrences (e.g. inside curl commands)
    (re.compile(r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key)(\s*:\s*)[^'\"\r\n]+"),
     r"\1\2" + REDACTED),
    # Bearer / Basic credentials
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9\-._~+/]{8,}=*"), r"\1 " + REDACTED),
    # JSON Web Tokens
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"), REDACTED),
    # Well-known API key formats
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{16,}"), REDACTED),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), REDACTED),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), REDACTED),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), REDACTED),
    # Credentials embedded in URLs: scheme://user:pass@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1" + REDACTED + "@"),
    # key=value / "key": "value" pairs (query strings, JSON, forms, config)
    (re.compile(
        r"(?i)([\"']?\b(?:" + _SECRET_KEYS + r")\b[\"']?\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s&;,\"'}\]]+)"),
     r"\1" + REDACTED),
]


def redact(text: str | None) -> tuple[str | None, int]:
    """Return (redacted_text, number_of_redactions)."""
    if not text:
        return text, 0
    total = 0
    for pattern, replacement in _PATTERNS:
        text, n = pattern.subn(replacement, text)
        total += n
    return text, total
