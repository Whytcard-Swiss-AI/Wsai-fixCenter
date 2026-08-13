from __future__ import annotations

import os
import re
from typing import Any

_SECRET = re.compile(
    r"(?i)\b(token|api[_-]?key|password|passwd|secret|authorization|cookie)(\s*[:=]\s*)([^\s,;]+)"
)
_QUOTED_SECRET = re.compile(
    r"(?i)([\"\'](?:token|api[_-]?key|password|passwd|secret|authorization|cookie)[\"\']\s*:\s*[\"\'])(.*?)([\"\'])"
)
_BEARER = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]+")
_URL_CREDENTIAL = re.compile(r"(?i)(https?://)[^/\s:@]+:[^@\s/]+@")
_KNOWN_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{30,})\b"
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_PEM = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
)
_EMAIL = re.compile(r"(?<![\w.-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")
_WINDOWS_HOME = re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\\s\"']+")
_UNIX_HOME = re.compile(r"(?<![\w])/(?:home|Users)/[^/\s\"']+")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_MAC = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")


def contains_secret(text: str) -> bool:
    """Detect credential-shaped values before writing a setup manifest."""
    return any(
        pattern.search(text)
        for pattern in (
            _SECRET,
            _QUOTED_SECRET,
            _BEARER,
            _URL_CREDENTIAL,
            _KNOWN_TOKEN,
            _JWT,
            _PEM,
        )
    )


def redact(text: str, *, max_chars: int = 8_000) -> str:
    """Remove common secrets and personal identifiers from diagnostic output."""
    value = _PEM.sub("<REDACTED>", text)[:max_chars]
    value = _SECRET.sub(
        lambda match: f"{match.group(1)}{match.group(2)}<REDACTED>", value
    )
    value = _QUOTED_SECRET.sub(r"\1<REDACTED>\3", value)
    value = _BEARER.sub(r"\1<REDACTED>", value)
    value = _URL_CREDENTIAL.sub(r"\1<REDACTED>@", value)
    value = _KNOWN_TOKEN.sub("<REDACTED>", value)
    value = _JWT.sub("<REDACTED>", value)
    value = _EMAIL.sub("<EMAIL>", value)
    value = _WINDOWS_HOME.sub("<HOME>", value)
    value = _UNIX_HOME.sub("<HOME>", value)
    value = _IPV4.sub("<IP>", value)
    value = _MAC.sub("<MAC>", value)
    for key in ("USERNAME", "USER", "COMPUTERNAME", "HOSTNAME"):
        sensitive = os.environ.get(key)
        if sensitive and len(sensitive) >= 3:
            value = re.sub(re.escape(sensitive), f"<{key}>", value, flags=re.IGNORECASE)
    if len(text) > max_chars:
        value += "\n<TRUNCATED>"
    return value


def redact_value(value: Any) -> Any:
    """Recursively redact strings before data enters a report or MCP response."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    if isinstance(value, dict):
        return {redact(str(key)): redact_value(item) for key, item in value.items()}
    return value
