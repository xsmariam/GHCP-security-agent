"""Local secret detection, masking before upload, and redaction of reports.

Detection is heuristic. It errs toward masking too much: a masked non-secret
costs a little review context, while a leaked secret cannot be taken back.
"""
from __future__ import annotations

import re

MASK = 'REDACTED_SECRET'
REDACTED = '[REDACTED]'

_SECRET_NAME = r'[\w$.-]*(?:passw(?:or)?d|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth[_-]?token|token|credential|client[_-]?secret)[\w$.-]*'

# name = "value"  |  name: "value"  |  "name": "value"  |  name := "value"  |  name: str = "value"
ASSIGNMENT = re.compile(
    r'(?P<name>["\']?' + _SECRET_NAME + r'["\']?)'
    r'(?P<sep>\s*(?::\s*[\w\[\]<>, .]+\s*)?(?::=|=|:)\s*)'
    r'(?P<q>["\'])(?P<value>[^"\'\n]{4,})(?P=q)',
    re.IGNORECASE,
)

# Well-known credential formats that are secret wherever they appear.
TOKEN_PATTERNS = [
    re.compile(r'AKIA[0-9A-Z]{16}'),                         # AWS access key id
    re.compile(r'gh[pousr]_[A-Za-z0-9]{36,}'),                # GitHub tokens
    re.compile(r'github_pat_[A-Za-z0-9_]{40,}'),
    re.compile(r'xox[baprs]-[A-Za-z0-9-]{10,}'),              # Slack
    re.compile(r'(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}'),  # Stripe
    re.compile(r'AIza[0-9A-Za-z_-]{35}'),                     # Google API key
    re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),  # JWT
    re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----'),
]

# Values that are clearly not secrets (placeholders, env lookups, empty-ish).
_PLACEHOLDER = re.compile(r'^(?:\$\{.*\}|%\(.*\)s|<.*>|\*+|x+|changeme|password|secret|your[_-].*|example.*|test|dummy|null|none|true|false)$', re.I)


def find_secrets(text: str) -> set[str]:
    """Return literal secret values found in text."""
    found: set[str] = set()
    for m in ASSIGNMENT.finditer(text):
        value = m.group('value').strip()
        if value and not _PLACEHOLDER.match(value) and value != MASK:
            found.add(value)
    for pattern in TOKEN_PATTERNS:
        found.update(m.group(0) for m in pattern.finditer(text))
    return found


def mask_source(text: str) -> tuple[str, int]:
    """Replace secret literal values in source with a fixed marker.

    Only the value inside the quotes is replaced, so line numbers are preserved
    and the model can still see that a hardcoded literal is assigned.
    """
    count = 0

    def _assign(m: re.Match) -> str:
        nonlocal count
        value = m.group('value').strip()
        if not value or _PLACEHOLDER.match(value) or value == MASK:
            return m.group(0)
        count += 1
        return f"{m.group('name')}{m.group('sep')}{m.group('q')}{MASK}{m.group('q')}"

    text = ASSIGNMENT.sub(_assign, text)
    for pattern in TOKEN_PATTERNS:
        def _token(m: re.Match) -> str:
            nonlocal count
            count += 1
            # keep line structure for multi-line keys
            return '\n'.join(MASK for _ in m.group(0).split('\n'))
        text = pattern.sub(_token, text)
    return text, count


def redact(obj, secrets: set[str]):
    """Recursively replace any known secret value inside strings of obj."""
    ordered = sorted((s for s in secrets if len(s) >= 4), key=len, reverse=True)
    if not ordered:
        return obj

    def _walk(o):
        if isinstance(o, str):
            for s in ordered:
                if s in o:
                    o = o.replace(s, REDACTED)
            return o
        if isinstance(o, list):
            return [_walk(x) for x in o]
        if isinstance(o, dict):
            return {k: _walk(v) for k, v in o.items()}
        return o

    return _walk(obj)
