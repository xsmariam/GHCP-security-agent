"""Evidence-validated, read-only AI security review of source code."""

__version__ = "2.0.0"


class AuditError(Exception):
    """A fatal problem that stops the audit (bad input, missing CLI, tampering)."""
