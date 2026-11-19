# Required output

Respond with ONLY one JSON object, with no markdown fences and no commentary:

{
  "files_reviewed": ["path/of/assigned/file.ext"],
  "unreviewed_files": [{"file": "path/of/assigned/file2.ext", "reason": "why it could not be reviewed"}],
  "findings": [
    {
      "title": "Short vulnerability name",
      "severity": "High",
      "cwe": "CWE-89",
      "file": "path/of/assigned/file.ext",
      "line_start": 42,
      "line_end": 42,
      "evidence": "EXACT short substring copied from the cited line(s)",
      "explanation": "One or two sentences: where untrusted data comes from, where it ends up, and the security impact.",
      "remediation": "One concrete fix.",
      "confidence": "high",
      "verification_status": "source-supported",
      "risk": {"exposure": 3, "exploitability": 3, "impact": 2, "rationale": "Why each score applies.", "assumptions": ""}
    }
  ]
}

Rules the local validator enforces:
- Every ASSIGNED FILE appears exactly once, in `files_reviewed` or `unreviewed_files`. Responses that miss a file are rejected and retried.
- `evidence` is a literal, contiguous, character-for-character substring of lines `line_start`..`line_end` (at most 15 lines apart). Prefer one distinctive expression on a single line and cite that line for both start and end. Do not add ellipses, change quotes, or join distant lines. A finding whose evidence does not match is discarded.
- If the obvious evidence contains a secret, quote the variable name or the call instead, never the value.
- Use file paths exactly as listed, relative to the workspace root. Findings must be in ASSIGNED FILES.
- `confidence` is `high`, `medium` or `low`. If there are no issues, return an empty `findings` list; never invent findings.
