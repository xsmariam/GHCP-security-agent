"""Deterministic checks on model output.

Two levels:
* Structural problems (not JSON, wrong shape, incomplete file coverage) reject the
  whole response and trigger a fresh, restricted retry.
* A single finding that cannot be verified (wrong file, bad lines, evidence that is
  not on the cited lines, malformed risk) is dropped and recorded in
  `rejected_findings` with the reason. Other verified findings are kept.

Evidence matching proves a quoted string exists at the cited location. It does NOT
prove the vulnerability is real; a human must still confirm findings.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import AuditError
from .risk_policy import RiskPolicyError, assess_finding

ALLOWED_CONFIDENCE = {'high', 'medium', 'low'}
REQUIRED = ['title', 'cwe', 'file', 'line_start', 'line_end', 'evidence', 'explanation',
            'remediation', 'confidence', 'risk', 'verification_status']
MAX_SPAN = 15


def extract_json(output: str) -> dict:
    """Parse the model's reply; tolerate code fences or a sentence around the JSON."""
    text = output.strip()
    fenced = re.search(r'```(?:json)?\s*(\{.*\})\s*```', text, re.S)
    candidates = [fenced.group(1)] if fenced else []
    candidates.append(text)
    first, last = text.find('{'), text.rfind('}')
    if 0 <= first < last:
        candidates.append(text[first:last + 1])
    for c in candidates:
        try:
            val = json.loads(c)
        except json.JSONDecodeError:
            continue
        if isinstance(val, dict):
            return val
    raise AuditError('Response was not a single valid JSON object')


def check_structure(data: dict, assigned: list[str]) -> None:
    if not isinstance(data, dict):
        raise AuditError('Response is not a JSON object')
    reviewed, unreviewed = data.get('files_reviewed'), data.get('unreviewed_files', [])
    if not isinstance(reviewed, list) or not isinstance(unreviewed, list):
        raise AuditError('files_reviewed and unreviewed_files must be lists')
    # unreviewed entries may be "path" or {"file": path, "reason": ...}
    unreviewed_names = [u.get('file') if isinstance(u, dict) else u for u in unreviewed]
    names = reviewed + unreviewed_names
    if not all(isinstance(s, str) for s in names):
        raise AuditError('File coverage entries must be strings')
    expected = set(assigned)
    missing = sorted(expected - set(names))
    extra = sorted(set(names) - expected)
    if missing or extra or len(names) != len(set(names)):
        detail = []
        if missing:
            detail.append(f'missing {missing[:5]}')
        if extra:
            detail.append(f'not assigned {extra[:5]}')
        if len(names) != len(set(names)):
            detail.append('duplicates')
        raise AuditError('File coverage must list each assigned file exactly once (' + '; '.join(detail) + ')')
    if not isinstance(data.get('findings'), list):
        raise AuditError('findings must be a list')
    if len(data['findings']) > 150:
        raise AuditError('More than 150 findings in one batch')


def check_finding(f, assigned: set[str], reviewed: set[str], file_lines: dict[str, list[str]]) -> tuple[dict | None, str | None]:
    """Return (clean_finding, None) or (None, reason)."""
    if not isinstance(f, dict):
        return None, 'not an object'
    missing = [k for k in REQUIRED if k not in f]
    if missing:
        return None, f'missing fields: {", ".join(missing)}'
    for k in ('title', 'cwe', 'file', 'evidence', 'explanation', 'remediation', 'confidence'):
        if not isinstance(f[k], str) or not f[k].strip():
            return None, f'invalid {k}'
    if not re.fullmatch(r'CWE-\d{1,5}', f['cwe'].strip()):
        return None, 'cwe must look like CWE-123'
    if f['confidence'] not in ALLOWED_CONFIDENCE:
        return None, 'confidence must be high, medium or low'
    if f['file'] not in assigned:
        return None, f'file {f["file"]!r} is not an assigned file'
    if f['file'] not in reviewed:
        return None, 'finding is in a file listed as unreviewed'
    lines = file_lines[f['file']]
    start, end = f['line_start'], f['line_end']
    if type(start) is not int or type(end) is not int or start < 1 or end < start or end > len(lines) or end - start > MAX_SPAN:
        return None, f'invalid line range {start}-{end} (file has {len(lines)} lines)'
    evidence = f['evidence'].strip()
    excerpt = '\n'.join(lines[start - 1:end])
    if not 3 <= len(evidence) <= 300:
        return None, 'evidence must be 3-300 characters'
    if evidence not in excerpt:
        # tolerate indentation differences on multi-line evidence only
        squash = lambda s: re.sub(r'\s+', ' ', s).strip()
        if '\n' not in evidence or squash(evidence) not in squash(excerpt):
            return None, 'evidence is not an exact excerpt of the cited lines'
    if len(f['title']) > 160 or len(f['explanation']) > 800 or len(f['remediation']) > 600:
        return None, 'text fields too long'
    try:
        outcome = assess_finding(f)
    except RiskPolicyError as exc:
        return None, f'risk: {exc}'
    clean = {
        'title': f['title'].strip(), 'severity': outcome['severity'], 'cwe': f['cwe'].strip(),
        'file': f['file'], 'line_start': start, 'line_end': end, 'evidence': evidence,
        'explanation': f['explanation'].strip(), 'remediation': f['remediation'].strip(),
        'confidence': f['confidence'], 'verification_status': f['verification_status'],
        'risk': {k: f['risk'][k] for k in ('exposure', 'exploitability', 'impact')} | {
            'score': outcome['score'], 'rationale': f['risk']['rationale'].strip(),
            'assumptions': f['risk'].get('assumptions', '').strip()},
    }
    if isinstance(f.get('severity'), str) and f['severity'] != outcome['severity']:
        clean['model_severity'] = f['severity']  # transparency: policy overrode the model
    return clean, None


def validate_batch(data: dict, assigned: list[str], paths: dict[str, Path]) -> tuple[list[dict], list[dict], list[dict]]:
    """Validate one batch response. Returns (findings, rejected, unreviewed)."""
    check_structure(data, assigned)
    unreviewed = [u if isinstance(u, dict) else {'file': u, 'reason': 'not reviewed by model'}
                  for u in data.get('unreviewed_files', [])]
    reviewed = set(data['files_reviewed'])
    file_lines = {rel: paths[rel].read_text(encoding='utf-8').splitlines() for rel in assigned}
    findings, rejected = [], []
    for i, raw in enumerate(data['findings'], 1):
        clean, reason = check_finding(raw, set(assigned), reviewed, file_lines)
        if clean:
            findings.append(clean)
        else:
            title = raw.get('title') if isinstance(raw, dict) else None
            file = raw.get('file') if isinstance(raw, dict) else None
            rejected.append({'title': str(title)[:160] if title else f'finding #{i}',
                             'file': str(file)[:300] if file else None, 'reason': reason})
    return findings, rejected, unreviewed


def _overlaps(a: dict, b: dict) -> bool:
    return a['file'] == b['file'] and a['cwe'] == b['cwe'] and \
        max(a['line_start'], b['line_start']) <= min(a['line_end'], b['line_end'])


def deduplicate(findings: list[dict]) -> list[dict]:
    """Drop exact duplicates (same file, CWE and overlapping lines); keep the most severe."""
    from .risk_policy import SEVERITY_RANK
    kept: list[dict] = []
    for f in sorted(findings, key=lambda x: (SEVERITY_RANK[x['severity']], -x['risk']['score'])):
        if not any(_overlaps(f, k) for k in kept):
            kept.append(f)
    return kept


def assign_ids(findings: list[dict]) -> list[dict]:
    from .risk_policy import SEVERITY_RANK
    ordered = sorted(findings, key=lambda x: (SEVERITY_RANK[x['severity']], x['file'], x['line_start']))
    return [{'id': f'F{i:03d}', **f} for i, f in enumerate(ordered, 1)]
