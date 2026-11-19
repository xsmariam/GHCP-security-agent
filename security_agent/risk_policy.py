"""Transparent, deterministic qualitative risk model. Not a CVSS implementation.

The model supplies three 0-3 scores with a rationale; this module, not the model,
decides the final severity. Total 0-2 Low, 3-5 Medium, 6-7 High, 8-9 Critical.
"""
from __future__ import annotations

VALID_STATUS = {'source-supported', 'conditional', 'requires-review'}
SEVERITIES = ('Critical', 'High', 'Medium', 'Low')
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # 0 = most severe

# Weak password storage that is actively used compromises every stored credential
# once hashes leak, so it is never ranked below High when source-supported.
PASSWORD_STORAGE_CWES = {'CWE-916', 'CWE-328', 'CWE-759', 'CWE-760', 'CWE-256', 'CWE-257'}


class RiskPolicyError(ValueError):
    pass


def severity_from_score(score: int) -> str:
    return 'Low' if score <= 2 else 'Medium' if score <= 5 else 'High' if score <= 7 else 'Critical'


def assess_finding(f: dict) -> dict:
    risk = f.get('risk')
    if not isinstance(risk, dict):
        raise RiskPolicyError('missing risk assessment')
    for name in ('exposure', 'exploitability', 'impact'):
        if type(risk.get(name)) is not int or risk[name] not in (0, 1, 2, 3):
            raise RiskPolicyError(f'{name} must be an integer between 0 and 3')
    rationale = risk.get('rationale')
    if not isinstance(rationale, str) or not 15 <= len(rationale.strip()) <= 500:
        raise RiskPolicyError('risk rationale is missing or not 15-500 characters')
    status = f.get('verification_status')
    if status not in VALID_STATUS:
        raise RiskPolicyError('invalid verification_status')
    assumptions = risk.get('assumptions', '')
    if not isinstance(assumptions, str) or len(assumptions) > 400:
        raise RiskPolicyError('invalid assumptions')
    if status != 'source-supported' and not assumptions.strip():
        raise RiskPolicyError('conditional and requires-review findings must state assumptions')

    score = risk['exposure'] + risk['exploitability'] + risk['impact']
    severity = severity_from_score(score)
    # Uncertainty caps: unproven deployment conditions or reachability limit severity.
    if status == 'conditional' and severity == 'Critical':
        severity = 'High'
    if status == 'requires-review' and severity in ('Critical', 'High'):
        severity = 'Medium'
    if f.get('cwe') in PASSWORD_STORAGE_CWES and status == 'source-supported' and severity in ('Low', 'Medium'):
        severity = 'High'
    return {'score': score, 'severity': severity}


def at_or_above(severity: str, threshold: str) -> bool:
    return SEVERITY_RANK[severity] <= SEVERITY_RANK[threshold]
