#!/usr/bin/env python3
"""Stand-in for the Copilot CLI used by tests. Behaves like an imperfect model:
returns one real finding, one fabricated finding, and echoes a secret it should not."""
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
prompt = args[args.index('-p') + 1]
if os.environ.get('FAKE_COPILOT_LOG'):
    with open(os.environ['FAKE_COPILOT_LOG'], 'a') as fh:
        fh.write(json.dumps(args[2:]) + '\n')
assigned = prompt.split('ASSIGNED FILES:\n', 1)[1].split('\n\n', 1)[0].splitlines()
findings = []
for rel in assigned:
    lines = Path(rel).read_text().splitlines()
    for i, line in enumerate(lines, 1):
        if '"/bin/sh"' in line:
            findings.append({
                'title': 'OS command injection', 'severity': 'Critical', 'cwe': 'CWE-78', 'file': rel,
                'line_start': i, 'line_end': i, 'evidence': '"/bin/sh"',
                'explanation': 'Request parameter reaches a shell. Old password was Sup3rS3cret!2024.',
                'remediation': 'Avoid the shell; validate the host and pass arguments as an array.',
                'confidence': 'high', 'verification_status': 'source-supported',
                'risk': {'exposure': 3, 'exploitability': 3, 'impact': 3,
                         'rationale': 'Unauthenticated handler passes input to sh -c.', 'assumptions': ''}})
        if 'DB_PASSWORD =' in line:
            findings.append({
                'title': 'Hardcoded database password', 'severity': 'High', 'cwe': 'CWE-798', 'file': rel,
                'line_start': i, 'line_end': i, 'evidence': line.strip(),
                'explanation': 'Credential literal in source.', 'remediation': 'Load from a secret manager.',
                'confidence': 'high', 'verification_status': 'source-supported',
                'risk': {'exposure': 2, 'exploitability': 2, 'impact': 3,
                         'rationale': 'Anyone with source access obtains DB credentials.', 'assumptions': ''}})
findings.append({
    'title': 'Invented issue', 'severity': 'High', 'cwe': 'CWE-89', 'file': assigned[0],
    'line_start': 1, 'line_end': 1, 'evidence': 'SELECT * FROM nowhere',
    'explanation': 'Hallucinated.', 'remediation': 'n/a', 'confidence': 'low',
    'verification_status': 'source-supported',
    'risk': {'exposure': 3, 'exploitability': 3, 'impact': 1, 'rationale': 'Made up for the test case.', 'assumptions': ''}})
print('Here is the audit:\n```json\n' + json.dumps({'files_reviewed': assigned, 'unreviewed_files': [], 'findings': findings}) + '\n```')
