import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
VULNSHOP = ROOT / 'examples' / 'vulnshop'
FAKE_COPILOT = Path(__file__).resolve().parent / 'fixtures' / 'fake_copilot.py'


def finding(file, line, evidence, **over):
    f = {'title': 'OS command injection', 'severity': 'Critical', 'cwe': 'CWE-78', 'file': file,
         'line_start': line, 'line_end': line, 'evidence': evidence,
         'explanation': 'User input reaches a shell.', 'remediation': 'Avoid the shell.',
         'confidence': 'high', 'verification_status': 'source-supported',
         'risk': {'exposure': 3, 'exploitability': 3, 'impact': 3,
                  'rationale': 'Unauthenticated input reaches sh -c.', 'assumptions': ''}}
    f.update(over)
    return f


def line_of(path: Path, needle: str) -> int:
    return next(i for i, l in enumerate(path.read_text().splitlines(), 1) if needle in l)
