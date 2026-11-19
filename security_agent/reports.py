"""Local reports from validated, redacted audit data: text, HTML, SARIF, JSON."""
from __future__ import annotations

import html
import json
import os
from pathlib import Path

from . import __version__
from .languages import LANGUAGE_LABELS
from .risk_policy import SEVERITIES

SARIF_LEVEL = {'Critical': 'error', 'High': 'error', 'Medium': 'warning', 'Low': 'note'}
SECURITY_SEVERITY = {'Critical': '9.5', 'High': '7.5', 'Medium': '5.0', 'Low': '2.0'}  # GitHub code scanning buckets


def counts(findings: list[dict]) -> dict[str, int]:
    return {s: sum(f['severity'] == s for f in findings) for s in SEVERITIES}


def summary(data: dict) -> str:
    fs = data['findings']
    c = counts(fs)
    cov = data['coverage']
    lines = [
        f"Security audit: {data['repository']} | {cov['reviewed']}/{cov['total']} files reviewed | {len(fs)} findings",
        'Severity: ' + ', '.join(f'{v} {k}' for k, v in c.items()),
    ]
    if fs:
        lines.append('Top priorities:')
        lines.extend(f"- [{f['id']}] {f['severity']}: {f['title']} ({f['cwe']}) - {f['file']}:{f['line_start']}"
                     for f in fs[:10])
        if len(fs) > 10:
            lines.append(f'+ {len(fs) - 10} more in findings.json / audit_report.html')
    if cov['unreviewed']:
        lines.append(f"Coverage gap: {len(cov['unreviewed'])} files NOT reviewed (see report).")
    if data['rejected_findings']:
        lines.append(f"Discarded: {len(data['rejected_findings'])} model claims failed evidence checks and were not reported.")
    pending = sum(f['verification_status'] != 'source-supported' for f in fs)
    if pending:
        lines.append(f'Needs human review: {pending} conditional/uncertain findings.')
    lines.append('AI-assisted static review: evidence locations are verified, exploitability is not. No source files changed.')
    return '\n'.join(lines)


def html_report(data: dict) -> str:
    esc = lambda s: html.escape(str(s), quote=True)
    fs = data['findings']
    c = counts(fs)
    cov = data['coverage']
    colors = {'Critical': '#8b1a1a', 'High': '#c0392b', 'Medium': '#b9770e', 'Low': '#2e6b9e'}
    rows = '\n'.join(
        f'<tr><td>{esc(f["id"])}</td><td><span class="sev" style="background:{colors[f["severity"]]}">{esc(f["severity"])}</span></td>'
        f'<td>{esc(f["title"])}<div class="muted">{esc(f["cwe"])} · {esc(f["verification_status"])} · confidence {esc(f["confidence"])}</div></td>'
        f'<td><code>{esc(f["file"])}:{f["line_start"]}</code></td><td>{esc(f["remediation"])}</td></tr>'
        for f in fs)
    details = '\n'.join(
        f'<details id="{esc(f["id"])}"><summary><b>{esc(f["id"])}</b> {esc(f["severity"])} — {esc(f["title"])}</summary>'
        f'<p><b>Location:</b> <code>{esc(f["file"])}</code> lines {f["line_start"]}–{f["line_end"]}</p>'
        f'<pre>{esc(f["evidence"])}</pre><p>{esc(f["explanation"])}</p>'
        f'<p><b>Fix:</b> {esc(f["remediation"])}</p>'
        f'<p class="muted"><b>Risk</b> exposure {f["risk"]["exposure"]}, exploitability {f["risk"]["exploitability"]}, '
        f'impact {f["risk"]["impact"]} (score {f["risk"]["score"]}/9). {esc(f["risk"]["rationale"])}'
        + (f' <b>Assumptions:</b> {esc(f["risk"]["assumptions"])}' if f['risk']['assumptions'] else '') + '</p></details>'
        for f in fs)
    gaps = ''.join(f'<li><code>{esc(u["file"])}</code> — {esc(u.get("reason", ""))}</li>' for u in cov['unreviewed'])
    rejected = ''.join(f'<li>{esc(r["title"])} <span class="muted">({esc(r.get("file") or "?")}): {esc(r["reason"])}</span></li>'
                       for r in data['rejected_findings'])
    langs = ', '.join(f'{LANGUAGE_LABELS.get(k, k)} ({v})' for k, v in data['languages'].items())
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Security Audit — {esc(data['repository'])}</title>
<style>body{{font:14px -apple-system,BlinkMacSystemFont,Segoe UI,Arial,sans-serif;color:#202936;max-width:1080px;margin:32px auto;padding:0 18px;line-height:1.5}}
h1{{font-size:24px;margin-bottom:4px}}h2{{font-size:18px;margin-top:28px}}.muted{{color:#5f6b78;font-size:12.5px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{padding:8px 10px;border:1px solid #d9dfe5;text-align:left;vertical-align:top}}th{{background:#f0f3f6}}
.sev{{color:#fff;border-radius:4px;padding:1px 7px;font-size:12px;white-space:nowrap}}.cards{{display:flex;gap:10px;flex-wrap:wrap}}
.card{{border:1px solid #d9dfe5;border-radius:8px;padding:10px 16px;min-width:90px}}.card b{{font-size:22px;display:block}}
details{{border:1px solid #d9dfe5;border-radius:6px;padding:8px 12px;margin:8px 0}}pre{{background:#f6f8fa;padding:8px;overflow-x:auto;white-space:pre-wrap}}code{{font-size:12.5px}}</style></head><body>
<h1>Security Audit — {esc(data['repository'])}</h1>
<p class="muted">Generated {esc(data['generated_at_utc'])} · security-agent {esc(__version__)} · AI-assisted static review (read-only)</p>
<div class="cards">{''.join(f'<div class="card"><b style="color:{colors[k]}">{v}</b>{k}</div>' for k, v in c.items())}
<div class="card"><b>{cov['reviewed']}/{cov['total']}</b>files reviewed</div></div>
<p><b>Languages:</b> {esc(langs)}</p>
<h2>Findings</h2>{'<table><tr><th>ID</th><th>Severity</th><th>Issue</th><th>Location</th><th>Recommended action</th></tr>' + rows + '</table>' if fs else '<p>No verified findings.</p>'}
{'<h2>Details</h2>' + details if fs else ''}
{'<h2>Coverage gaps</h2><ul>' + gaps + '</ul>' if gaps else ''}
{'<h2>Discarded model claims</h2><p class="muted">These failed local evidence checks and are not counted as findings. They may still merit a manual look.</p><ul>' + rejected + '</ul>' if rejected else ''}
<h2>Next steps</h2><ol><li>Confirm each finding; record false positives so the team can tune prompts.</li>
<li>Assign owners and fix Critical and High items first; document accepted risks.</li>
<li>Add regression tests for recurring root causes, then rescan.</li></ol>
<p class="muted">Severity comes from a transparent qualitative rubric (not CVSS). Evidence excerpts are verified to exist at the cited lines; exploitability was not tested. Secret values are redacted.</p>
</body></html>'''


def sarif(data: dict) -> dict:
    rules: dict[str, dict] = {}
    results = []
    for f in data['findings']:
        rule_id = f['cwe']
        if rule_id not in rules:
            num = rule_id.split('-')[1]
            rules[rule_id] = {
                'id': rule_id, 'name': rule_id.replace('-', ''),
                'shortDescription': {'text': f['title']},
                'helpUri': f'https://cwe.mitre.org/data/definitions/{num}.html',
                'properties': {'tags': ['security', rule_id]},
            }
        results.append({
            'ruleId': rule_id, 'level': SARIF_LEVEL[f['severity']],
            'message': {'text': f"{f['title']}: {f['explanation']} Fix: {f['remediation']}"},
            'locations': [{'physicalLocation': {
                'artifactLocation': {'uri': f['file']},
                'region': {'startLine': f['line_start'], 'endLine': f['line_end']}}}],
            'partialFingerprints': {'securityAgent/v1': f"{f['file']}:{f['cwe']}:{f['evidence'][:80]}"},
            'properties': {'security-severity': SECURITY_SEVERITY[f['severity']], 'severity': f['severity'],
                           'confidence': f['confidence'], 'verification_status': f['verification_status']},
        })
    return {
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'version': '2.1.0',
        'runs': [{'tool': {'driver': {'name': 'security-agent', 'version': __version__,
                                      'informationUri': 'https://github.com/xsmariam/java-security-agent',
                                      'rules': list(rules.values())}},
                  'results': results}],
    }


def write_outputs(data: dict, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(out_dir, 0o700)  # reports may describe weaknesses: keep them private
    except OSError:
        pass
    outputs = {
        'findings.json': json.dumps(data, indent=2, ensure_ascii=False) + '\n',
        'results.sarif': json.dumps(sarif(data), indent=2, ensure_ascii=False) + '\n',
        'audit_summary.txt': summary(data) + '\n',
        'audit_report.html': html_report(data),
    }
    written = []
    for name, value in outputs.items():
        p = out_dir / name
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            fh.write(value)
        written.append(p)
    return written
