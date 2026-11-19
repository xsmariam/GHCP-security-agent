#!/usr/bin/env python3
"""Evidence-validated, read-only AI security review of a source repository.

Uses the GitHub Copilot CLI as the reviewer. Python standard library only.

Exit codes: 0 success | 1 error | 2 findings at/above --fail-on | 3 incomplete coverage
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from security_agent import AuditError, __version__
from security_agent.discovery import build_snapshot, digests, discover, make_batches
from security_agent.languages import LANGUAGE_LABELS
from security_agent.reports import summary, write_outputs
from security_agent.risk_policy import SEVERITIES, at_or_above
from security_agent.runner import run_audit
from security_agent.secrets import redact
from security_agent.validation import assign_ids, deduplicate

ROOT = Path(__file__).resolve().parent


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description='Read-only, evidence-validated AI security review of a code repository via GitHub Copilot CLI.')
    p.add_argument('repo', nargs='?', type=Path, help='Path to the repository to review')
    p.add_argument('--repo', dest='repo_opt', type=Path, help=argparse.SUPPRESS)  # backward compatible
    p.add_argument('--output', type=Path, default=Path.cwd() / 'security-audit-output',
                   help='Report folder (must be outside the target repo). Default: ./security-audit-output')
    p.add_argument('--check', action='store_true', help='List what would be reviewed; no AI call')
    p.add_argument('--yes', action='store_true', help='Approve sending the selected source to GitHub Copilot without a prompt')
    p.add_argument('--languages', help='Comma list to limit review, e.g. java,python,javascript')
    p.add_argument('--exclude', action='append', default=[], metavar='GLOB',
                   help='Skip matching paths, e.g. --exclude "**/test/**" (repeatable)')
    p.add_argument('--include-config', action='store_true',
                   help='Also review config/IaC files (YAML, XML, properties, Dockerfile, Terraform, ...)')
    p.add_argument('--no-mask-secrets', action='store_true',
                   help='Send secret literal values unmasked (NOT recommended)')
    p.add_argument('--fail-on', choices=['none', *SEVERITIES], default='none',
                   help='Exit with code 2 if any finding is at or above this severity (for CI)')
    p.add_argument('--batch-files', type=int, default=40, help='Max files per model request (default 40)')
    p.add_argument('--batch-bytes', type=int, default=250_000, help='Max source bytes per model request')
    p.add_argument('--max-files', type=int, default=2000, help='Refuse to scan more files than this')
    p.add_argument('--max-attempts', type=int, default=3, help='Attempts per batch when output fails validation')
    p.add_argument('--timeout', type=int, default=600, help='Seconds per model request (default 600)')
    p.add_argument('--model', help='Copilot model to use (passed to copilot --model)')
    p.add_argument('--copilot-bin', default='copilot', help=argparse.SUPPRESS)
    p.add_argument('--version', action='version', version=f'security-agent {__version__}')
    args = p.parse_args(argv)
    args.repo = args.repo or args.repo_opt
    if args.repo is None:
        p.error('give the repository to review, e.g.  python3 run_analysis.py path/to/repo')
    for name in ('batch_files', 'batch_bytes', 'max_files', 'max_attempts', 'timeout'):
        if getattr(args, name) < 1:
            p.error(f'--{name.replace("_", "-")} must be positive')
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        repo = args.repo.resolve()
        out = args.output.resolve()
        if out == repo or repo in out.parents:
            raise AuditError('--output must be outside the target repository so the source stays untouched')
        langs = {l.strip().lower() for l in args.languages.split(',')} if args.languages else None
        inv = discover(repo, include_config=args.include_config, languages=langs, exclude=args.exclude,
                       max_files=args.max_files)
        batches = make_batches(inv, args.batch_files, args.batch_bytes)
        lang_text = ', '.join(f'{LANGUAGE_LABELS.get(k, k)} {v}' for k, v in inv.languages().items())
        cli = shutil.which(args.copilot_bin)
        if cli:
            cli = str(Path(cli).resolve())  # the CLI runs from inside the snapshot folder
        print(f'Repository: {repo.name} | {len(inv.files)} files ({inv.total_bytes / 1024:.0f} KB) | {lang_text}')
        print(f'Model requests: {len(batches)} batch(es) | Copilot CLI: {cli or "not found"}')
        if inv.skipped:
            print(f'Skipped {len(inv.skipped)} files (never sent):')
            for rel, reason in inv.skipped[:15]:
                print(f'  - {rel}: {reason}')
            if len(inv.skipped) > 15:
                print(f'  ... and {len(inv.skipped) - 15} more')
        if args.check:
            for rel, f in inv.files.items():
                print(f'  {f.language:<11} {rel}')
            print('Check complete. No AI request made, nothing changed.')
            return 0
        if not cli:
            raise AuditError('GitHub Copilot CLI not found. Install it and sign in, then run with --check.')

        hashes_before = digests({r: f.path for r, f in inv.files.items()})
        if not args.yes:
            print(f'\nThis will send {len(inv.files)} files to the GitHub Copilot service for review '
                  f'({"secret values masked first" if not args.no_mask_secrets else "SECRETS NOT MASKED"}).')
            print(f'Up to {args.max_attempts} read-only attempts per batch. No files are edited, run or emailed.')
            if input('Type ANALYZE to approve: ').strip() != 'ANALYZE':
                raise AuditError('Not approved; nothing was sent.')

        with tempfile.TemporaryDirectory(prefix='security-audit-') as temp:
            snap = build_snapshot(inv, Path(temp), mask_secrets=not args.no_mask_secrets)
            if snap.masked_count:
                print(f'Masked {snap.masked_count} secret value(s) before upload.')
            languages = {r: f.language for r, f in inv.files.items()}
            results = run_audit(cli, snap.root, snap.paths, languages, batches, masked=not args.no_mask_secrets,
                                max_attempts=args.max_attempts, timeout=args.timeout, model=args.model)
            if digests({r: f.path for r, f in inv.files.items()}) != hashes_before:
                raise AuditError('Source files changed during the scan; results discarded. Re-run on a stable checkout.')
            secrets = snap.secrets

        findings = assign_ids(deduplicate([f for r in results for f in r.findings]))
        unreviewed = [u for r in results for u in r.unreviewed]
        data = {
            'tool': {'name': 'security-agent', 'version': __version__, 'reviewer': 'GitHub Copilot CLI',
                     'model': args.model or 'default', 'scan_mode': 'ai-only'},
            'repository': repo.name,
            'generated_at_utc': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'languages': inv.languages(),
            'coverage': {'total': len(inv.files), 'reviewed': len(inv.files) - len(unreviewed),
                         'unreviewed': unreviewed, 'skipped': [{'file': r, 'reason': why} for r, why in inv.skipped]},
            'findings': findings,
            'rejected_findings': [x for r in results for x in r.rejected],
            'batches': [{'files': len(r.files), 'attempts': r.attempts, 'error': r.error} for r in results],
        }
        data = redact(data, secrets)  # never write a secret value to disk, even if the model echoed one
        written = write_outputs(data, out)
        print('\n' + summary(data))
        print('\nReports:\n' + '\n'.join(f'  {p}' for p in written))
        if args.fail_on != 'none' and any(at_or_above(f['severity'], args.fail_on) for f in findings):
            return 2
        return 3 if unreviewed else 0
    except (AuditError, OSError, UnicodeError, subprocess.SubprocessError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('\nCancelled.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
