"""Invoke the GitHub Copilot CLI in a restricted, read-only mode, batch by batch."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import AuditError
from .discovery import AGENT_NAME
from .prompts import build_prompt, retry_suffix
from .validation import extract_json, validate_batch

# Only file viewing/search tools exist for the model; writes, shell, URL fetches and
# memory are additionally denied in case a future CLI version widens defaults.
TOOL_FLAGS = ['--available-tools=view,grep,glob', '--allow-tool=read',
              '--deny-tool=write,shell,url,memory', '--no-ask-user', '--no-auto-update']


def copilot_command(cli: str, prompt: str, model: str | None = None) -> list[str]:
    cmd = [cli, '-p', prompt, '-s', f'--agent={AGENT_NAME}', *TOOL_FLAGS]
    if model:
        cmd.append(f'--model={model}')
    return cmd


@dataclass
class BatchResult:
    files: list[str]
    attempts: int
    findings: list[dict] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)
    unreviewed: list[dict] = field(default_factory=list)
    error: str | None = None


def run_batch(cli: str, snapshot_root: Path, paths: dict[str, Path], batch: list[str], prompt: str, *,
              max_attempts: int = 3, timeout: int = 600, model: str | None = None,
              log: Callable[[str], None] = print) -> BatchResult:
    """A retry is a fresh restricted invocation, never a relaxation of validation."""
    last_error: str | None = None
    for attempt in range(1, max_attempts + 1):
        request = prompt + (retry_suffix(last_error) if last_error else '')
        try:
            result = subprocess.run(copilot_command(cli, request, model), cwd=snapshot_root,
                                    capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            last_error = f'timed out after {timeout}s'
            log(f'  attempt {attempt}/{max_attempts}: {last_error}')
            continue
        if result.returncode != 0:
            # Auth/permission/installation problems will not fix themselves on retry.
            raise AuditError(f'Copilot CLI failed (exit {result.returncode}). Check that it is installed and signed in. '
                             f'{result.stderr.strip()[:300]}')
        try:
            data = extract_json(result.stdout)
            findings, rejected, unreviewed = validate_batch(data, batch, paths)
            return BatchResult(batch, attempt, findings, rejected, unreviewed)
        except AuditError as exc:
            last_error = str(exc)
            log(f'  attempt {attempt}/{max_attempts} rejected: {last_error}')
    return BatchResult(batch, max_attempts, unreviewed=[{'file': f, 'reason': 'batch failed validation'} for f in batch],
                       error=last_error)


def run_audit(cli: str, snapshot_root: Path, paths: dict[str, Path], languages: dict[str, str],
              batches: list[list[str]], *, masked: bool, max_attempts: int = 3, timeout: int = 600,
              model: str | None = None, log: Callable[[str], None] = print) -> list[BatchResult]:
    results = []
    for i, batch in enumerate(batches, 1):
        log(f'Batch {i}/{len(batches)}: {len(batch)} files')
        prompt = build_prompt(batch, languages, batch_index=i, batch_count=len(batches),
                              total_files=len(paths), masked=masked)
        r = run_batch(cli, snapshot_root, paths, batch, prompt, max_attempts=max_attempts,
                      timeout=timeout, model=model, log=log)
        if r.error:
            log(f'  batch {i} could not be validated; its files are reported as unreviewed.')
        else:
            log(f'  {len(r.findings)} verified findings' + (f', {len(r.rejected)} rejected' if r.rejected else ''))
        results.append(r)
    return results
