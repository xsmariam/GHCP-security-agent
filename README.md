# Security Agent: evidence-validated AI code review

A command-line tool that finds security vulnerabilities in a code repository. It uses the **GitHub Copilot CLI** as the reviewer, in a locked-down, read-only mode, and then **checks every claim the AI makes against the real source** before reporting it. Findings that cite a wrong file, wrong line, or code that isn't there are thrown out.

Works on Java/Kotlin, Python, JavaScript/TypeScript, Go, C#, PHP, Ruby, C/C++, Rust, Swift, shell, SQL and HTML, plus optional config/infrastructure files (YAML, XML, Dockerfile, Terraform, ...). Python standard library only; no dependencies.

## Quick start

```bash
# 1. Requirements: Python 3.10+, GitHub Copilot CLI installed and signed in
python3 --version
copilot --help          # install: https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli

# 2. See what would be reviewed (no AI call, nothing sent)
python3 run_analysis.py path/to/your/repo --check

# 3. Run the review (asks you to type ANALYZE before sending code)
python3 run_analysis.py path/to/your/repo

# Try it on the included intentionally vulnerable app
python3 run_analysis.py examples/vulnshop
```

Reports are written to `./security-audit-output/` (must be outside the repo being scanned):

| File | Use |
|---|---|
| `audit_report.html` | Readable report: severity counts, findings table, details with evidence, coverage gaps |
| `findings.json` | Full structured results |
| `results.sarif` | Standard SARIF 2.1.0: upload to GitHub code scanning or open with the VS Code SARIF Viewer |
| `audit_summary.txt` | Short terminal summary |

## Useful options

| Option | What it does |
|---|---|
| `--languages java,python` | Only review these languages |
| `--exclude "**/test/**"` | Skip paths matching a glob (repeatable) |
| `--include-config` | Also review config and infrastructure files |
| `--fail-on High` | Exit code 2 if any finding is High or worse (for CI pipelines) |
| `--model NAME` | Choose the Copilot model |
| `--batch-files`, `--batch-bytes` | How much code goes into each AI request (default 40 files / 250 KB) |
| `--timeout`, `--max-attempts` | Per-request time limit and retries |
| `--yes` | Skip the approval prompt (e.g. in CI) |

Exit codes: `0` success · `1` error · `2` findings at/above `--fail-on` · `3` some files could not be reviewed.

## How it works

1. **Discover**: finds source files (respects `.gitignore` in git repos) and skips dependencies and build output (`node_modules`, `vendor`, `target`, `dist`, ...). It never sends `.env` files, private keys, certificates, lock files, minified bundles or anything named like an answer key.
2. **Isolate and mask**: copies only the selected files to a temporary folder. **Secret values (passwords, API keys, tokens, private keys) are replaced with `REDACTED_SECRET` before anything leaves your machine.** Line numbers are kept, so hardcoded-secret findings still work.
3. **Review in batches**: large repos are split into batches. Each batch is a separate Copilot request. The model can only view/search files: writing, shell, URL fetching and memory are disabled. Prompts are built from editable checklists in `prompts/` (a general one plus one for each language).
4. **Validate**: the program checks every response:
   - Every assigned file must be marked reviewed or unreviewed. If not, the request is retried.
   - Each finding must point to a real file and line range, and its `evidence` must be an exact copy of the code on those lines. Findings that fail are **discarded** (and listed in the report so you can look manually). The rest are kept.
   - Severity is **computed by the program** from the model's 0-3 exposure / exploitability / impact scores (see `prompts/risk_rubric.md`), not taken from the model.
5. **Report**: removes duplicates, assigns IDs, redacts any secret value that slipped into the output, and writes private (owner-only) report files. A hash check confirms the original source was not changed.

## Safety properties

- Source is read only: never edited, compiled, executed or committed.
- Code goes to GitHub Copilot only after you approve, with secrets masked first (`--no-mask-secrets` turns masking off; not recommended).
- Repository content is treated as untrusted. Prompts tell the model to ignore instructions found in code (prompt injection), and the validator ignores anything it can't verify.
- **Limitations:** this is an AI-assisted static review. A verified finding proves the quoted code exists at that location, *not* that it is exploitable. The AI can also miss issues. A person should confirm findings before acting on them, and this is not a replacement for SAST/DAST tools, dependency scanning, or a penetration test.

## Project layout

```
run_analysis.py           command-line entry point
security_agent/           discovery, secret masking, Copilot runner, validation, risk policy, reports
prompts/                  editable review instructions (general + prompts/languages/*.md)
examples/vulnshop/        intentionally vulnerable Java app for trying the tool
evaluate_baseline.py      score a run against a separately stored answer key
tests/                    unit + end-to-end tests (use a fake Copilot CLI; no network)
```

Run the tests with `python3 -m unittest discover -s tests` (or `python3 -m pytest tests`).

## Measuring accuracy

Keep the answer key **outside** this project so the AI can never read it, then:

```bash
python3 evaluate_baseline.py --key ../vulnshop-eval/answer_key.csv --findings security-audit-output/findings.json
```

This reports recall and severity agreement. Unmatched findings are not automatically false positives; review them by hand.

## Adding a language or tuning detection

Add `prompts/languages/<name>.md` and map file extensions to `<name>` in `security_agent/languages.py`. Checklists are plain markdown, so you can improve detection without changing code.
