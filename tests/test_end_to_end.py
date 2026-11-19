"""Full CLI runs against a fake Copilot binary (no network, no real AI)."""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch

from helpers import FAKE_COPILOT, VULNSHOP, finding, line_of
import run_analysis
from security_agent.discovery import digests, discover
from security_agent.runner import run_batch


class EndToEndTests(unittest.TestCase):
    def run_cli(self, *extra):
        out = tempfile.mkdtemp()
        log = Path(out) / 'calls.log'
        os.environ['FAKE_COPILOT_LOG'] = str(log)
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            code = run_analysis.main([str(VULNSHOP), '--yes', '--output', str(Path(out) / 'report'),
                                      '--copilot-bin', str(FAKE_COPILOT), *extra])
        return code, Path(out) / 'report', buf.getvalue() + err.getvalue(), log

    def setUp(self):
        FAKE_COPILOT.chmod(0o755)
        self.before = digests({r: f.path for r, f in discover(VULNSHOP).files.items()})

    def tearDown(self):
        self.assertEqual(self.before, digests({r: f.path for r, f in discover(VULNSHOP).files.items()}),
                         'source files must never change')

    def test_full_run(self):
        code, report, output, log = self.run_cli('--batch-files', '7')
        self.assertEqual(code, 0, output)
        data = json.loads((report / 'findings.json').read_text())
        titles = sorted(f['title'] for f in data['findings'])
        self.assertEqual(titles, ['Hardcoded database password', 'OS command injection'])
        self.assertEqual(len(data['batches']), 3)
        self.assertEqual(len(data['rejected_findings']), 3)  # one invented finding per batch
        self.assertEqual(data['coverage']['reviewed'], 19)
        for name in ('findings.json', 'results.sarif', 'audit_summary.txt', 'audit_report.html'):
            text = (report / name).read_text()
            self.assertNotIn('Sup3rS3cret!2024', text, f'secret leaked into {name}')
            self.assertEqual(os.stat(report / name).st_mode & 0o777, 0o600)
        sarif = json.loads((report / 'results.sarif').read_text())
        self.assertEqual(sarif['version'], '2.1.0')
        self.assertEqual(len(sarif['runs'][0]['results']), 2)
        for call in log.read_text().splitlines():
            args = json.loads(call)
            self.assertIn('--deny-tool=write,shell,url,memory', args)
            self.assertIn('--available-tools=view,grep,glob', args)
            self.assertNotIn('--allow-all', args)

    def test_fail_on_exit_code(self):
        code, _, _, _ = self.run_cli('--fail-on', 'High')
        self.assertEqual(code, 2)

    def test_check_mode_makes_no_call(self):
        code, report, output, log = self.run_cli('--check')
        self.assertEqual(code, 0)
        self.assertFalse(log.exists())
        self.assertFalse(report.exists())
        self.assertIn('19 files', output)

    def test_output_inside_repo_refused(self):
        buf = io.StringIO()
        with redirect_stderr(buf), redirect_stdout(io.StringIO()):
            code = run_analysis.main([str(VULNSHOP), '--check', '--output', str(VULNSHOP / 'out')])
        self.assertEqual(code, 1)
        self.assertIn('outside', buf.getvalue())


class RetryTests(unittest.TestCase):
    def setUp(self):
        self.paths = {r: f.path for r, f in discover(VULNSHOP).files.items()}
        self.batch = list(self.paths)
        diag = 'src/main/java/com/vulnshop/web/DiagnosticsHandler.java'
        self.good = {'files_reviewed': self.batch, 'unreviewed_files': [],
                     'findings': [finding(diag, line_of(self.paths[diag], '/bin/sh'), '/bin/sh')]}

    def reply(self, obj, code=0):
        return type('R', (), {'returncode': code, 'stdout': obj if isinstance(obj, str) else json.dumps(obj), 'stderr': 'boom'})

    def test_structural_failure_retries_then_succeeds(self):
        bad = dict(self.good, files_reviewed=self.batch[:-1])
        with patch('security_agent.runner.subprocess.run', side_effect=[self.reply('not json'), self.reply(bad), self.reply(self.good)]) as m:
            r = run_batch('copilot', VULNSHOP, self.paths, self.batch, 'PROMPT', log=lambda s: None)
        self.assertEqual(r.attempts, 3)
        self.assertEqual(len(r.findings), 1)
        self.assertIn('PREVIOUS RESPONSE FAILED LOCAL VALIDATION', m.call_args_list[1].args[0][2])

    def test_timeout_then_exhausted_marks_unreviewed(self):
        effects = [subprocess.TimeoutExpired('copilot', 1), self.reply('nope'), self.reply('nope')]
        with patch('security_agent.runner.subprocess.run', side_effect=effects):
            r = run_batch('copilot', VULNSHOP, self.paths, self.batch, 'PROMPT', log=lambda s: None)
        self.assertIsNotNone(r.error)
        self.assertEqual(len(r.unreviewed), len(self.batch))

    def test_cli_error_is_fatal(self):
        from security_agent import AuditError
        with patch('security_agent.runner.subprocess.run', return_value=self.reply('', code=1)):
            with self.assertRaises(AuditError):
                run_batch('copilot', VULNSHOP, self.paths, self.batch, 'PROMPT', log=lambda s: None)


if __name__ == '__main__':
    unittest.main()
