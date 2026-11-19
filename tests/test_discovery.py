import tempfile
import unittest
from pathlib import Path

from helpers import VULNSHOP
from security_agent import AuditError
from security_agent.discovery import build_snapshot, digests, discover, make_batches


def write(root: Path, rel: str, content, binary=False):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    (p.write_bytes if binary else p.write_text)(content)


class DiscoveryTests(unittest.TestCase):
    def test_vulnshop_java_files(self):
        inv = discover(VULNSHOP)
        self.assertEqual(len(inv.files), 19)
        self.assertEqual(inv.languages(), {'java': 19})

    def test_multi_language_and_never_send(self):
        with tempfile.TemporaryDirectory() as t:
            r = Path(t)
            write(r, 'app/main.py', 'import os\n')
            write(r, 'web/index.ts', 'export const x = 1\n')
            write(r, 'svc/handler.go', 'package svc\n')
            write(r, 'node_modules/lib/index.js', 'x\n')
            write(r, '.env', 'API_KEY=abc\n')
            write(r, 'certs/server.pem', '-----BEGIN PRIVATE KEY-----\n')
            write(r, 'config/app.yml', 'debug: true\n')
            write(r, 'blob.py', b'\x00\x01\x02', binary=True)
            inv = discover(r)
            self.assertEqual(set(inv.files), {'app/main.py', 'web/index.ts', 'svc/handler.go'})
            self.assertIn(('blob.py', 'binary content'), inv.skipped)
            inv2 = discover(r, include_config=True)
            self.assertIn('config/app.yml', inv2.files)
            self.assertNotIn('.env', inv2.files)
            self.assertTrue(any(rel == '.env' for rel, _ in inv2.skipped))
            inv3 = discover(r, languages={'python'})
            self.assertEqual(set(inv3.files), {'app/main.py'})
            inv4 = discover(r, exclude=['web/*'])
            self.assertNotIn('web/index.ts', inv4.files)

    def test_empty_repo_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(AuditError):
                discover(Path(t))

    def test_snapshot_masks_secrets_and_preserves_lines(self):
        inv = discover(VULNSHOP)
        before = digests({r: f.path for r, f in inv.files.items()})
        with tempfile.TemporaryDirectory() as t:
            snap = build_snapshot(inv, Path(t))
            cfg = 'src/main/java/com/vulnshop/config/AppConfig.java'
            masked = snap.paths[cfg].read_text()
            self.assertNotIn('Sup3rS3cret!2024', masked)
            self.assertIn('DB_PASSWORD = "REDACTED_SECRET"', masked)
            self.assertIn('System.getenv("SMTP_PASSWORD")', masked)  # env lookup is not a secret
            self.assertEqual(len(masked.splitlines()), len(inv.files[cfg].path.read_text().splitlines()))
            self.assertIn('Sup3rS3cret!2024', snap.secrets)
            self.assertTrue((Path(t) / '.github/agents/security-auditor.agent.md').exists())
        self.assertEqual(before, digests({r: f.path for r, f in inv.files.items()}))

    def test_batches_cover_every_file_once(self):
        inv = discover(VULNSHOP)
        batches = make_batches(inv, max_files=5)
        flat = [f for b in batches for f in b]
        self.assertEqual(sorted(flat), sorted(inv.files))
        self.assertTrue(all(len(b) <= 5 for b in batches))


if __name__ == '__main__':
    unittest.main()
