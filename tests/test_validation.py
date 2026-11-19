import unittest

from helpers import VULNSHOP, finding, line_of
from security_agent import AuditError
from security_agent.discovery import discover
from security_agent.risk_policy import assess_finding
from security_agent.secrets import find_secrets, mask_source, redact
from security_agent.validation import assign_ids, deduplicate, extract_json, validate_batch

DIAG = 'src/main/java/com/vulnshop/web/DiagnosticsHandler.java'


class ValidationTests(unittest.TestCase):
    def setUp(self):
        inv = discover(VULNSHOP)
        self.paths = {r: f.path for r, f in inv.files.items()}
        self.assigned = list(self.paths)
        self.line = line_of(self.paths[DIAG], '/bin/sh')

    def response(self, *findings):
        return {'files_reviewed': list(self.assigned), 'unreviewed_files': [], 'findings': list(findings)}

    def test_valid_finding_kept(self):
        found, rejected, _ = validate_batch(self.response(finding(DIAG, self.line, '/bin/sh')), self.assigned, self.paths)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['severity'], 'Critical')
        self.assertEqual(rejected, [])

    def test_bad_findings_dropped_individually(self):
        good = finding(DIAG, self.line, '/bin/sh')
        bad_line = finding(DIAG, 9999, '/bin/sh', title='bad line')
        bad_evidence = finding(DIAG, self.line, 'fabricated attack path', title='bad evidence')
        bad_file = finding('src/Nope.java', 1, 'x', title='bad file')
        found, rejected, _ = validate_batch(self.response(good, bad_line, bad_evidence, bad_file), self.assigned, self.paths)
        self.assertEqual([f['title'] for f in found], ['OS command injection'])
        self.assertEqual({r['title'] for r in rejected}, {'bad line', 'bad evidence', 'bad file'})

    def test_coverage_gap_is_structural(self):
        data = self.response()
        data['files_reviewed'].pop()
        with self.assertRaisesRegex(AuditError, 'exactly once'):
            validate_batch(data, self.assigned, self.paths)

    def test_unreviewed_with_reason_accepted(self):
        data = self.response()
        last = data['files_reviewed'].pop()
        data['unreviewed_files'] = [{'file': last, 'reason': 'too large'}]
        _, _, unreviewed = validate_batch(data, self.assigned, self.paths)
        self.assertEqual(unreviewed, [{'file': last, 'reason': 'too large'}])

    def test_policy_overrides_model_severity(self):
        f = finding(DIAG, self.line, '/bin/sh', severity='Low')
        found, _, _ = validate_batch(self.response(f), self.assigned, self.paths)
        self.assertEqual(found[0]['severity'], 'Critical')
        self.assertEqual(found[0]['model_severity'], 'Low')

    def test_dedupe_and_ids(self):
        f = validate_batch(self.response(finding(DIAG, self.line, '/bin/sh')), self.assigned, self.paths)[0][0]
        result = assign_ids(deduplicate([f, dict(f)]))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['id'], 'F001')

    def test_extract_json_variants(self):
        self.assertEqual(extract_json('{"a": 1}'), {'a': 1})
        self.assertEqual(extract_json('```json\n{"a": 1}\n```'), {'a': 1})
        self.assertEqual(extract_json('Sure! {"a": 1} done.'), {'a': 1})
        with self.assertRaises(AuditError):
            extract_json('no json here')


class RiskTests(unittest.TestCase):
    def f(self, status='source-supported', e=3, x=3, i=3, cwe='CWE-78'):
        return {'cwe': cwe, 'verification_status': status,
                'risk': {'exposure': e, 'exploitability': x, 'impact': i,
                         'rationale': 'Scored from the visible data flow.',
                         'assumptions': '' if status == 'source-supported' else 'Deployment not visible.'}}

    def test_boundaries_and_caps(self):
        self.assertEqual(assess_finding(self.f())['severity'], 'Critical')
        self.assertEqual(assess_finding(self.f(e=1, x=1, i=0))['severity'], 'Low')
        self.assertEqual(assess_finding(self.f(e=2, x=2, i=1))['severity'], 'Medium')
        self.assertEqual(assess_finding(self.f(e=2, x=2, i=2))['severity'], 'High')
        self.assertEqual(assess_finding(self.f('conditional'))['severity'], 'High')
        self.assertEqual(assess_finding(self.f('requires-review'))['severity'], 'Medium')

    def test_xss_no_longer_artificially_capped(self):
        self.assertEqual(assess_finding(self.f(cwe='CWE-79'))['severity'], 'Critical')

    def test_password_storage_floor(self):
        self.assertEqual(assess_finding(self.f(e=1, x=1, i=2, cwe='CWE-916'))['severity'], 'High')
        self.assertEqual(assess_finding(self.f('requires-review', 1, 1, 2, 'CWE-916'))['severity'], 'Medium')

    def test_assumptions_required_when_uncertain(self):
        f = self.f('conditional')
        f['risk']['assumptions'] = ''
        with self.assertRaises(ValueError):
            assess_finding(f)


class SecretTests(unittest.TestCase):
    def test_languages(self):
        src = ('password = "hunter22x"\nconst apiKey = \'k-123456\'\n"client_secret": "abcd1234"\n'
               'token := "tok_998877"\nos.environ["SECRET"]\nkey = AKIAABCDEFGHIJKLMNOP\npassword = "changeme"\n')
        secrets = find_secrets(src)
        self.assertTrue({'hunter22x', 'k-123456', 'abcd1234', 'tok_998877', 'AKIAABCDEFGHIJKLMNOP'} <= secrets)
        self.assertNotIn('changeme', secrets)
        masked, n = mask_source(src)
        self.assertEqual(n, 5)
        self.assertNotIn('hunter22x', masked)
        self.assertEqual(len(masked.splitlines()), len(src.splitlines()))

    def test_redact_nested(self):
        out = redact({'a': ['x hunter22x y'], 'b': {'c': 'hunter22x'}}, {'hunter22x'})
        self.assertEqual(out, {'a': ['x [REDACTED] y'], 'b': {'c': '[REDACTED]'}})


if __name__ == '__main__':
    unittest.main()
