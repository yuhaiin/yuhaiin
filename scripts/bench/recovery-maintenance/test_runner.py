import unittest

from run import redact_journal


class RecoveryDiagnosticsTests(unittest.TestCase):
    def test_clone_bootstrap_capabilities_are_redacted_with_journal_prefixes(self):
        raw = ('Oct 27 yuhaiin[123]: Initialization code: synthetic-capability\n'
               'TLS certificate SHA-256 fingerprint: public-fingerprint\n'
               'Initialization code: another-capability\r\n')
        result = redact_journal(raw)
        self.assertNotIn('synthetic-capability', result)
        self.assertNotIn('another-capability', result)
        self.assertEqual(result.count('[redacted]'), 2)
        self.assertIn('public-fingerprint', result)


if __name__ == '__main__':
    unittest.main()
