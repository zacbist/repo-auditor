import os
import tempfile
import unittest

from repo_auditor.scanners.license import LicenseScanner


class TestLicenseScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = LicenseScanner()
        self.tmpdir = tempfile.mkdtemp()

    def test_finds_license(self):
        with open(os.path.join(self.tmpdir, "LICENSE"), "w") as f:
            f.write("MIT License\n")
        findings = self.scanner.scan(self.tmpdir)
        self.assertTrue(findings[0]["found"])

    def test_finds_license_md(self):
        with open(os.path.join(self.tmpdir, "LICENSE.md"), "w") as f:
            f.write("# MIT\n")
        findings = self.scanner.scan(self.tmpdir)
        self.assertTrue(findings[0]["found"])

    def test_missing_license(self):
        findings = self.scanner.scan(self.tmpdir)
        self.assertFalse(findings[0]["found"])
        self.assertEqual(findings[0]["severity"], "medium")


if __name__ == "__main__":
    unittest.main()
