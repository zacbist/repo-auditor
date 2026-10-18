import os
import tempfile
import unittest

from repo_auditor.scanners.config import ConfigScanner


class TestConfigScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = ConfigScanner()
        self.tmpdir = tempfile.mkdtemp()

    def test_detects_env_file(self):
        path = os.path.join(self.tmpdir, ".env")
        with open(path, "w") as f:
            f.write("SECRET=abc\n")
        findings = self.scanner.scan(self.tmpdir)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")

    def test_detects_credentials_json(self):
        path = os.path.join(self.tmpdir, "credentials.json")
        with open(path, "w") as f:
            f.write("{}\n")
        findings = self.scanner.scan(self.tmpdir)
        self.assertEqual(len(findings), 1)

    def test_detects_npmrc(self):
        path = os.path.join(self.tmpdir, ".npmrc")
        with open(path, "w") as f:
            f.write("//registry.npmjs.org/:_authToken=abc\n")
        findings = self.scanner.scan(self.tmpdir)
        self.assertEqual(len(findings), 1)

    def test_clean_repo(self):
        path = os.path.join(self.tmpdir, "main.py")
        with open(path, "w") as f:
            f.write("print('ok')\n")
        findings = self.scanner.scan(self.tmpdir)
        self.assertEqual(len(findings), 0)

    def test_nested_sensitive_file(self):
        nested = os.path.join(self.tmpdir, "config")
        os.makedirs(nested)
        path = os.path.join(nested, ".env")
        with open(path, "w") as f:
            f.write("DB_PASS=x\n")
        findings = self.scanner.scan(self.tmpdir)
        self.assertEqual(len(findings), 1)


if __name__ == "__main__":
    unittest.main()
