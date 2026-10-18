import os
import tempfile
import unittest

from repo_auditor.scanners.secrets import SecretsScanner


class TestSecretsScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = SecretsScanner()
        self.tmpdir = tempfile.mkdtemp()

    def _write(self, name, content):
        path = os.path.join(self.tmpdir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)

    def test_detects_aws_key(self):
        self._write("config.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        findings = self.scanner.scan(self.tmpdir)
        self.assertTrue(any(f["label"] == "AWS access key" for f in findings))

    def test_detects_github_token(self):
        self._write("deploy.sh", 'TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789\n')
        findings = self.scanner.scan(self.tmpdir)
        self.assertTrue(any(f["label"] == "GitHub token" for f in findings))

    def test_detects_private_key(self):
        self._write("key.pem", "-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----\n")
        findings = self.scanner.scan(self.tmpdir)
        self.assertTrue(any(f["label"] == "Private key" for f in findings))

    def test_detects_api_key(self):
        self._write("app.js", 'const apiKey = "sk-abc123def456ghi789jkl012mno345pqr"\n')
        findings = self.scanner.scan(self.tmpdir)
        self.assertTrue(len(findings) > 0)

    def test_clean_file_no_findings(self):
        self._write("main.py", 'print("hello world")\n')
        findings = self.scanner.scan(self.tmpdir)
        self.assertEqual(len(findings), 0)

    def test_skips_binary_extensions(self):
        self._write("bundle.min.js", 'api_key = "AKIAIOSFODNN7EXAMPLE"\n')
        findings = self.scanner.scan(self.tmpdir)
        self.assertEqual(len(findings), 0)

    def test_skips_git_directory(self):
        self._write(".git/config", 'password = "supersecret123"\n')
        findings = self.scanner.scan(self.tmpdir)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
