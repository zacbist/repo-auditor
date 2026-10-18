import os
import tempfile
import unittest

from repo_auditor.auditor import run_audit, summarize


class TestAuditor(unittest.TestCase):
    def test_run_audit_clean_repo(self):
        tmpdir = tempfile.mkdtemp()
        with open(os.path.join(tmpdir, "LICENSE"), "w") as f:
            f.write("MIT\n")
        with open(os.path.join(tmpdir, "main.py"), "w") as f:
            f.write("print('hello')\n")

        results = run_audit(tmpdir)
        self.assertIn("secrets", results)
        self.assertIn("dependencies", results)
        self.assertIn("files", results)
        self.assertIn("license", results)
        self.assertIn("config", results)

    def test_summarize(self):
        results = {
            "secrets": [{"severity": "high"}, {"severity": "high"}],
            "files": [{"severity": "medium"}],
            "license": [{"found": True}],
        }
        summary = summarize(results)
        self.assertEqual(summary["high"], 2)
        self.assertEqual(summary["medium"], 1)
        self.assertEqual(summary["total"], 4)

    def test_run_audit_with_issues(self):
        tmpdir = tempfile.mkdtemp()
        with open(os.path.join(tmpdir, ".env"), "w") as f:
            f.write("SECRET=abc\n")
        with open(os.path.join(tmpdir, "requirements.txt"), "w") as f:
            f.write("flask\n")

        results = run_audit(tmpdir)
        summary = summarize(results)
        self.assertGreater(summary["total"], 0)


if __name__ == "__main__":
    unittest.main()
