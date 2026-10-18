import json
import os
import subprocess
import sys
import unittest


class TestIntegration(unittest.TestCase):
    def test_audit_remote_repo(self):
        result = subprocess.run(
            [sys.executable, "run.py", "https://github.com/zacbist/git-templates.git"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0)

        self.assertTrue(os.path.isfile("report.json"))
        with open("report.json") as f:
            report = json.load(f)

        self.assertIn("url", report)
        self.assertIn("summary", report)
        self.assertIn("results", report)
        self.assertIsInstance(report["summary"]["total"], int)


if __name__ == "__main__":
    unittest.main()
