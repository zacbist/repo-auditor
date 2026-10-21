import os
import tempfile
import json
import unittest

from repo_auditor.scanners.dependencies import DependencyScanner


class TestDependencyScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = DependencyScanner()
        self.tmpdir = tempfile.mkdtemp()

    def _write(self, name, content):
        path = os.path.join(self.tmpdir, name)
        with open(path, "w") as f:
            f.write(content)

    def test_pinned_requirement_ok(self):
        self._write("requirements.txt", "flask==2.3.0\nrequests>=2.28.0\n")
        findings = self.scanner.scan(self.tmpdir)
        unpinned = [f for f in findings if f["issue"] == "unpinned version"]
        self.assertEqual(len(unpinned), 0)

    def test_unpinned_requirement(self):
        self._write("requirements.txt", "flask\nrequests\n")
        findings = self.scanner.scan(self.tmpdir)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f["issue"] == "unpinned version" for f in findings))

    def test_package_json_wildcard(self):
        pkg = {"dependencies": {"lodash": "*", "express": "^4.18.0"}}
        self._write("package.json", json.dumps(pkg))
        findings = self.scanner.scan(self.tmpdir)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["package"], "lodash")

    def test_package_json_latest(self):
        pkg = {"devDependencies": {"jest": "latest"}}
        self._write("package.json", json.dumps(pkg))
        findings = self.scanner.scan(self.tmpdir)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["package"], "jest")

    def test_no_dependency_files(self):
        findings = self.scanner.scan(self.tmpdir)
        self.assertEqual(len(findings), 0)

    def test_comments_ignored(self):
        self._write("requirements.txt", "# this is a comment\nflask==2.3.0\n")
        findings = self.scanner.scan(self.tmpdir)
        unpinned = [f for f in findings if f["issue"] == "unpinned version"]
        self.assertEqual(len(unpinned), 0)


if __name__ == "__main__":
    unittest.main()
