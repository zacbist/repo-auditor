import os
import tempfile
import unittest

from repo_auditor.scanners.files import FileScanner


class TestFileScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = FileScanner()
        self.tmpdir = tempfile.mkdtemp()

    def test_detects_large_file(self):
        path = os.path.join(self.tmpdir, "big.dat")
        with open(path, "wb") as f:
            f.write(b"\x00" * (6 * 1024 * 1024))
        findings = self.scanner.scan(self.tmpdir)
        large = [f for f in findings if f["type"] == "large_file"]
        self.assertEqual(len(large), 1)

    def test_detects_binary(self):
        path = os.path.join(self.tmpdir, "app.exe")
        with open(path, "wb") as f:
            f.write(b"\x00" * 100)
        findings = self.scanner.scan(self.tmpdir)
        bins = [f for f in findings if f["type"] == "binary_in_repo"]
        self.assertEqual(len(bins), 1)

    def test_normal_file_ok(self):
        path = os.path.join(self.tmpdir, "main.py")
        with open(path, "w") as f:
            f.write("print('hello')\n")
        findings = self.scanner.scan(self.tmpdir)
        self.assertEqual(len(findings), 0)

    def test_skips_git_directory(self):
        git_dir = os.path.join(self.tmpdir, ".git")
        os.makedirs(git_dir)
        path = os.path.join(git_dir, "big.dat")
        with open(path, "wb") as f:
            f.write(b"\x00" * (6 * 1024 * 1024))
        findings = self.scanner.scan(self.tmpdir)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
