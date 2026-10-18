import os

from .base import BaseScanner

LARGE_FILE_THRESHOLD = 5 * 1024 * 1024

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".dat",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".db", ".sqlite", ".sqlite3",
}


class FileScanner(BaseScanner):
    name = "files"

    def scan(self, repo_path):
        findings = []
        for root, _, files in os.walk(repo_path):
            if ".git" in root.split(os.sep):
                continue
            for fname in files:
                fpath = os.path.join(root, fname)
                relpath = os.path.relpath(fpath, repo_path)
                try:
                    size = os.path.getsize(fpath)
                except OSError:
                    continue

                if size > LARGE_FILE_THRESHOLD:
                    findings.append({
                        "type": "large_file",
                        "severity": "medium",
                        "file": relpath,
                        "size_mb": round(size / 1024 / 1024, 2),
                    })

                ext = os.path.splitext(fname)[1].lower()
                if ext in BINARY_EXTENSIONS:
                    findings.append({
                        "type": "binary_in_repo",
                        "severity": "low",
                        "file": relpath,
                        "size_mb": round(size / 1024 / 1024, 2),
                    })
        return findings
