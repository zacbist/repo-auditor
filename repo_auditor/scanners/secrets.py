import os
import re

from .base import BaseScanner

PATTERNS = [
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?[\w\-]{20,}', "API key"),
    (r'(?:secret|password|passwd|pwd)\s*[:=]\s*["\']?[^\s"\']{8,}', "Hardcoded secret"),
    (r'AKIA[0-9A-Z]{16}', "AWS access key"),
    (r'ghp_[A-Za-z0-9]{36}', "GitHub token"),
    (r'sk-[A-Za-z0-9]{32,}', "OpenAI/Stripe secret key"),
    (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "Private key"),
    (r'xox[bporas]-[A-Za-z0-9\-]{10,}', "Slack token"),
    (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', "JWT token"),
]

SKIP_EXTENSIONS = {".min.js", ".map", ".lock", ".svg", ".png", ".jpg", ".gif", ".woff", ".ttf"}


class SecretsScanner(BaseScanner):
    name = "secrets"

    def scan(self, repo_path):
        findings = []
        for root, _, files in os.walk(repo_path):
            if ".git" in root.split(os.sep):
                continue
            for fname in files:
                if any(fname.endswith(ext) for ext in SKIP_EXTENSIONS):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        for i, line in enumerate(f, 1):
                            for pattern, label in PATTERNS:
                                if re.search(pattern, line, re.IGNORECASE):
                                    findings.append({
                                        "type": "secret",
                                        "severity": "high",
                                        "file": os.path.relpath(fpath, repo_path),
                                        "line": i,
                                        "label": label,
                                    })
                except (OSError, UnicodeDecodeError):
                    continue
        return findings
