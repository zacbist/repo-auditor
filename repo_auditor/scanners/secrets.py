import os
import re

import chardet
import structlog
from dotenv import dotenv_values

from .base import BaseScanner

log = structlog.get_logger()

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


def detect_encoding(filepath):
    with open(filepath, "rb") as f:
        raw = f.read(8192)
    result = chardet.detect(raw)
    return result.get("encoding") or "utf-8"


class SecretsScanner(BaseScanner):
    name = "secrets"

    def scan(self, repo_path):
        findings = []
        findings.extend(self._scan_files(repo_path))
        findings.extend(self._scan_dotenv(repo_path))
        return findings

    def _scan_files(self, repo_path):
        findings = []
        for root, _, files in os.walk(repo_path):
            if ".git" in root.split(os.sep):
                continue
            for fname in files:
                if any(fname.endswith(ext) for ext in SKIP_EXTENSIONS):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    encoding = detect_encoding(fpath)
                    with open(fpath, "r", encoding=encoding, errors="ignore") as f:
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

    def _scan_dotenv(self, repo_path):
        findings = []
        for name in (".env", ".env.local", ".env.production", ".env.staging"):
            env_path = os.path.join(repo_path, name)
            if not os.path.isfile(env_path):
                continue
            log.info("dotenv.found", file=name)
            try:
                values = dotenv_values(env_path)
                for key, val in values.items():
                    if val and any(s in key.upper() for s in ("SECRET", "KEY", "TOKEN", "PASSWORD", "CREDENTIAL")):
                        findings.append({
                            "type": "secret",
                            "severity": "high",
                            "file": name,
                            "label": f"exposed env var: {key}",
                        })
            except OSError:
                continue
        return findings
