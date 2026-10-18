import os

from .base import BaseScanner

SENSITIVE_FILES = [
    ".env", ".env.local", ".env.production", ".env.staging",
    "credentials.json", "service-account.json",
    ".npmrc", ".pypirc", ".netrc",
    "id_rsa", "id_ed25519", "id_ecdsa",
    ".htpasswd", "shadow",
]


class ConfigScanner(BaseScanner):
    name = "config"

    def scan(self, repo_path):
        findings = []
        for root, _, files in os.walk(repo_path):
            if ".git" in root.split(os.sep):
                continue
            for fname in files:
                if fname in SENSITIVE_FILES:
                    findings.append({
                        "type": "sensitive_file",
                        "severity": "high",
                        "file": os.path.relpath(os.path.join(root, fname), repo_path),
                    })
        return findings
