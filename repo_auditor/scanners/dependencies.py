import json
import os

from .base import BaseScanner


class DependencyScanner(BaseScanner):
    name = "dependencies"

    def scan(self, repo_path):
        findings = []
        findings.extend(self._check_requirements(repo_path))
        findings.extend(self._check_package_json(repo_path))
        findings.extend(self._check_pipfile(repo_path))
        return findings

    def _check_requirements(self, repo_path):
        findings = []
        req_file = os.path.join(repo_path, "requirements.txt")
        if not os.path.isfile(req_file):
            return findings
        with open(req_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                if "==" not in line and ">=" not in line and "<=" not in line:
                    findings.append({
                        "type": "dependency",
                        "severity": "low",
                        "source": "requirements.txt",
                        "package": line.split("[")[0],
                        "issue": "unpinned version",
                    })
        return findings

    def _check_package_json(self, repo_path):
        findings = []
        pkg_file = os.path.join(repo_path, "package.json")
        if not os.path.isfile(pkg_file):
            return findings
        try:
            with open(pkg_file) as f:
                pkg = json.load(f)
        except (json.JSONDecodeError, OSError):
            return findings
        for section in ("dependencies", "devDependencies"):
            for name, version in pkg.get(section, {}).items():
                if version in ("*", "latest"):
                    findings.append({
                        "type": "dependency",
                        "severity": "medium",
                        "source": "package.json",
                        "package": name,
                        "version": version,
                        "issue": "wildcard or latest version",
                    })
                elif not version[0].isdigit() and version[0] not in ("^", "~"):
                    findings.append({
                        "type": "dependency",
                        "severity": "low",
                        "source": "package.json",
                        "package": name,
                        "version": version,
                        "issue": "non-standard version specifier",
                    })
        return findings

    def _check_pipfile(self, repo_path):
        findings = []
        pipfile = os.path.join(repo_path, "Pipfile")
        if not os.path.isfile(pipfile):
            return findings
        with open(pipfile) as f:
            for line in f:
                if '"*"' in line:
                    pkg = line.split("=")[0].strip().strip('"')
                    findings.append({
                        "type": "dependency",
                        "severity": "low",
                        "source": "Pipfile",
                        "package": pkg,
                        "issue": "wildcard version",
                    })
        return findings
