import json
import os

import httpx
import structlog
import toml
import yaml
from packaging.requirements import Requirement, InvalidRequirement
from packaging.version import Version, InvalidVersion

from .base import BaseScanner

log = structlog.get_logger()

PYPI_TIMEOUT = 5


def _pypi_latest(package_name):
    try:
        resp = httpx.get(
            f"https://pypi.org/pypi/{package_name}/json",
            timeout=PYPI_TIMEOUT,
        )
        if resp.status_code == 200:
            return resp.json()["info"]["version"]
    except (httpx.HTTPError, KeyError, ValueError):
        pass
    return None


class DependencyScanner(BaseScanner):
    name = "dependencies"

    def scan(self, repo_path):
        findings = []
        findings.extend(self._check_requirements(repo_path))
        findings.extend(self._check_package_json(repo_path))
        findings.extend(self._check_pipfile(repo_path))
        findings.extend(self._check_pyproject(repo_path))
        findings.extend(self._check_conda(repo_path))
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
                try:
                    req = Requirement(line)
                    if not req.specifier:
                        findings.append({
                            "type": "dependency",
                            "severity": "low",
                            "source": "requirements.txt",
                            "package": req.name,
                            "issue": "unpinned version",
                        })
                    else:
                        latest = _pypi_latest(req.name)
                        if latest:
                            try:
                                latest_ver = Version(latest)
                                if latest_ver not in req.specifier:
                                    findings.append({
                                        "type": "dependency",
                                        "severity": "low",
                                        "source": "requirements.txt",
                                        "package": req.name,
                                        "issue": f"pinned to {req.specifier}, latest is {latest}",
                                    })
                            except InvalidVersion:
                                pass
                except InvalidRequirement:
                    continue
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
        try:
            data = toml.load(pipfile)
            for section in ("packages", "dev-packages"):
                for pkg, spec in data.get(section, {}).items():
                    if spec == "*":
                        findings.append({
                            "type": "dependency",
                            "severity": "low",
                            "source": "Pipfile",
                            "package": pkg,
                            "issue": "wildcard version",
                        })
        except (toml.TomlDecodeError, OSError):
            pass
        return findings

    def _check_pyproject(self, repo_path):
        findings = []
        pyproject = os.path.join(repo_path, "pyproject.toml")
        if not os.path.isfile(pyproject):
            return findings
        try:
            data = toml.load(pyproject)
            deps = data.get("project", {}).get("dependencies", [])
            for dep in deps:
                try:
                    req = Requirement(dep)
                    if not req.specifier:
                        findings.append({
                            "type": "dependency",
                            "severity": "low",
                            "source": "pyproject.toml",
                            "package": req.name,
                            "issue": "unpinned version",
                        })
                except InvalidRequirement:
                    continue
        except (toml.TomlDecodeError, OSError):
            pass
        return findings

    def _check_conda(self, repo_path):
        findings = []
        env_file = os.path.join(repo_path, "environment.yml")
        if not os.path.isfile(env_file):
            return findings
        try:
            with open(env_file) as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                return findings
            for dep in data.get("dependencies", []):
                if isinstance(dep, str) and "=" not in dep:
                    findings.append({
                        "type": "dependency",
                        "severity": "low",
                        "source": "environment.yml",
                        "package": dep,
                        "issue": "unpinned conda dependency",
                    })
        except (yaml.YAMLError, OSError):
            pass
        return findings
