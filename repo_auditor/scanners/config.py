import os

import defusedxml.ElementTree as ET
import structlog
import yaml

from .base import BaseScanner

log = structlog.get_logger()

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
        findings.extend(self._check_sensitive_files(repo_path))
        findings.extend(self._check_ci_configs(repo_path))
        findings.extend(self._check_xml_configs(repo_path))
        return findings

    def _check_sensitive_files(self, repo_path):
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

    def _check_ci_configs(self, repo_path):
        findings = []
        workflows_dir = os.path.join(repo_path, ".github", "workflows")
        if os.path.isdir(workflows_dir):
            for fname in os.listdir(workflows_dir):
                if fname.endswith((".yml", ".yaml")):
                    fpath = os.path.join(workflows_dir, fname)
                    findings.extend(self._scan_workflow(fpath, repo_path))

        for ci_file in (".gitlab-ci.yml", ".circleci/config.yml"):
            fpath = os.path.join(repo_path, ci_file)
            if os.path.isfile(fpath):
                findings.extend(self._scan_ci_yaml(fpath, repo_path))
        return findings

    def _scan_workflow(self, fpath, repo_path):
        findings = []
        try:
            with open(fpath) as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                return findings
            for job_name, job in data.get("jobs", {}).items():
                for step in job.get("steps", []):
                    uses = step.get("uses", "")
                    if "@" in uses and not uses.endswith(("@v1", "@v2", "@v3", "@v4", "@main")):
                        if len(uses.split("@")[-1]) == 40:
                            continue
                        findings.append({
                            "type": "ci_config",
                            "severity": "low",
                            "file": os.path.relpath(fpath, repo_path),
                            "issue": f"unpinned action: {uses}",
                        })
        except (yaml.YAMLError, OSError):
            pass
        return findings

    def _scan_ci_yaml(self, fpath, repo_path):
        findings = []
        try:
            with open(fpath) as f:
                yaml.safe_load(f)
        except yaml.YAMLError:
            findings.append({
                "type": "ci_config",
                "severity": "medium",
                "file": os.path.relpath(fpath, repo_path),
                "issue": "invalid YAML syntax",
            })
        except OSError:
            pass
        return findings

    def _check_xml_configs(self, repo_path):
        findings = []
        xml_configs = ["pom.xml", ".classpath", "web.xml", "struts.xml", "hibernate.cfg.xml"]
        for root, _, files in os.walk(repo_path):
            if ".git" in root.split(os.sep):
                continue
            for fname in files:
                if fname not in xml_configs:
                    continue
                fpath = os.path.join(root, fname)
                try:
                    tree = ET.parse(fpath)
                    log.debug("xml.parsed", file=fname)
                    if fname == "pom.xml":
                        findings.extend(self._check_pom(tree, fpath, repo_path))
                except ET.ParseError:
                    findings.append({
                        "type": "config",
                        "severity": "low",
                        "file": os.path.relpath(fpath, repo_path),
                        "issue": "malformed XML",
                    })
                except OSError:
                    continue
        return findings

    def _check_pom(self, tree, fpath, repo_path):
        findings = []
        root = tree.getroot()
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"
        for dep in root.iter(f"{ns}dependency"):
            version_el = dep.find(f"{ns}version")
            if version_el is not None and "${" in (version_el.text or ""):
                continue
            artifact = dep.find(f"{ns}artifactId")
            if version_el is None and artifact is not None:
                findings.append({
                    "type": "dependency",
                    "severity": "low",
                    "file": os.path.relpath(fpath, repo_path),
                    "package": artifact.text,
                    "issue": "no version specified in pom.xml",
                })
        return findings
