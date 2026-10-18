import os

from .scanners import ALL_SCANNERS


def run_audit(repo_path):
    results = {}
    for scanner_cls in ALL_SCANNERS:
        scanner = scanner_cls()
        results[scanner.name] = scanner.scan(repo_path)
    return results


def summarize(results):
    all_findings = []
    for findings in results.values():
        all_findings.extend(findings)

    high = sum(1 for f in all_findings if f.get("severity") == "high")
    medium = sum(1 for f in all_findings if f.get("severity") == "medium")
    low = sum(1 for f in all_findings if f.get("severity") == "low")

    return {
        "total": len(all_findings),
        "high": high,
        "medium": medium,
        "low": low,
    }
