import structlog

from .scanners import ALL_SCANNERS

log = structlog.get_logger()


def run_audit(repo_path):
    results = {}
    for scanner_cls in ALL_SCANNERS:
        scanner = scanner_cls()
        log.info("scanner.start", scanner=scanner.name, path=repo_path)
        findings = scanner.scan(repo_path)
        results[scanner.name] = findings
        log.info("scanner.done", scanner=scanner.name, count=len(findings))
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
