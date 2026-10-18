import argparse
import json
import sys

from dynamic_git import get_git, GitConfig

from .auditor import run_audit, summarize


def parse_args():
    parser = argparse.ArgumentParser(description="Audit a git repository for security issues")
    parser.add_argument("url", nargs="?", default="https://github.com/expressjs/express.git",
                        help="Repository URL to audit")
    parser.add_argument("-b", "--branch", default="main", help="Branch to clone")
    parser.add_argument("-o", "--output", default="report.json", help="Output file path")
    parser.add_argument("--format", choices=["json", "text"], default="json", help="Output format")
    return parser.parse_args()


def print_text_report(report):
    summary = report["summary"]
    print(f"\n{'='*50}")
    print(f"Audit Report: {report['url']}")
    print(f"{'='*50}")
    print(f"Branch: {report.get('branch', 'unknown')}")
    print(f"HEAD:   {report.get('head', 'unknown')}")
    print(f"\nFindings: {summary['total']} total "
          f"({summary['high']} high, {summary['medium']} medium, {summary['low']} low)\n")

    for category, findings in report["results"].items():
        if not findings:
            continue
        print(f"[{category}]")
        for f in findings:
            sev = f.get("severity", "info")
            msg = f.get("label") or f.get("issue") or f.get("file", "")
            loc = f.get("file", "")
            if f.get("line"):
                loc += f":{f['line']}"
            print(f"  [{sev.upper():6}] {loc:40} {msg}")
        print()


def main():
    args = parse_args()
    print(f"Cloning {args.url}...")

    config = GitConfig(branch=args.branch)
    repo = get_git(args.url, config=config)

    print("Running audit...")
    results = run_audit(repo.working_dir)
    summary = summarize(results)

    report = {
        "url": args.url,
        "branch": args.branch,
        "head": str(repo.head.commit),
        "results": results,
        "summary": summary,
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    if args.format == "text":
        print_text_report(report)
    else:
        print(f"Found {summary['total']} issues "
              f"({summary['high']} high, {summary['medium']} medium, {summary['low']} low)")

    print(f"Report saved to {args.output}")
    return 0 if summary["high"] == 0 else 1
