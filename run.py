#!/usr/bin/env python3
import json
import sys

import click
import colorama
import structlog
from rich.console import Console
from rich.table import Table
from tabulate import tabulate

from dynamic_git import get_git, GitConfig
from repo_auditor.auditor import run_audit, summarize
from repo_auditor.reporter import render_html

colorama.init()
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(20),
)
log = structlog.get_logger()
console = Console()

SEVERITY_COLORS = {"high": "red", "medium": "yellow", "low": "blue"}


def print_table(report):
    summary = report["summary"]
    console.print(f"\n[bold]Audit Report:[/bold] {report['url']}")
    console.print(f"Branch: {report['branch']}  HEAD: {report['head'][:12]}\n")

    table = Table(show_header=True)
    table.add_column("Severity", width=8)
    table.add_column("Category", width=14)
    table.add_column("File", width=30)
    table.add_column("Details")

    for category, findings in report["results"].items():
        for f in findings:
            sev = f.get("severity", "info")
            color = SEVERITY_COLORS.get(sev, "white")
            detail = f.get("label") or f.get("issue") or f.get("package", "")
            loc = f.get("file", "")
            if f.get("line"):
                loc += f":{f['line']}"
            table.add_row(f"[{color}]{sev.upper()}[/{color}]", category, loc, detail)

    console.print(table)
    console.print(f"\n[bold]Total:[/bold] {summary['total']} findings "
                  f"([red]{summary['high']} high[/red], "
                  f"[yellow]{summary['medium']} medium[/yellow], "
                  f"[blue]{summary['low']} low[/blue])\n")


def print_simple(report):
    rows = []
    for category, findings in report["results"].items():
        for f in findings:
            sev = f.get("severity", "info").upper()
            loc = f.get("file", "")
            if f.get("line"):
                loc += f":{f['line']}"
            detail = f.get("label") or f.get("issue") or f.get("package", "")
            rows.append([sev, category, loc, detail])
    if rows:
        print(tabulate(rows, headers=["Severity", "Category", "File", "Details"], tablefmt="grid"))
    summary = report["summary"]
    print(f"\nTotal: {summary['total']} findings "
          f"({summary['high']} high, {summary['medium']} medium, {summary['low']} low)")


@click.command()
@click.argument("url", default="https://github.com/expressjs/express.git")
@click.option("-b", "--branch", default="main", help="Branch to clone")
@click.option("-o", "--output", default="report.json", help="Output file path")
@click.option("--html", "html_output", default=None, help="Generate HTML report")
@click.option("--text", is_flag=True, help="Print rich table to terminal")
@click.option("--simple", is_flag=True, help="Print plain table to terminal")
def main(url, branch, output, html_output, text, simple):
    log.info("audit.start", url=url, branch=branch)
    console.print(f"[dim]Cloning {url}...[/dim]")
    config = GitConfig(branch=branch)
    repo = get_git(url, config=config)

    console.print("[dim]Running audit...[/dim]")
    results = run_audit(repo.working_dir)
    summary = summarize(results)

    report = {
        "url": url,
        "branch": branch,
        "head": str(repo.head.commit),
        "results": results,
        "summary": summary,
    }

    with open(output, "w") as f:
        json.dump(report, f, indent=2)

    if html_output:
        render_html(report, html_output)
        console.print(f"HTML report saved to [bold]{html_output}[/bold]")

    if text:
        print_table(report)
    elif simple:
        print_simple(report)
    else:
        console.print(f"Found {summary['total']} issues "
                      f"([red]{summary['high']} high[/red], "
                      f"[yellow]{summary['medium']} medium[/yellow], "
                      f"[blue]{summary['low']} low[/blue])")

    log.info("audit.done", total=summary["total"])
    console.print(f"Report saved to [bold]{output}[/bold]")


if __name__ == "__main__":
    main()
