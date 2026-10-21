# repo-auditor

Audit git repositories for security issues, leaked secrets, and misconfigurations.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python run.py https://github.com/org/repo.git
```

### Options

```
python run.py <url> [-b branch] [-o output.json] [--html report.html] [--text] [--simple]
```

## Checks

- **Secrets** — API keys, AWS credentials, GitHub tokens, private keys, JWTs, exposed .env variables
- **Dependencies** — unpinned versions, wildcard specifiers, outdated PyPI packages, conda environments
- **Files** — large files, binaries committed to repo
- **License** — missing license file detection
- **Config** — sensitive files, CI/CD misconfigurations, XML config analysis

## Output

Results are written to `report.json`. Use `--text` for rich terminal output, `--simple` for plain tables, or `--html report.html` for a styled HTML report.
