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
python run.py <url> [-b branch] [-o output.json] [--format text|json]
```

## Checks

- **Secrets** — API keys, AWS credentials, GitHub tokens, private keys, JWTs
- **Dependencies** — unpinned versions, wildcard specifiers
- **Files** — large files, binaries committed to repo
- **License** — missing license file detection
- **Config** — sensitive files (.env, credentials.json, .npmrc, etc.)

## Output

Results are written to `report.json`. Use `--format text` for terminal output.
Open `index.html` in a browser to view the HTML report.
