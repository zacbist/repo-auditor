from datetime import datetime, timezone

from jinja2 import Environment, BaseLoader
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import get_lexer_for_filename, TextLexer

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }}</title>
<style>
:root{--bg:#0d1117;--fg:#c9d1d9;--card:#161b22;--border:#30363d;--accent:#58a6ff;--high:#e67e22;--medium:#f39c12;--low:#95a5a6;--ok:#2ecc71}
@media(prefers-color-scheme:light){:root{--bg:#fff;--fg:#24292f;--card:#f6f8fa;--border:#d0d7de;--accent:#0969da;--high:#bc4c00;--medium:#9a6700;--low:#6e7781;--ok:#1a7f37}}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:var(--bg);color:var(--fg);line-height:1.6;padding:2rem;max-width:960px;margin:0 auto}
h1{font-size:1.5rem;margin-bottom:.5rem}
h2{font-size:1.1rem;margin:1.5rem 0 .5rem;border-bottom:1px solid var(--border);padding-bottom:.25rem}
.meta{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:1rem;margin:1rem 0;font-size:.85rem}
.meta p{margin:.15rem 0}
.sev{display:inline-block;padding:1px 8px;border-radius:3px;color:#fff;font-size:.75rem;font-weight:600;text-transform:uppercase}
.sev-high{background:var(--high)}.sev-medium{background:var(--medium)}.sev-low{background:var(--low)}
table{width:100%;border-collapse:collapse;font-size:.85rem;margin-bottom:1rem}
th{text-align:left;padding:6px 8px;background:var(--card);border-bottom:2px solid var(--border)}
td{padding:5px 8px;border-bottom:1px solid var(--border);vertical-align:top}
tr:hover{background:var(--card)}
.footer{text-align:center;color:var(--low);margin-top:2rem;font-size:.8rem}
.empty{color:var(--ok);padding:1rem}
{{ pygments_css }}
.highlight{background:var(--card);border:1px solid var(--border);border-radius:4px;padding:.5rem;overflow-x:auto;font-size:.8rem;margin:.5rem 0}
</style>
</head>
<body>
<h1>{{ title }}</h1>
<div class="meta">
  <p><strong>Repository:</strong> {{ url }}</p>
  <p><strong>Branch:</strong> {{ branch }}</p>
  <p><strong>HEAD:</strong> <code>{{ head }}</code></p>
  <p><strong>Findings:</strong> {{ summary.total }}
    (<span style="color:var(--high)">{{ summary.high }} high</span>,
     <span style="color:var(--medium)">{{ summary.medium }} medium</span>,
     <span style="color:var(--low)">{{ summary.low }} low</span>)</p>
</div>

{% for category, findings in results.items() %}
<h2>{{ category | title }} ({{ findings | length }})</h2>
{% if findings %}
<table>
<thead><tr><th>Severity</th><th>Type</th><th>Location</th><th>Details</th></tr></thead>
<tbody>
{% for f in findings %}
<tr>
  <td><span class="sev sev-{{ f.severity | default('info') }}">{{ f.severity | default('info') | upper }}</span></td>
  <td>{{ f.type }}</td>
  <td>{{ f.file | default('') }}{% if f.line %}:{{ f.line }}{% endif %}</td>
  <td>{{ f.label | default(f.issue | default(f.package | default(''))) }}</td>
</tr>
{% endfor %}
</tbody>
</table>
{% else %}
<p class="empty">No findings.</p>
{% endif %}
{% endfor %}

<p class="footer">Generated {{ timestamp }}</p>
</body>
</html>"""


def highlight_code(code, filename="file.py"):
    try:
        lexer = get_lexer_for_filename(filename)
    except Exception:
        lexer = TextLexer()
    formatter = HtmlFormatter(nowrap=False, style="monokai")
    return highlight(code, lexer, formatter)


def _pygments_css():
    return HtmlFormatter(style="monokai").get_style_defs(".highlight")


def render_html(report, output_path=None):
    env = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string(TEMPLATE)
    html = template.render(
        title=f"Audit: {report.get('url', 'unknown')}",
        url=report.get("url", ""),
        branch=report.get("branch", ""),
        head=report.get("head", ""),
        results=report.get("results", {}),
        summary=report.get("summary", {}),
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        pygments_css=_pygments_css(),
    )
    if output_path:
        with open(output_path, "w") as f:
            f.write(html)
    return html
