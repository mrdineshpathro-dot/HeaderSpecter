"""Standalone HTML report generator.

Produces a single self-contained ``.html`` file — no CDN, no external fonts, no
JavaScript frameworks — with a modern dark security theme, responsive layout,
severity badges, a score visualisation and every analysis section.
"""

from __future__ import annotations

import html
from collections.abc import Iterable, Sequence
from typing import Any

from . import AUTHOR, AUTHOR_URL, PROJECT_URL, TAGLINE, __version__
from .analyzer import ScanResult
from .findings import Severity
from .utils import human_duration, iso_now, slugify, truncate

__all__ = ["render_html"]

_SEVERITY_CLASS = {
    "CRITICAL": "crit",
    "HIGH": "high",
    "MEDIUM": "med",
    "LOW": "low",
    "INFO": "info",
    "PASS": "pass",
}

_CSS = """
:root{
  --bg:#080b10; --bg2:#0d131b; --panel:#111823; --panel2:#0d141d; --line:#1e2a38;
  --text:#e8eef5; --muted:#8fa0b3; --accent:#22d3ee; --accent2:#a78bfa;
  --crit:#ff4d6d; --high:#ff7849; --med:#f5c451; --low:#38bdf8; --info:#8b93f8; --pass:#34d399;
  --mono:"JetBrains Mono","Fira Code","SFMono-Regular",Consolas,"Liberation Mono",monospace;
  --sans:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 20% -10%,#12202c 0%,var(--bg) 60%);color:var(--text);
  font-family:var(--sans);line-height:1.55;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:1180px;margin:0 auto;padding:32px 20px 80px}
header.masthead{display:flex;flex-wrap:wrap;gap:20px;align-items:center;justify-content:space-between;
  border:1px solid var(--line);background:linear-gradient(135deg,rgba(34,211,238,.08),rgba(167,139,250,.06));
  border-radius:16px;padding:24px 28px;margin-bottom:28px}
.brand{display:flex;flex-direction:column;gap:6px}
.brand h1{margin:0;font-size:30px;letter-spacing:.5px}
.brand h1 span{background:linear-gradient(90deg,var(--accent),var(--accent2));-webkit-background-clip:text;
  background-clip:text;color:transparent}
.brand p{margin:0;color:var(--muted);font-size:14px}
.masthead .meta{text-align:right;color:var(--muted);font-size:13px;font-family:var(--mono)}
section{margin:26px 0}
h2{font-size:18px;letter-spacing:.14em;text-transform:uppercase;color:var(--accent);margin:0 0 14px;
  padding-bottom:8px;border-bottom:1px solid var(--line)}
h3{font-size:15px;margin:22px 0 10px;color:var(--text)}
.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);
  border-radius:14px;padding:20px 22px}
.grid{display:grid;gap:16px}
.grid.cols-2{grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}
.grid.cols-3{grid-template-columns:repeat(auto-fit,minmax(220px,1fr))}
.grid.cols-4{grid-template-columns:repeat(auto-fit,minmax(170px,1fr))}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.stat .v{font-size:24px;font-weight:700;font-family:var(--mono)}
.stat .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.09em}
.scorebox{display:flex;gap:26px;align-items:center;flex-wrap:wrap}
.ring{flex:0 0 auto}
.score-detail{flex:1 1 260px;min-width:240px}
.score-detail .grade{font-size:15px;color:var(--muted);font-family:var(--mono)}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700;
  letter-spacing:.08em;font-family:var(--mono);border:1px solid transparent}
.badge.crit{color:#fff;background:rgba(255,77,109,.18);border-color:var(--crit)}
.badge.high{color:#ffd9c9;background:rgba(255,120,73,.16);border-color:var(--high)}
.badge.med{color:#fdf0c9;background:rgba(245,196,81,.14);border-color:var(--med)}
.badge.low{color:#cdeeff;background:rgba(56,189,248,.14);border-color:var(--low)}
.badge.info{color:#dcdcff;background:rgba(139,147,248,.14);border-color:var(--info)}
.badge.pass{color:#c8f7e4;background:rgba(52,211,153,.14);border-color:var(--pass)}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em;font-weight:600}
tbody tr:hover{background:rgba(34,211,238,.04)}
code,pre,.mono{font-family:var(--mono)}
code{background:rgba(148,163,184,.12);padding:1px 6px;border-radius:5px;font-size:12.5px;word-break:break-all}
pre{background:#070a0f;border:1px solid var(--line);border-radius:10px;padding:14px 16px;overflow:auto;
  font-size:12.5px;color:#cfe8f5}
.finding{border:1px solid var(--line);border-left-width:4px;border-radius:12px;padding:16px 18px;margin-bottom:14px;
  background:var(--panel)}
.finding.crit{border-left-color:var(--crit)} .finding.high{border-left-color:var(--high)}
.finding.med{border-left-color:var(--med)} .finding.low{border-left-color:var(--low)}
.finding.info{border-left-color:var(--info)} .finding.pass{border-left-color:var(--pass)}
.finding h4{margin:0 0 8px;font-size:15px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.finding .fid{font-family:var(--mono);color:var(--muted);font-size:12px}
.finding dl{display:grid;grid-template-columns:110px 1fr;gap:6px 14px;margin:10px 0 0;font-size:13.5px}
.finding dt{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.07em}
.finding dd{margin:0}
.chain{list-style:none;margin:0;padding:0;font-family:var(--mono);font-size:13px}
.chain li{padding:8px 0 8px 22px;border-left:2px solid var(--line);position:relative;margin-left:8px}
.chain li:before{content:"";position:absolute;left:-6px;top:14px;width:10px;height:10px;border-radius:50%;
  background:var(--accent)}
.chain li.final:before{background:var(--pass)}
.muted{color:var(--muted)}
.pill{display:inline-block;margin:2px 6px 2px 0;padding:2px 8px;border:1px solid var(--line);border-radius:999px;
  font-size:11.5px;font-family:var(--mono);color:var(--muted)}
details{border:1px solid var(--line);border-radius:12px;padding:12px 16px;background:var(--panel)}
details summary{cursor:pointer;color:var(--accent);font-weight:600;font-size:14px}
details[open] summary{margin-bottom:12px}
footer{margin-top:44px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);font-size:13px;
  display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap}
.notice{border:1px solid rgba(245,196,81,.35);background:rgba(245,196,81,.08);border-radius:12px;padding:12px 16px;
  color:#f8e6b4;font-size:13px}
.target-nav a{display:inline-block;margin:0 10px 8px 0;padding:6px 12px;border:1px solid var(--line);
  border-radius:999px;font-size:13px;font-family:var(--mono)}
@media(max-width:640px){
  .finding dl{grid-template-columns:1fr}
  .masthead .meta{text-align:left}
  .wrap{padding:18px 14px 60px}
}
"""


def _e(value: Any) -> str:
    """HTML-escape any value."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _sev_class(severity: str) -> str:
    return _SEVERITY_CLASS.get(str(severity).upper(), "info")


def _badge(severity: str, text: str | None = None) -> str:
    label = text or severity
    return f'<span class="badge {_sev_class(severity)}">{_e(label)}</span>'


def _score_ring(score: float, grade: str) -> str:
    radius = 54
    circumference = 2 * 3.14159 * radius
    pct = max(0.0, min(100.0, score)) / 100.0
    dash = circumference * pct
    color = "var(--pass)" if score >= 80 else "var(--med)" if score >= 60 else "var(--high)" if score >= 40 else "var(--crit)"
    return f"""
<div class="ring">
  <svg width="140" height="140" viewBox="0 0 140 140" role="img" aria-label="Security score {score:.0f} out of 100">
    <circle cx="70" cy="70" r="{radius}" fill="none" stroke="#1e2a38" stroke-width="12"/>
    <circle cx="70" cy="70" r="{radius}" fill="none" stroke="{color}" stroke-width="12" stroke-linecap="round"
            stroke-dasharray="{dash:.2f} {circumference:.2f}" transform="rotate(-90 70 70)"/>
    <text x="70" y="66" text-anchor="middle" fill="#e8eef5" font-size="30" font-family="monospace"
          font-weight="700">{score:.0f}</text>
    <text x="70" y="90" text-anchor="middle" fill="#8fa0b3" font-size="13" font-family="monospace">/ 100 · {_e(grade)}</text>
  </svg>
</div>
"""


def _rows_table(rows: Iterable[Any], columns: tuple[str, str] = ("Check", "Detail")) -> str:
    body: list[str] = []
    for row in rows:
        label, status, detail = row
        severity = status.value if isinstance(status, Severity) else str(status)
        body.append(
            f"<tr><td>{_badge(severity, severity)}</td><td><strong>{_e(label)}</strong></td>"
            f"<td class='muted'>{_e(detail)}</td></tr>"
        )
    if not body:
        return "<p class='muted'>No data.</p>"
    return (
        f"<table><thead><tr><th>Status</th><th>{_e(columns[0])}</th><th>{_e(columns[1])}</th></tr></thead>"
        f"<tbody>{''.join(body)}</tbody></table>"
    )


def _summary_section(results: Sequence[ScanResult]) -> str:
    if len(results) < 2:
        return ""
    rows: list[str] = []
    nav: list[str] = []
    for index, result in enumerate(results):
        anchor = f"target-{index}-{slugify(result.final_url or result.target, 32)}"
        nav.append(f'<a href="#{anchor}">{_e(truncate(result.host or result.target, 34))}</a>')
        counts = result.counts
        score = f"{result.score:.0f}" if result.score is not None else "—"
        rows.append(
            f"<tr><td><a href='#{anchor}'>{_e(truncate(result.final_url or result.target, 60))}</a></td>"
            f"<td>{_e(result.status_code or 'ERROR')}</td>"
            f"<td class='mono'>{score}</td><td>{_badge('PASS' if (result.score or 0) >= 80 else 'MEDIUM', result.grade)}</td>"
            f"<td>{counts.get('CRITICAL', 0)}</td><td>{counts.get('HIGH', 0)}</td><td>{counts.get('MEDIUM', 0)}</td>"
            f"<td>{counts.get('LOW', 0)}</td><td>{counts.get('INFO', 0)}</td></tr>"
        )
    scored = [r for r in results if r.score is not None]
    average = sum(r.score or 0 for r in scored) / len(scored) if scored else 0
    return f"""
<section>
  <h2>Executive Summary</h2>
  <div class="grid cols-4" style="margin-bottom:18px">
    <div class="stat"><div class="v">{len(results)}</div><div class="l">Targets scanned</div></div>
    <div class="stat"><div class="v">{average:.1f}</div><div class="l">Average score</div></div>
    <div class="stat"><div class="v">{sum(1 for r in results if not r.ok)}</div><div class="l">Failed scans</div></div>
    <div class="stat"><div class="v">{sum((r.counts or {}).get('CRITICAL', 0) + (r.counts or {}).get('HIGH', 0) for r in results)}</div>
      <div class="l">Critical + high</div></div>
  </div>
  <div class="card">
    <table>
      <thead><tr><th>Target</th><th>Status</th><th>Score</th><th>Grade</th><th>C</th><th>H</th><th>M</th><th>L</th><th>I</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </div>
  <div class="target-nav" style="margin-top:14px">{''.join(nav)}</div>
</section>
"""


def _findings_html(result: ScanResult) -> str:
    analysis = result.analysis
    if analysis is None:
        return ""
    issues = analysis.issues
    if not issues:
        return "<div class='card'><p class='muted'>No issues detected — the target meets every baseline check.</p></div>"
    blocks: list[str] = []
    for finding in issues:
        remediation = (
            f"<dt>Template</dt><dd><pre>{_e(finding.remediation)}</pre></dd>" if finding.remediation else ""
        )
        value = f"<dt>Observed</dt><dd><code>{_e(truncate(finding.value, 400))}</code></dd>" if finding.value else ""
        header = f"<dt>Header</dt><dd><code>{_e(finding.header)}</code></dd>" if finding.header else ""
        references = ""
        if finding.references:
            links = " ".join(
                f'<a class="pill" href="{_e(ref)}" rel="noreferrer noopener" target="_blank">{_e(_short_ref(ref))}</a>'
                for ref in finding.references
            )
            references = f"<dt>Reference</dt><dd>{links}</dd>"
        blocks.append(
            f"""
<article class="finding {_sev_class(finding.severity.value)}">
  <h4>{_badge(finding.severity.value)} <span>{_e(finding.title)}</span> <span class="fid">{_e(finding.id)}</span></h4>
  <dl>
    {header}
    {value}
    <dt>Detail</dt><dd>{_e(finding.reason)}</dd>
    <dt>Impact</dt><dd class="muted">{_e(finding.impact)}</dd>
    <dt>Fix</dt><dd>{_e(finding.recommendation)}</dd>
    {remediation}
    {references}
  </dl>
</article>"""
        )
    return "".join(blocks)


def _short_ref(url: str) -> str:
    cleaned = url.replace("https://", "").replace("http://", "")
    return truncate(cleaned, 46)


def _headers_table(result: ScanResult) -> str:
    analysis = result.analysis
    if analysis is None:
        return ""
    rows = []
    for check in list(analysis.header_checks) + list(analysis.extra_checks):
        rows.append(
            f"<tr><td>{_badge(check.status.value, check.state)}</td><td><code>{_e(check.header)}</code></td>"
            f"<td class='muted'>{_e(truncate(check.value or check.note, 140))}</td></tr>"
        )
    return (
        "<table><thead><tr><th>Status</th><th>Header</th><th>Value / note</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _csp_html(result: ScanResult) -> str:
    analysis = result.analysis
    csp = analysis.csp if analysis else None
    if csp is None or not csp.present:
        return "<div class='card'><p class='muted'>No Content-Security-Policy header was returned.</p></div>"
    directive_rows = "".join(
        f"<tr><td>{_badge(row.status.value, row.status.value)}</td><td><code>{_e(row.directive)}</code></td>"
        f"<td class='mono'>{_e(truncate(row.value, 150))}</td><td class='muted'>{_e(row.note)}</td></tr>"
        for row in csp.directive_rows
    )
    return f"""
<div class="card">
  {_rows_table(csp.rows)}
  <h3>Directives</h3>
  <table><thead><tr><th>Status</th><th>Directive</th><th>Value</th><th>Note</th></tr></thead>
  <tbody>{directive_rows}</tbody></table>
  <h3>Policy</h3>
  <pre>{_e(csp.raw)}</pre>
</div>
"""


def _cookies_html(result: ScanResult) -> str:
    analysis = result.analysis
    cookies = analysis.cookies if analysis else None
    if cookies is None or not cookies.cookies:
        return "<div class='card'><p class='muted'>No cookies were set by this response.</p></div>"
    rows = []
    for cookie in cookies.cookies:
        issues = ", ".join(cookie.issues) if cookie.issues else "—"
        rows.append(
            f"<tr><td>{_badge(cookie.status.value)}</td><td><code>{_e(cookie.name)}</code></td>"
            f"<td>{'yes' if cookie.secure else '<strong>no</strong>'}</td>"
            f"<td>{'yes' if cookie.http_only else '<strong>no</strong>'}</td>"
            f"<td>{_e(cookie.same_site or 'not set')}</td>"
            f"<td class='muted'>{_e(cookie.domain or '—')}</td>"
            f"<td class='muted'>{_e(issues)}</td></tr>"
        )
    return f"""
<div class="card">
  <table>
    <thead><tr><th>Status</th><th>Cookie</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Domain</th><th>Issues</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
  <p class="muted" style="margin-bottom:0">Cookie values are redacted; only attribute metadata is stored in this report.</p>
</div>
"""


def _tls_html(result: ScanResult) -> str:
    analysis = result.analysis
    if analysis is None:
        return ""
    tls = analysis.tls
    rows = _rows_table(analysis.tls_rows)
    extra = ""
    if tls and tls.subject_alt_names:
        pills = "".join(f'<span class="pill">{_e(name)}</span>' for name in tls.subject_alt_names[:24])
        extra = f"<h3>Subject alternative names</h3><div>{pills}</div>"
    return f"<div class='card'>{rows}{extra}</div>"


def _redirects_html(result: ScanResult) -> str:
    analysis = result.analysis
    redirects = analysis.redirects if analysis else None
    if redirects is None or not redirects.hops:
        return "<div class='card'><p class='muted'>No redirects — the target responded directly.</p></div>"
    items = "".join(
        f"<li><code>{_e(hop.url)}</code> <span class='muted'>→ {hop.status_code}</span></li>" for hop in redirects.hops
    )
    items += f"<li class='final'><code>{_e(result.final_url)}</code> <span class='muted'>→ {result.status_code}</span></li>"
    return f"<div class='card'><ul class='chain'>{items}</ul>{_rows_table(redirects.rows)}</div>"


def _cors_html(result: ScanResult) -> str:
    analysis = result.analysis
    cors = analysis.cors if analysis else None
    if cors is None:
        return ""
    return f"<div class='card'>{_rows_table(cors.rows)}</div>"


def _disclosure_html(result: ScanResult) -> str:
    analysis = result.analysis
    if analysis is None or not analysis.disclosure:
        return "<div class='card'><p class='muted'>No revealing technology headers detected.</p></div>"
    rows = "".join(
        f"<tr><td>{_badge(item.severity.value)}</td><td><code>{_e(item.header)}</code></td>"
        f"<td class='mono'>{_e(truncate(item.value, 120))}</td><td class='muted'>{_e(item.note)}</td></tr>"
        for item in analysis.disclosure
    )
    return f"""
<div class="card">
  <table><thead><tr><th>Severity</th><th>Header</th><th>Value</th><th>Observation</th></tr></thead>
  <tbody>{rows}</tbody></table>
  <p class="muted" style="margin-bottom:0">Information disclosure observations — they reduce attacker effort but are not vulnerabilities on their own.</p>
</div>
"""


def _score_section(result: ScanResult) -> str:
    analysis = result.analysis
    if analysis is None or analysis.score is None:
        return ""
    score = analysis.score
    counts = analysis.counts
    stats = "".join(
        f"<div class='stat'><div class='v' style='color:var(--{_sev_class(sev)})'>{counts.get(sev, 0)}</div>"
        f"<div class='l'>{sev.title()}</div></div>"
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )
    deductions = "".join(
        f"<tr><td class='mono'>{_e(item.finding_id)}</td><td>{_badge(item.severity)}</td>"
        f"<td>{_e(item.category)}</td><td>{_e(item.title)}</td>"
        f"<td class='mono'>-{item.applied_points:.1f}{'*' if item.capped else ''}</td></tr>"
        for item in score.deductions
    )
    bonuses = "".join(
        f"<tr><td class='mono'>BONUS</td><td>{_badge('PASS', '+')}</td><td>bonus</td><td>{_e(item.reason)}</td>"
        f"<td class='mono'>+{item.points:.1f}</td></tr>"
        for item in score.bonuses
    )
    return f"""
<section>
  <h2>Security Score</h2>
  <div class="card scorebox">
    {_score_ring(score.score, score.grade)}
    <div class="score-detail">
      <div class="grade">base {score.base_score:.0f} − {score.total_deducted:.1f} deductions
        + {score.total_bonus:.1f} bonus = <strong>{score.score:.1f}</strong></div>
      <div class="grid cols-4" style="margin-top:14px">{stats}</div>
    </div>
  </div>
  <details style="margin-top:14px">
    <summary>Score breakdown ({len(score.deductions)} deductions)</summary>
    <table><thead><tr><th>ID</th><th>Severity</th><th>Category</th><th>Finding</th><th>Points</th></tr></thead>
    <tbody>{deductions}{bonuses}</tbody></table>
    <p class="muted">* capped by the category limit defined in the scoring configuration.</p>
  </details>
</section>
"""


def _target_section(result: ScanResult, index: int) -> str:
    anchor = f"target-{index}-{slugify(result.final_url or result.target, 32)}"
    if not result.ok or result.analysis is None:
        return f"""
<section id="{anchor}">
  <h2>{_e(result.target)}</h2>
  <div class="card">
    <p>{_badge('HIGH', 'SCAN FAILED')} <strong>{_e(result.error)}</strong></p>
    <p class="muted">{_e(result.hint or '')}</p>
  </div>
</section>
"""
    analysis = result.analysis
    recommendations = "".join(f"<li>{_e(item)}</li>" for item in analysis.recommendations)
    meta_rows = "".join(
        f"<tr><td>{_e(key)}</td><td class='mono'>{_e(value)}</td></tr>" for key, value in (result.meta or {}).items()
    )
    return f"""
<section id="{anchor}">
  <h2>Target · {_e(result.final_url or result.target)}</h2>
  <div class="grid cols-4">
    <div class="stat"><div class="v">{_e(result.status_code)}</div><div class="l">HTTP status</div></div>
    <div class="stat"><div class="v">{_e(human_duration(result.elapsed_ms))}</div><div class="l">Response time</div></div>
    <div class="stat"><div class="v">{len(result.headers)}</div><div class="l">Headers</div></div>
    <div class="stat"><div class="v">{analysis.redirects.count if analysis.redirects else 0}</div><div class="l">Redirects</div></div>
  </div>
</section>
{_score_section(result)}
<section><h2>Findings</h2>{_findings_html(result)}</section>
<section><h2>Header Security</h2><div class="card">{_headers_table(result)}</div></section>
<section><h2>Content-Security-Policy</h2>{_csp_html(result)}</section>
<section><h2>Cookies</h2>{_cookies_html(result)}</section>
<section><h2>CORS</h2>{_cors_html(result)}</section>
<section><h2>TLS</h2>{_tls_html(result)}</section>
<section><h2>Redirect Chain</h2>{_redirects_html(result)}</section>
<section><h2>Technology Disclosure</h2>{_disclosure_html(result)}</section>
<section><h2>Recommendations</h2><div class="card"><ol>{recommendations or '<li class="muted">Nothing to action.</li>'}</ol></div></section>
<section>
  <h2>Raw Headers &amp; Metadata</h2>
  <details><summary>Raw response head</summary><pre>{_e(result.raw_headers_text())}</pre></details>
  <details style="margin-top:12px"><summary>Scan metadata</summary>
    <table><tbody>
      <tr><td>Requested URL</td><td class="mono">{_e(result.url)}</td></tr>
      <tr><td>Final URL</td><td class="mono">{_e(result.final_url)}</td></tr>
      <tr><td>HTTP version</td><td class="mono">{_e(result.http_version)}</td></tr>
      <tr><td>Scanned at</td><td class="mono">{_e(result.scanned_at)}</td></tr>
      <tr><td>Policy</td><td class="mono">{_e(analysis.policy_name or 'built-in defaults')}</td></tr>
      {meta_rows}
    </tbody></table>
  </details>
</section>
"""


def render_html(results: Sequence[ScanResult], title: str | None = None) -> str:
    """Render a complete standalone HTML report."""
    results = list(results)
    heading = title or (
        f"Security header report · {results[0].host}" if len(results) == 1 and results else "Security header report"
    )
    body = _summary_section(results) + "".join(_target_section(result, index) for index, result in enumerate(results))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="HeaderSpecter {_e(__version__)}">
<title>HeaderSpecter — {_e(heading)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
  <header class="masthead">
    <div class="brand">
      <h1>Header<span>Specter</span></h1>
      <p>{_e(TAGLINE)}</p>
      <p class="muted">Created by {_e(AUTHOR)} · <a href="{_e(AUTHOR_URL)}" rel="noreferrer noopener">{_e(AUTHOR_URL)}</a></p>
    </div>
    <div class="meta">
      <div>v{_e(__version__)}</div>
      <div>{_e(iso_now())}</div>
      <div>{len(results)} target(s)</div>
    </div>
  </header>
  <div class="notice">
    This report documents observed HTTP response headers and their security implications. Remediation snippets are
    templates and must be reviewed against the application's own resource requirements before deployment.
  </div>
  {body}
  <footer>
    <div>HeaderSpecter v{_e(__version__)} · <a href="{_e(PROJECT_URL)}" rel="noreferrer noopener">{_e(PROJECT_URL)}</a></div>
    <div>Authorised security testing only · {_e(AUTHOR)} · <a href="{_e(AUTHOR_URL)}" rel="noreferrer noopener">buy me a coffee</a></div>
  </footer>
</div>
</body>
</html>
"""
