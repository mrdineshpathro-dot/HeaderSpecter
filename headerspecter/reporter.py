"""Report generation, exports and baseline comparison.

Covers terminal rendering, JSON / CSV / Markdown exports and the diffing used
by both ``--compare`` and ``--watch``.

The terminal renderer is driven by :class:`~headerspecter.config.OutputConfig`
so the CLI section flags (``--csp``, ``--cookies``, ``--tls`` …) can turn the
report into exactly the view the operator asked for.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import AUTHOR, AUTHOR_URL, __version__
from .analyzer import ScanResult
from .config import OutputConfig
from .findings import Severity
from .ui import UI
from .utils import human_duration, iso_now, truncate, write_text

__all__ = [
    "render_terminal",
    "render_quiet",
    "render_batch_terminal",
    "to_json",
    "to_csv",
    "to_markdown",
    "save_baseline",
    "load_baseline",
    "DiffResult",
    "compare_results",
    "compare_to_baseline",
]


# --------------------------------------------------------------------------- #
# Terminal
# --------------------------------------------------------------------------- #
def render_terminal(ui: UI, result: ScanResult, output: OutputConfig | None = None) -> None:
    """Render one scan result to the terminal."""
    cfg = output or OutputConfig()

    if not result.ok or result.analysis is None:
        ui.error(f"{result.target}: {result.error}", result.hint)
        return

    analysis = result.analysis

    if cfg.show_response:
        ui.target_summary(result)

    if cfg.show_score and analysis.score is not None:
        ui.score_panel(analysis.score, analysis.counts)

    if cfg.show_headers:
        ui.header_table(analysis.header_checks, "Header Security")
        if analysis.extra_checks:
            ui.header_table(analysis.extra_checks, "Additional & Legacy Headers")

    if cfg.show_csp:
        ui.csp_section(analysis.csp)

    if cfg.show_hsts and analysis.hsts is not None:
        ui.section("HSTS", "Strict-Transport-Security")
        ui.rows_panel("Transport Security", analysis.hsts.rows)

    if cfg.show_headers and analysis.permissions is not None and analysis.permissions.rows:
        ui.section("Permissions Policy")
        ui.rows_panel("Browser Feature Policy", analysis.permissions.rows)

    if cfg.show_headers and analysis.cross_origin is not None:
        ui.section("Cross-Origin Policies", "COOP · CORP · COEP")
        ui.rows_panel("Isolation Posture", analysis.cross_origin.rows)

    if cfg.show_cookies:
        ui.cookie_section(analysis.cookies)

    if cfg.show_cors and analysis.cors is not None:
        ui.section("CORS Analysis")
        ui.rows_panel("Cross-Origin Resource Sharing", analysis.cors.rows)

    if cfg.show_tls:
        ui.section("TLS Security")
        ui.rows_panel("Transport Layer", analysis.tls_rows or [("TLS", Severity.INFO, "no data")])

    if cfg.show_redirects:
        ui.redirect_section(analysis.redirects, result.final_url, result.status_code)

    if cfg.show_headers and analysis.caching_rows:
        ui.section("Caching")
        ui.rows_panel("Cache Posture", analysis.caching_rows)

    if cfg.show_disclosure:
        ui.disclosure_section(analysis.disclosure)

    if cfg.show_findings:
        ui.findings_section(analysis.findings, verbose=cfg.verbose_findings)

    if cfg.verbose_findings and cfg.show_score and analysis.score is not None:
        ui.score_breakdown(analysis.score)

    if cfg.show_recommendations:
        ui.recommendations_section(analysis.recommendations)

    if cfg.show_raw:
        ui.raw_headers_section(result)


def render_quiet(ui: UI, results: Sequence[ScanResult]) -> None:
    """Render one compact, script-friendly line per target (``--quiet``)."""
    from rich.text import Text

    for result in results:
        if not result.ok:
            ui.console.print(
                Text.assemble(
                    (f"{result.target}  ", "bright_white"),
                    ("ERROR  ", "hs.bad"),
                    (result.error or "scan failed", "hs.dim"),
                )
            )
            continue
        counts = result.counts
        score = result.analysis.score if result.analysis else None
        style = score.grade_style if score else "hs.dim"
        ui.console.print(
            Text.assemble(
                (f"{result.final_url or result.target}  ", "bright_white"),
                (f"{result.status_code}  ", "hs.dim"),
                (f"score {result.score:.0f}/100  ", style),
                (f"grade {result.grade}  ", style),
                (f"C:{counts.get('CRITICAL', 0)} ", "sev.CRITICAL"),
                (f"H:{counts.get('HIGH', 0)} ", "sev.HIGH"),
                (f"M:{counts.get('MEDIUM', 0)} ", "sev.MEDIUM"),
                (f"L:{counts.get('LOW', 0)} ", "sev.LOW"),
                (f"I:{counts.get('INFO', 0)}", "sev.INFO"),
            )
        )


def render_batch_terminal(
    ui: UI,
    results: Sequence[ScanResult],
    output: OutputConfig | None = None,
    detail: bool = False,
) -> None:
    """Render a batch scan: optional per-target detail plus the scoreboard."""
    cfg = output or OutputConfig()
    if detail:
        for result in results:
            ui.blank()
            ui.print(f"[hs.accent]{'═' * min(ui.console.width, 80)}[/]")
            render_terminal(ui, result, cfg)
    ui.batch_summary(results)

    failures = [result for result in results if not result.ok]
    if failures:
        ui.section("Failed Targets", f"{len(failures)}")
        for result in failures:
            ui.error(f"{result.target}: {result.error}", result.hint)


# --------------------------------------------------------------------------- #
# Structured exports
# --------------------------------------------------------------------------- #
def _envelope(results: Sequence[ScanResult]) -> dict[str, Any]:
    payload = [result.to_dict() for result in results]
    scored = [result for result in results if result.score is not None]
    return {
        "tool": "HeaderSpecter",
        "version": __version__,
        "author": AUTHOR,
        "author_url": AUTHOR_URL,
        "generated_at": iso_now(),
        "target_count": len(results),
        "average_score": round(sum(r.score or 0 for r in scored) / len(scored), 1) if scored else None,
        "results": payload,
    }


def to_json(results: Sequence[ScanResult], pretty: bool = True, single: bool | None = None) -> str:
    """Serialise results as JSON.

    A single-target scan produces the bare result object (easy to pipe into
    ``jq``); batch scans produce an envelope with summary metadata.
    """
    as_single = single if single is not None else len(results) == 1
    data: Any = results[0].to_dict() if as_single and results else _envelope(results)
    return json.dumps(data, indent=2 if pretty else None, ensure_ascii=False, sort_keys=False)


CSV_COLUMNS: tuple[str, ...] = (
    "target",
    "final_url",
    "status_code",
    "score",
    "grade",
    "finding_id",
    "severity",
    "category",
    "header",
    "title",
    "value",
    "reason",
    "recommendation",
)


def to_csv(results: Sequence[ScanResult]) -> str:
    """Serialise every finding of every target as CSV rows."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for result in results:
        base = {
            "target": result.target,
            "final_url": result.final_url,
            "status_code": result.status_code if result.status_code is not None else "",
            "score": f"{result.score:.1f}" if result.score is not None else "",
            "grade": result.grade,
        }
        if not result.ok or result.analysis is None:
            writer.writerow(
                {
                    **base,
                    "finding_id": "SCAN-ERROR",
                    "severity": "ERROR",
                    "category": "scan",
                    "header": "",
                    "title": result.error or "scan failed",
                    "value": result.error_kind or "",
                    "reason": result.error or "",
                    "recommendation": result.hint or "",
                }
            )
            continue
        for finding in result.analysis.findings:
            writer.writerow(
                {
                    **base,
                    "finding_id": finding.id,
                    "severity": finding.severity.value,
                    "category": finding.category,
                    "header": finding.header or "",
                    "title": finding.title,
                    "value": truncate(finding.value or "", 240),
                    "reason": finding.reason,
                    "recommendation": finding.recommendation,
                }
            )
    return buffer.getvalue()


def _md_escape(value: str | None) -> str:
    if not value:
        return ""
    return str(value).replace("|", "\\|").replace("\n", " ")


def to_markdown(results: Sequence[ScanResult]) -> str:
    """Render a Markdown report for one or many targets."""
    lines: list[str] = []
    lines.append("# HeaderSpecter Security Report")
    lines.append("")
    lines.append(f"*Generated {iso_now()} by HeaderSpecter v{__version__} — {AUTHOR} ({AUTHOR_URL})*")
    lines.append("")

    if len(results) > 1:
        lines.append("## Summary")
        lines.append("")
        lines.append("| Target | Status | Score | Grade | Critical | High | Medium | Low | Info |")
        lines.append("|---|---|---|---|---|---|---|---|---|")
        for result in results:
            counts = result.counts
            lines.append(
                f"| {_md_escape(result.final_url or result.target)} "
                f"| {result.status_code or 'ERROR'} "
                f"| {f'{result.score:.0f}' if result.score is not None else '—'} "
                f"| {result.grade} "
                f"| {counts.get('CRITICAL', 0)} | {counts.get('HIGH', 0)} | {counts.get('MEDIUM', 0)} "
                f"| {counts.get('LOW', 0)} | {counts.get('INFO', 0)} |"
            )
        lines.append("")

    for result in results:
        lines.extend(_markdown_target(result))

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(
        "Report produced with [HeaderSpecter](https://github.com/mrdineshpathro-dot/HeaderSpecter) — "
        f"authorised security testing only. Support the author: {AUTHOR_URL}"
    )
    return "\n".join(lines) + "\n"


def _markdown_target(result: ScanResult) -> list[str]:
    lines: list[str] = []
    lines.append(f"## {result.final_url or result.target}")
    lines.append("")
    if not result.ok or result.analysis is None:
        lines.append(f"**Scan failed:** {result.error}")
        if result.hint:
            lines.append("")
            lines.append(f"> {result.hint}")
        lines.append("")
        return lines

    analysis = result.analysis
    score = analysis.score
    counts = analysis.counts
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append(f"| Status | {result.status_code} {result.reason} |")
    lines.append(f"| Final URL | {result.final_url} |")
    lines.append(f"| Protocol | {result.http_version or 'HTTP/1.1'} |")
    lines.append(f"| Response time | {human_duration(result.elapsed_ms)} |")
    if score:
        lines.append(f"| Security score | **{score.score:.0f} / 100** (grade {score.grade}) |")
    lines.append(f"| Scanned at | {result.scanned_at} |")
    lines.append("")
    lines.append(
        f"**Findings:** {counts.get('CRITICAL', 0)} critical · {counts.get('HIGH', 0)} high · "
        f"{counts.get('MEDIUM', 0)} medium · {counts.get('LOW', 0)} low · {counts.get('INFO', 0)} info"
    )
    lines.append("")

    lines.append("### Header security")
    lines.append("")
    lines.append("| Header | Status | Value |")
    lines.append("|---|---|---|")
    for check in list(analysis.header_checks) + list(analysis.extra_checks):
        lines.append(f"| {check.header} | {check.state} | {_md_escape(truncate(check.value or check.note, 90))} |")
    lines.append("")

    issues = analysis.issues
    if issues:
        lines.append("### Findings")
        lines.append("")
        for finding in issues:
            lines.append(f"#### [{finding.severity.value}] {finding.id} — {finding.title}")
            lines.append("")
            if finding.header:
                lines.append(f"- **Header:** `{finding.header}`")
            if finding.value:
                lines.append(f"- **Observed:** `{truncate(finding.value, 200)}`")
            lines.append(f"- **Detail:** {finding.reason}")
            lines.append(f"- **Impact:** {finding.impact}")
            lines.append(f"- **Recommendation:** {finding.recommendation}")
            if finding.remediation:
                lines.append("")
                lines.append("```http")
                lines.append(finding.remediation)
                lines.append("```")
            lines.append("")
    else:
        lines.append("### Findings")
        lines.append("")
        lines.append("No issues detected.")
        lines.append("")

    if analysis.csp and analysis.csp.present:
        lines.append("### CSP analysis")
        lines.append("")
        lines.append("| Check | Status | Detail |")
        lines.append("|---|---|---|")
        for label, status, detail in analysis.csp.rows:
            lines.append(f"| {label} | {status.value} | {_md_escape(detail)} |")
        lines.append("")

    if analysis.cookies and analysis.cookies.cookies:
        lines.append("### Cookies")
        lines.append("")
        lines.append("| Cookie | Secure | HttpOnly | SameSite | Issues |")
        lines.append("|---|---|---|---|---|")
        for cookie in analysis.cookies.cookies:
            lines.append(
                f"| `{cookie.name}` | {'yes' if cookie.secure else 'NO'} | {'yes' if cookie.http_only else 'NO'} "
                f"| {cookie.same_site or 'not set'} | {_md_escape(', '.join(cookie.issues) or '—')} |"
            )
        lines.append("")

    if analysis.tls and analysis.tls.handshake_ok:
        tls = analysis.tls
        lines.append("### TLS")
        lines.append("")
        lines.append(f"- Protocol: {tls.protocol}")
        lines.append(f"- Certificate valid: {'yes' if tls.verified else 'NO'}")
        lines.append(f"- Hostname match: {'yes' if tls.hostname_valid else 'NO'}")
        lines.append(f"- Issuer: {tls.issuer or 'unknown'}")
        lines.append(f"- Expires: {tls.not_after or 'unknown'} ({tls.days_remaining} days remaining)")
        lines.append("")

    if analysis.redirects and analysis.redirects.hops:
        lines.append("### Redirect chain")
        lines.append("")
        for hop in analysis.redirects.hops:
            lines.append(f"{hop.index}. `{hop.url}` → {hop.status_code}")
        lines.append(f"{len(analysis.redirects.hops) + 1}. `{result.final_url}` → {result.status_code}")
        lines.append("")

    if analysis.recommendations:
        lines.append("### Recommendations")
        lines.append("")
        for item in analysis.recommendations:
            lines.append(f"- {item}")
        lines.append("")

    lines.append("<details><summary>Raw headers</summary>")
    lines.append("")
    lines.append("```http")
    lines.append(result.raw_headers_text())
    lines.append("```")
    lines.append("")
    lines.append("</details>")
    lines.append("")
    return lines


# --------------------------------------------------------------------------- #
# Baselines and diffing
# --------------------------------------------------------------------------- #
def save_baseline(result: ScanResult, path: str | Path) -> Path:
    """Persist a scan result as a baseline JSON document."""
    payload = result.to_dict()
    payload["baseline"] = {"created_at": iso_now(), "tool_version": __version__}
    return write_text(path, json.dumps(payload, indent=2, ensure_ascii=False))


def load_baseline(path: str | Path) -> dict[str, Any]:
    """Load a baseline JSON document."""
    file_path = Path(path).expanduser()
    data = json.loads(file_path.read_text(encoding="utf-8"))
    if isinstance(data, Mapping) and "results" in data and isinstance(data["results"], list) and data["results"]:
        return dict(data["results"][0])  # accept batch envelopes too
    return dict(data)


@dataclass(slots=True)
class DiffResult:
    """Difference between a baseline scan and the current scan."""

    label: str = ""
    added: list[tuple[str, str]] = field(default_factory=list)
    removed: list[tuple[str, str]] = field(default_factory=list)
    changed: list[tuple[str, str, str]] = field(default_factory=list)
    new_findings: list[dict[str, Any]] = field(default_factory=list)
    resolved_findings: list[dict[str, Any]] = field(default_factory=list)
    score_before: float | None = None
    score_after: float | None = None
    status_before: int | None = None
    status_after: int | None = None

    @property
    def has_changes(self) -> bool:
        """True when anything changed between the two scans."""
        return bool(
            self.added
            or self.removed
            or self.changed
            or self.new_findings
            or self.resolved_findings
            or self.status_before != self.status_after
        )

    @property
    def score_delta(self) -> float | None:
        """Score difference (``None`` when either side is missing)."""
        if self.score_before is None or self.score_after is None:
            return None
        return round(self.score_after - self.score_before, 1)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "label": self.label,
            "added": [{"header": name, "value": value} for name, value in self.added],
            "removed": [{"header": name, "value": value} for name, value in self.removed],
            "changed": [{"header": name, "before": old, "after": new} for name, old, new in self.changed],
            "new_findings": self.new_findings,
            "resolved_findings": self.resolved_findings,
            "score_before": self.score_before,
            "score_after": self.score_after,
            "score_delta": self.score_delta,
            "status_before": self.status_before,
            "status_after": self.status_after,
            "has_changes": self.has_changes,
        }


#: Headers whose value changes on every response.  They are ignored when
#: diffing two scans so that watch mode only reports meaningful changes.
VOLATILE_HEADERS: frozenset[str] = frozenset(
    {
        "date",
        "age",
        "expires",
        "last-modified",
        "etag",
        "content-length",
        "keep-alive",
        "connection",
        "x-request-id",
        "x-correlation-id",
        "x-trace-id",
        "x-amz-cf-id",
        "x-amz-request-id",
        "cf-ray",
        "x-timer",
        "x-runtime",
        "x-served-by",
        "x-cache-hits",
        "report-to",
        "nel",
        "alt-svc",
        "retry-after",
    }
)

_COOKIE_VALUE_RE = re.compile(r"^(?P<name>[^=;]+)=(?P<value>[^;]*)")


def _stable_cookie(value: str) -> str:
    """Replace the cookie value with a placeholder so only attributes diff."""
    return _COOKIE_VALUE_RE.sub(lambda m: f"{m.group('name')}=<value>", value, count=1)


def _headers_map(payload: Mapping[str, Any], ignore_volatile: bool = True) -> dict[str, str]:
    headers: dict[str, list[str]] = {}
    for item in payload.get("headers", []) or []:
        if isinstance(item, Mapping):
            name = str(item.get("name", "")).strip().lower()
            value = str(item.get("value", ""))
        else:  # tolerate [name, value] pairs
            name, value = str(item[0]).strip().lower(), str(item[1])
        if not name:
            continue
        if ignore_volatile and name in VOLATILE_HEADERS:
            continue
        if name == "set-cookie":
            value = _stable_cookie(value)
        headers.setdefault(name, []).append(value)
    return {name: ", ".join(sorted(values)) for name, values in headers.items()}


def _findings_map(payload: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    analysis = payload.get("analysis") or {}
    findings = analysis.get("findings", []) if isinstance(analysis, Mapping) else []
    result: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        if str(finding.get("severity")) == Severity.PASS.value:
            continue
        raw_value = str(finding.get("value") or "")
        if str(finding.get("header") or "").lower() == "set-cookie":
            raw_value = _stable_cookie(raw_value)
        key = f"{finding.get('id')}::{finding.get('header') or ''}::{truncate(raw_value, 60)}"
        result[key] = dict(finding)
    return result


def compare_payloads(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    label: str = "",
    ignore_volatile: bool = True,
) -> DiffResult:
    """Diff two serialised scan results.

    Volatile headers (``Date``, ``ETag``, request ids, …) and cookie *values*
    are ignored by default so that continuous monitoring only reports changes
    that actually affect security posture.
    """
    diff = DiffResult(label=label or f"{before.get('final_url', '?')} → {after.get('final_url', '?')}")
    old_headers = _headers_map(before, ignore_volatile)
    new_headers = _headers_map(after, ignore_volatile)

    from .headers import normalize_header_name

    for name in sorted(set(new_headers) - set(old_headers)):
        diff.added.append((normalize_header_name(name), new_headers[name]))
    for name in sorted(set(old_headers) - set(new_headers)):
        diff.removed.append((normalize_header_name(name), old_headers[name]))
    for name in sorted(set(old_headers) & set(new_headers)):
        if old_headers[name] != new_headers[name]:
            diff.changed.append((normalize_header_name(name), old_headers[name], new_headers[name]))

    old_findings = _findings_map(before)
    new_findings = _findings_map(after)
    for key in new_findings.keys() - old_findings.keys():
        diff.new_findings.append(new_findings[key])
    for key in old_findings.keys() - new_findings.keys():
        diff.resolved_findings.append(old_findings[key])
    diff.new_findings.sort(key=lambda item: str(item.get("severity")))
    diff.resolved_findings.sort(key=lambda item: str(item.get("severity")))

    diff.score_before = before.get("score")
    diff.score_after = after.get("score")
    diff.status_before = before.get("status_code")
    diff.status_after = after.get("status_code")
    return diff


def compare_results(before: ScanResult, after: ScanResult) -> DiffResult:
    """Diff two live scan results (used by watch mode)."""
    return compare_payloads(before.to_dict(), after.to_dict(), label=after.final_url or after.target)


def compare_to_baseline(result: ScanResult, baseline: Mapping[str, Any]) -> DiffResult:
    """Diff the current scan against a stored baseline."""
    label = f"baseline {baseline.get('scanned_at', 'unknown')} → now"
    return compare_payloads(baseline, result.to_dict(), label=label)


def write_report(
    results: Sequence[ScanResult],
    path: str | Path,
    fmt: str,
) -> Path:
    """Write ``results`` to ``path`` in the requested format."""
    fmt = fmt.lower()
    if fmt == "json":
        content = to_json(results)
    elif fmt == "csv":
        content = to_csv(results)
    elif fmt in {"md", "markdown"}:
        content = to_markdown(results)
    elif fmt == "html":
        from .html_report import render_html

        content = render_html(results)
    else:  # pragma: no cover - guarded by the CLI
        raise ValueError(f"Unsupported report format: {fmt}")
    return write_text(path, content)


def summarize_counts(results: Iterable[ScanResult]) -> dict[str, int]:
    """Aggregate finding counts across many results."""
    totals: dict[str, int] = {severity.value: 0 for severity in Severity}
    for result in results:
        for key, value in (result.counts or {}).items():
            totals[key] = totals.get(key, 0) + value
    return totals
