"""Terminal user interface built on :mod:`rich`.

Everything visual lives here: the ASCII banner, the colour/icon system, the
section renderers used by the terminal reporter, progress bars for batch scans
and the interactive menu.  The UI degrades gracefully: ``--no-color`` strips
styling, non-UTF-8 terminals fall back to ASCII icons and narrow terminals get
a compact banner.
"""

from __future__ import annotations

import shutil
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from rich.align import Align
from rich.box import HEAVY, ROUNDED, SIMPLE
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from . import AUTHOR, AUTHOR_URL, TAGLINE, __version__
from .findings import Finding, Severity, server_config_examples
from .utils import human_duration, supports_unicode, truncate, truncate_middle

__all__ = ["UI", "Icons", "HEADERSPECTER_THEME", "build_console"]


HEADERSPECTER_THEME = Theme(
    {
        "hs.title": "bold bright_cyan",
        "hs.subtitle": "bright_white",
        "hs.accent": "bright_magenta",
        "hs.dim": "grey58",
        "hs.value": "bold bright_white",
        "hs.label": "cyan",
        "hs.rule": "bright_cyan",
        "hs.ok": "bold green",
        "hs.warn": "bold yellow",
        "hs.bad": "bold red",
        "hs.crit": "bold bright_red",
        "hs.info": "bold blue",
        "hs.low": "bold cyan",
        "sev.CRITICAL": "bold bright_red",
        "sev.HIGH": "bold red",
        "sev.MEDIUM": "bold yellow",
        "sev.LOW": "bold cyan",
        "sev.INFO": "bold blue",
        "sev.PASS": "bold green",
    }
)

#: Gradient used for the ASCII banner (top to bottom).
_BANNER_GRADIENT = (
    "bright_cyan",
    "cyan",
    "bright_blue",
    "blue",
    "magenta",
    "bright_magenta",
)

_BLOCK_FONT: dict[str, tuple[str, ...]] = {
    "H": ("██╗  ██╗", "██║  ██║", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"),
    "E": ("███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"),
    "A": (" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"),
    "D": ("██████╗ ", "██╔══██╗", "██║  ██║", "██║  ██║", "██████╔╝", "╚═════╝ "),
    "R": ("██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"),
    "S": ("███████╗", "██╔════╝", "███████╗", "╚════██║", "███████║", "╚══════╝"),
    "P": ("██████╗ ", "██╔══██╗", "██████╔╝", "██╔═══╝ ", "██║     ", "╚═╝     "),
    "C": (" ██████╗", "██╔════╝", "██║     ", "██║     ", "╚██████╗", " ╚═════╝"),
    "T": ("████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "),
    " ": ("  ", "  ", "  ", "  ", "  ", "  "),
}


@dataclass(frozen=True)
class Icons:
    """Status icons with an ASCII fallback for limited terminals."""

    unicode: bool = True

    @property
    def pass_(self) -> str:
        """Icon for a passing check."""
        return "✓" if self.unicode else "[+]"

    @property
    def critical(self) -> str:
        """Icon for a critical finding."""
        return "⛔" if self.unicode else "[C]"

    @property
    def high(self) -> str:
        """Icon for a high severity finding."""
        return "✗" if self.unicode else "[H]"

    @property
    def warn(self) -> str:
        """Icon for a medium severity finding."""
        return "⚠" if self.unicode else "[M]"

    @property
    def low(self) -> str:
        """Icon for a low severity finding."""
        return "▲" if self.unicode else "[L]"

    @property
    def info(self) -> str:
        """Icon for informational output."""
        return "ℹ" if self.unicode else "[i]"

    @property
    def arrow(self) -> str:
        """Recommendation arrow."""
        return "→" if self.unicode else "->"

    @property
    def down(self) -> str:
        """Redirect arrow."""
        return "↓" if self.unicode else "v"

    @property
    def bullet(self) -> str:
        """List bullet."""
        return "•" if self.unicode else "*"

    @property
    def coffee(self) -> str:
        """Support link marker."""
        return "☕" if self.unicode else "(c)"

    @property
    def bar_filled(self) -> str:
        """Filled score-bar block."""
        return "█" if self.unicode else "#"

    @property
    def bar_empty(self) -> str:
        """Empty score-bar block."""
        return "░" if self.unicode else "."

    def for_severity(self, severity: Severity) -> str:
        """Return the icon matching ``severity``."""
        return {
            Severity.CRITICAL: self.critical,
            Severity.HIGH: self.high,
            Severity.MEDIUM: self.warn,
            Severity.LOW: self.low,
            Severity.INFO: self.info,
            Severity.PASS: self.pass_,
        }[severity]


def build_console(no_color: bool = False, quiet: bool = False, width: int | None = None) -> Console:
    """Create the shared Rich console."""
    detected = shutil.get_terminal_size(fallback=(100, 24)).columns
    resolved_width = width or min(max(detected, 60), 118)
    return Console(
        theme=HEADERSPECTER_THEME,
        no_color=no_color,
        highlight=False,
        soft_wrap=False,
        width=resolved_width,
        quiet=quiet,
    )


class UI:
    """High level renderer for every HeaderSpecter terminal view."""

    def __init__(self, console: Console | None = None, no_color: bool = False, quiet: bool = False) -> None:
        """Create a UI bound to a Rich console."""
        self.console = console or build_console(no_color=no_color, quiet=quiet)
        self.icons = Icons(unicode=supports_unicode(self.console.file))
        self.quiet = quiet
        self.no_color = no_color

    # ------------------------------------------------------------------ #
    # Primitives
    # ------------------------------------------------------------------ #
    def print(self, renderable: RenderableType = "", **kwargs: Any) -> None:
        """Print through the managed console."""
        self.console.print(renderable, **kwargs)

    def blank(self) -> None:
        """Print an empty line (suppressed in quiet mode)."""
        if not self.quiet:
            self.console.print()

    def section(self, title: str, subtitle: str = "") -> None:
        """Render a section heading with a heavy rule."""
        if self.quiet:
            return
        label = Text(title.upper(), style="hs.title")
        if subtitle:
            label.append(f"  {subtitle}", style="hs.dim")
        self.console.print()
        self.console.print(label)
        self.console.print(Rule(style="hs.rule", characters="━" if self.icons.unicode else "-"))

    def error(self, message: str, hint: str | None = None) -> None:
        """Print a friendly error (never a traceback)."""
        self.console.print(Text.assemble(("[ERROR] ", "hs.bad"), (message, "bright_white")))
        if hint:
            self.console.print(Text.assemble(("[INFO]  ", "hs.info"), (hint, "hs.dim")))

    def warn(self, message: str) -> None:
        """Print a warning line."""
        self.console.print(Text.assemble(("[WARN]  ", "hs.warn"), (message, "bright_white")))

    def info(self, message: str) -> None:
        """Print an informational line."""
        if not self.quiet:
            self.console.print(Text.assemble(("[INFO]  ", "hs.info"), (message, "hs.dim")))

    def success(self, message: str) -> None:
        """Print a success line."""
        if not self.quiet:
            self.console.print(Text.assemble((f"{self.icons.pass_} ", "hs.ok"), (message, "bright_white")))

    @contextmanager
    def status(self, message: str) -> Iterator[None]:
        """Spinner shown while network activity is in progress."""
        if self.quiet or not self.console.is_terminal:
            yield
            return
        with self.console.status(Text(message, style="hs.label"), spinner="dots"):
            yield

    def progress(self, total: int, description: str = "Scanning targets") -> Progress:
        """Build the batch scanning progress bar."""
        progress = Progress(
            SpinnerColumn(style="hs.accent"),
            TextColumn("[hs.label]{task.description}"),
            BarColumn(bar_width=None, complete_style="bright_cyan", finished_style="green"),
            MofNCompleteColumn(),
            TextColumn("[hs.dim]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
            disable=self.quiet,
        )
        progress.add_task(description, total=total)
        return progress

    # ------------------------------------------------------------------ #
    # Branding
    # ------------------------------------------------------------------ #
    def banner(self, compact: bool = False) -> None:
        """Render the startup banner."""
        if self.quiet:
            return
        width = self.console.width
        if compact or width < 62 or not self.icons.unicode:
            self._compact_banner()
            return

        letters = [_BLOCK_FONT[ch] for ch in "HEADER"]
        lines = ["".join(letter[row] for letter in letters) for row in range(6)]
        art = Text()
        for index, line in enumerate(lines):
            art.append(line + "\n", style=_BANNER_GRADIENT[index % len(_BANNER_GRADIENT)])
        art.append("░▒▓ ", style="bright_magenta")
        art.append("S P E C T E R", style="bold bright_white")
        art.append(f"  ▓▒░  v{__version__}", style="bright_magenta")

        subtitle = Text()
        subtitle.append(TAGLINE, style="hs.subtitle")
        subtitle.append("\nCreated by ", style="hs.dim")
        subtitle.append(AUTHOR, style="bold bright_yellow")
        subtitle.append(f"   {self.icons.coffee} ", style="hs.dim")
        subtitle.append(AUTHOR_URL, style="underline bright_blue")

        self.console.print(
            Panel(
                Group(Align.center(art), Text(), Align.center(subtitle)),
                box=ROUNDED,
                border_style="hs.rule",
                padding=(1, 2),
            )
        )

    def _compact_banner(self) -> None:
        title = Text()
        title.append("HeaderSpecter", style="hs.title")
        title.append(f" v{__version__}", style="hs.dim")
        title.append("\n")
        title.append(TAGLINE, style="hs.subtitle")
        title.append("\n")
        title.append(f"by {AUTHOR}  {self.icons.coffee} {AUTHOR_URL}", style="hs.dim")
        self.console.print(Panel(title, box=ROUNDED, border_style="hs.rule", padding=(0, 2)))

    def about(self) -> None:
        """Render the About panel."""
        body = Text()
        body.append("HeaderSpecter", style="hs.title")
        body.append(f"  v{__version__}\n", style="hs.dim")
        body.append(f"{TAGLINE}\n\n", style="hs.subtitle")
        body.append("Author      : ", style="hs.label")
        body.append(f"{AUTHOR}\n", style="hs.value")
        body.append("Support     : ", style="hs.label")
        body.append(f"{AUTHOR_URL}\n", style="underline bright_blue")
        body.append("Platform    : ", style="hs.label")
        body.append("Kali Linux, any POSIX system, Python 3.10+\n", style="hs.value")
        body.append("Purpose     : ", style="hs.label")
        body.append(
            "Defensive security auditing — header posture assessment,\n"
            "              hardening guidance and regression testing.\n\n",
            style="hs.value",
        )
        body.append(
            "Use HeaderSpecter only against systems you own or are explicitly\n"
            "authorised to assess.",
            style="hs.warn",
        )
        self.console.print(Panel(body, box=ROUNDED, border_style="hs.accent", title="About", padding=(1, 2)))

    def legal_notice(self) -> None:
        """One-line authorised-use reminder."""
        self.console.print(
            Text(
                "Authorised use only — scan systems you own or have written permission to test.",
                style="hs.dim",
            )
        )

    # ------------------------------------------------------------------ #
    # Severity helpers
    # ------------------------------------------------------------------ #
    def severity_text(self, severity: Severity, width: int = 8) -> Text:
        """Render a padded, coloured severity badge."""
        icon = self.icons.for_severity(severity)
        return Text(f"{icon} {severity.value:<{width}}", style=f"sev.{severity.value}")

    def status_text(self, severity: Severity, state: str) -> Text:
        """Render a state label (PASS/WARNING/…) in the severity colour."""
        return Text(f"{self.icons.for_severity(severity)} {state}", style=f"sev.{severity.value}")

    # ------------------------------------------------------------------ #
    # Sections
    # ------------------------------------------------------------------ #
    def target_summary(self, result: Any) -> None:
        """Render the target/response overview panel."""
        analysis = result.analysis
        table = Table.grid(padding=(0, 2))
        table.add_column(style="hs.label", no_wrap=True)
        table.add_column(style="hs.value", overflow="fold")

        status_style = "hs.ok" if (result.status_code or 0) < 400 else "hs.warn"
        table.add_row("Target", result.target)
        if result.final_url and result.final_url != result.url:
            table.add_row("Final URL", result.final_url)
        table.add_row(
            "Status",
            Text(f"{result.status_code} {result.reason}".strip(), style=status_style),
        )
        table.add_row("Protocol", ("HTTPS" if result.final_url.startswith("https") else "HTTP") + f" · {result.http_version or 'HTTP/1.1'}")
        table.add_row("Response", human_duration(result.elapsed_ms))
        if analysis is not None:
            ctype = analysis.context.content_type or "unknown"
            table.add_row("Content-Type", ctype)
            if analysis.redirects:
                table.add_row("Redirects", str(analysis.redirects.count))
            if analysis.cookies:
                table.add_row("Cookies", str(analysis.cookies.count))
            table.add_row("Headers", str(len(result.headers)))
        table.add_row("Scanned", result.scanned_at)

        self.console.print(
            Panel(table, title="Response", box=ROUNDED, border_style="hs.rule", title_align="left", padding=(1, 2))
        )

    def score_panel(self, score: Any, counts: dict[str, int]) -> None:
        """Render the security score block."""
        bar_width = max(18, min(40, self.console.width - 34))
        bar = score.bar(bar_width, self.icons.bar_filled, self.icons.bar_empty)

        big = Text()
        big.append(f"{score.score:.0f}", style=score.grade_style)
        big.append(" / 100   ", style="hs.dim")
        big.append(f"Grade {score.grade}", style=score.grade_style)

        bar_text = Text(bar, style=score.grade_style)

        counters = Table.grid(padding=(0, 3))
        for _ in range(5):
            counters.add_column(justify="left")
        counters.add_row(
            *[
                Text.assemble(
                    (f"{self.icons.for_severity(sev)} {sev.value.title():<9}", f"sev.{sev.value}"),
                    (str(counts.get(sev.value, 0)), "hs.value"),
                )
                for sev in (
                    Severity.CRITICAL,
                    Severity.HIGH,
                    Severity.MEDIUM,
                    Severity.LOW,
                    Severity.INFO,
                )
            ]
        )

        detail = Text()
        detail.append(f"base {score.base_score:.0f}", style="hs.dim")
        detail.append(f"  −{score.total_deducted:.1f} deductions", style="hs.dim")
        if score.total_bonus:
            detail.append(f"  +{score.total_bonus:.1f} bonus", style="hs.dim")

        self.console.print(
            Panel(
                Group(big, bar_text, Text(), counters, detail),
                title="Security Score",
                box=ROUNDED,
                border_style=score.grade_style.replace("bold ", ""),
                title_align="left",
                padding=(1, 2),
            )
        )

    def header_table(self, checks: Sequence[Any], title: str = "Header Security") -> None:
        """Render the per-header status table."""
        if not checks:
            return
        table = Table(box=SIMPLE, expand=True, show_edge=False, pad_edge=False)
        table.add_column("", width=2, no_wrap=True)
        table.add_column("Header", style="hs.label", no_wrap=True)
        table.add_column("Status", no_wrap=True, width=10)
        table.add_column("Value / Note", style="hs.dim", overflow="ellipsis")

        for check in checks:
            severity = check.status
            value = check.value or check.note or "—"
            table.add_row(
                Text(self.icons.for_severity(severity), style=f"sev.{severity.value}"),
                check.header,
                Text(check.state, style=f"sev.{severity.value}"),
                truncate(value, max(24, self.console.width - 46)),
            )
        self.section(title)
        self.console.print(table)

    def rows_panel(self, title: str, rows: Sequence[tuple[str, Severity, str]], border: str = "hs.rule") -> None:
        """Render a list of ``(label, severity, detail)`` rows inside a panel."""
        if not rows:
            return
        table = Table.grid(padding=(0, 2))
        table.add_column(width=2, no_wrap=True)
        table.add_column(style="hs.label", no_wrap=True)
        table.add_column(style="bright_white", overflow="fold")
        for label, severity, detail in rows:
            table.add_row(
                Text(self.icons.for_severity(severity), style=f"sev.{severity.value}"),
                label,
                Text(detail or "", style="hs.dim" if severity is Severity.INFO else ""),
            )
        self.console.print(
            Panel(table, title=title, box=ROUNDED, border_style=border, title_align="left", padding=(1, 2))
        )

    def csp_section(self, csp: Any) -> None:
        """Render the CSP analysis."""
        self.section("CSP Analysis", "Content-Security-Policy")
        if not csp or not csp.present:
            self.console.print(
                Text.assemble(
                    (f"{self.icons.high} ", "sev.HIGH"),
                    ("No Content-Security-Policy header was returned.", "bright_white"),
                )
            )
            return

        checks = Table.grid(padding=(0, 2))
        checks.add_column(width=2, no_wrap=True)
        checks.add_column(style="hs.label", no_wrap=True)
        checks.add_column(style="bright_white", overflow="fold")
        for label, severity, detail in csp.rows:
            checks.add_row(
                Text(self.icons.for_severity(severity), style=f"sev.{severity.value}"),
                label,
                Text(detail, style="hs.dim" if severity in (Severity.INFO, Severity.PASS) else ""),
            )
        self.console.print(checks)

        if csp.directive_rows:
            table = Table(box=SIMPLE, expand=True, show_edge=False, title_justify="left")
            table.add_column("Directive", style="hs.label", no_wrap=True)
            table.add_column("Value", style="bright_white", overflow="fold")
            table.add_column("Note", style="hs.dim", no_wrap=True)
            for row in csp.directive_rows:
                table.add_row(
                    Text(row.directive, style=f"sev.{row.status.value}" if row.status is not Severity.PASS else "hs.label"),
                    truncate(row.value, max(30, self.console.width - 46)),
                    row.note,
                )
            self.console.print()
            self.console.print(table)

    def cookie_section(self, cookies: Any) -> None:
        """Render per-cookie security analysis."""
        self.section("Cookie Security")
        if not cookies or not cookies.cookies:
            self.console.print(Text(f"{self.icons.pass_} No cookies were set by this response.", style="hs.ok"))
            return
        for cookie in cookies.cookies:
            body = Table.grid(padding=(0, 2))
            body.add_column(style="hs.label", no_wrap=True)
            body.add_column(style="bright_white", overflow="fold")
            body.add_row("Value", cookie.value_preview)
            body.add_row(
                "Secure",
                Text(f"{self.icons.pass_} yes", style="hs.ok") if cookie.secure else Text(f"{self.icons.warn} missing", style="hs.warn"),
            )
            body.add_row(
                "HttpOnly",
                Text(f"{self.icons.pass_} yes", style="hs.ok") if cookie.http_only else Text(f"{self.icons.warn} missing", style="hs.warn"),
            )
            body.add_row(
                "SameSite",
                Text(f"{self.icons.pass_} {cookie.same_site}", style="hs.ok")
                if cookie.same_site
                else Text(f"{self.icons.warn} missing", style="hs.warn"),
            )
            if cookie.domain:
                body.add_row("Domain", cookie.domain)
            if cookie.path:
                body.add_row("Path", cookie.path)
            if cookie.expires:
                body.add_row("Expires", cookie.expires)
            if cookie.max_age is not None:
                body.add_row("Max-Age", str(cookie.max_age))
            if cookie.issues:
                body.add_row("Issues", Text(", ".join(cookie.issues), style="hs.warn"))
            title = Text(cookie.name, style=f"sev.{cookie.status.value}")
            if cookie.prefix:
                title.append(f"  [{cookie.prefix}]", style="hs.dim")
            self.console.print(
                Panel(body, title=title, box=ROUNDED, border_style=f"sev.{cookie.status.value}", title_align="left", padding=(0, 2))
            )

    def redirect_section(self, redirects: Any, final_url: str, final_status: int | None) -> None:
        """Render the redirect chain."""
        self.section("Redirect Chain")
        if redirects is None or not redirects.hops:
            self.console.print(Text(f"{self.icons.pass_} No redirects — direct response.", style="hs.ok"))
            return
        body = Text()
        for hop in redirects.hops:
            body.append(f"{hop.index}. ", style="hs.dim")
            body.append(hop.url + "\n", style="bright_white")
            body.append(f"   {self.icons.down} {hop.status_code}", style="hs.accent")
            if hop.location:
                body.append(f"  {truncate(hop.location, 60)}", style="hs.dim")
            body.append("\n\n")
        body.append(f"{len(redirects.hops) + 1}. ", style="hs.dim")
        body.append(final_url + "\n", style="bold bright_white")
        body.append(f"   {self.icons.down} {final_status}", style="hs.ok" if (final_status or 0) < 400 else "hs.warn")
        self.console.print(body)
        if redirects.rows:
            self.rows_panel("Redirect Observations", redirects.rows)

    def findings_section(self, findings: Sequence[Finding], verbose: bool = False, detail_limit: int = 3) -> None:
        """Render the findings table plus detail panels."""
        issues = [finding for finding in findings if finding.is_issue]
        self.section("Findings", f"{len(issues)} issue(s)")
        if not issues:
            self.console.print(Text(f"{self.icons.pass_} No issues detected — excellent posture.", style="hs.ok"))
            return

        table = Table(box=SIMPLE, expand=True, show_edge=False)
        table.add_column("Severity", no_wrap=True, width=12)
        table.add_column("ID", style="hs.dim", no_wrap=True, width=7)
        table.add_column("Finding", style="bright_white", overflow="fold")
        table.add_column("Header", style="hs.label", no_wrap=True, overflow="ellipsis", max_width=26)
        for finding in issues:
            table.add_row(
                self.severity_text(finding.severity),
                finding.id,
                finding.title,
                finding.header or "—",
            )
        self.console.print(table)

        detailed = issues if verbose else [f for f in issues if f.severity in (Severity.CRITICAL, Severity.HIGH)][:detail_limit]
        if not detailed:
            return
        self.console.print()
        for finding in detailed:
            self.finding_detail(finding, show_examples=verbose)

    def finding_detail(self, finding: Finding, show_examples: bool = False) -> None:
        """Render one finding as a detail panel."""
        body = Text()
        if finding.value:
            body.append("Observed  : ", style="hs.label")
            body.append(truncate(finding.value, 220) + "\n", style="bright_white")
        body.append("Detail    : ", style="hs.label")
        body.append(finding.reason + "\n\n", style="bright_white")
        body.append("Impact    : ", style="hs.label")
        body.append(finding.impact + "\n\n", style="hs.dim")
        body.append("Fix       : ", style="hs.label")
        body.append(finding.recommendation, style="bright_white")
        renderables: list[RenderableType] = [body]

        if finding.remediation:
            snippet = Text()
            snippet.append("\nRecommended header\n", style="hs.label")
            for line in finding.remediation.splitlines():
                snippet.append(f"  {line}\n", style="bright_green")
            renderables.append(snippet)
        if show_examples and finding.remediation and finding.header:
            header_name = finding.remediation.split(":")[0].strip()
            value = finding.remediation.split(":", 1)[1].strip() if ":" in finding.remediation else ""
            if header_name and value and "\n" not in finding.remediation:
                examples = server_config_examples(header_name, value)
                table = Table(box=SIMPLE, show_edge=False, expand=True)
                table.add_column("Stack", style="hs.label", no_wrap=True)
                table.add_column("Template", style="hs.dim", overflow="fold")
                for stack, snippet in examples.items():
                    table.add_row(stack, snippet)
                renderables.append(
                    Panel(table, title="Deployment templates (review before use)", box=SIMPLE, border_style="hs.dim", title_align="left")
                )

        self.console.print(
            Panel(
                Group(*renderables),
                title=Text.assemble(
                    (f"[{finding.severity.value}] ", f"sev.{finding.severity.value}"),
                    (f"{finding.id}  ", "hs.dim"),
                    (finding.title, "bold bright_white"),
                ),
                box=ROUNDED,
                border_style=f"sev.{finding.severity.value}",
                title_align="left",
                padding=(1, 2),
            )
        )

    def disclosure_section(self, items: Sequence[Any]) -> None:
        """Render the technology disclosure table."""
        self.section("Technology Disclosure", "information disclosure observations")
        if not items:
            self.console.print(Text(f"{self.icons.pass_} No revealing technology headers detected.", style="hs.ok"))
            return
        table = Table(box=SIMPLE, expand=True, show_edge=False)
        table.add_column("", width=2, no_wrap=True)
        table.add_column("Header", style="hs.label", no_wrap=True)
        table.add_column("Value", style="bright_white", overflow="fold")
        table.add_column("Note", style="hs.dim", no_wrap=True)
        for item in items:
            table.add_row(
                Text(self.icons.for_severity(item.severity), style=f"sev.{item.severity.value}"),
                item.header,
                truncate(item.value, 60),
                item.note,
            )
        self.console.print(table)
        self.console.print(
            Text(
                "These are observations, not vulnerabilities — they lower the cost of reconnaissance.",
                style="hs.dim",
            )
        )

    def recommendations_section(self, recommendations: Sequence[str]) -> None:
        """Render the short action list."""
        if not recommendations:
            return
        self.section("Recommendations")
        for item in recommendations:
            self.console.print(Text.assemble((f"{self.icons.arrow} ", "hs.accent"), (item, "bright_white")))

    def raw_headers_section(self, result: Any) -> None:
        """Render the raw response head exactly as received."""
        self.section("Raw Headers")
        text = Text()
        if result.status_code is not None:
            text.append(f"{result.http_version or 'HTTP/1.1'} {result.status_code} {result.reason}\n", style="hs.accent")
        for name, value in result.headers:
            text.append(f"{name}: ", style="hs.label")
            text.append(f"{value}\n", style="bright_white")
        self.console.print(Panel(text, box=ROUNDED, border_style="hs.dim", padding=(1, 2)))

    def score_breakdown(self, score: Any) -> None:
        """Render the transparent score breakdown table."""
        if not score or not score.deductions:
            return
        self.section("Score Breakdown", "every deduction is explained")
        table = Table(box=SIMPLE, expand=True, show_edge=False)
        table.add_column("ID", style="hs.dim", no_wrap=True, width=7)
        table.add_column("Severity", no_wrap=True, width=12)
        table.add_column("Category", style="hs.label", no_wrap=True)
        table.add_column("Finding", style="bright_white", overflow="ellipsis")
        table.add_column("Points", justify="right", style="hs.warn", no_wrap=True)
        for item in score.deductions:
            severity = Severity.parse(item.severity)
            table.add_row(
                item.finding_id,
                self.severity_text(severity),
                item.category,
                item.title,
                f"-{item.applied_points:.1f}" + ("*" if item.capped else ""),
            )
        for bonus in score.bonuses:
            table.add_row("BONUS", Text(" +", style="hs.ok"), "bonus", bonus.reason, f"+{bonus.points:.1f}")
        self.console.print(table)
        self.console.print(
            Text(
                f"base {score.base_score:.0f} − {score.total_deducted:.1f} + {score.total_bonus:.1f} = {score.score:.1f}"
                + ("   (* capped by category limit)" if any(d.capped for d in score.deductions) else ""),
                style="hs.dim",
            )
        )

    # ------------------------------------------------------------------ #
    # Batch views
    # ------------------------------------------------------------------ #
    def batch_summary(self, results: Sequence[Any]) -> None:
        """Render the batch scoreboard and dashboard."""
        self.section("Batch Summary", f"{len(results)} target(s)")
        table = Table(box=SIMPLE, expand=True, show_edge=False)
        table.add_column("Target", style="bright_white", overflow="ellipsis", max_width=42)
        table.add_column("Status", no_wrap=True, width=8)
        table.add_column("Score", justify="right", no_wrap=True, width=6)
        table.add_column("Grade", no_wrap=True, width=6)
        table.add_column("C", justify="right", width=3, style="sev.CRITICAL")
        table.add_column("H", justify="right", width=3, style="sev.HIGH")
        table.add_column("M", justify="right", width=3, style="sev.MEDIUM")
        table.add_column("L", justify="right", width=3, style="sev.LOW")
        table.add_column("I", justify="right", width=3, style="sev.INFO")
        table.add_column("Time", justify="right", no_wrap=True, width=9)

        for result in results:
            if not result.ok:
                table.add_row(
                    result.target,
                    Text("ERROR", style="hs.bad"),
                    "—",
                    Text("ERR", style="hs.bad"),
                    "—", "—", "—", "—", "—",
                    "—",
                )
                continue
            counts = result.counts
            grade_style = result.analysis.score.grade_style if result.analysis and result.analysis.score else "hs.dim"
            table.add_row(
                result.final_url or result.target,
                Text(str(result.status_code), style="hs.ok" if (result.status_code or 0) < 400 else "hs.warn"),
                Text(f"{result.score:.0f}", style=grade_style),
                Text(result.grade, style=grade_style),
                str(counts.get("CRITICAL", 0)),
                str(counts.get("HIGH", 0)),
                str(counts.get("MEDIUM", 0)),
                str(counts.get("LOW", 0)),
                str(counts.get("INFO", 0)),
                human_duration(result.elapsed_ms),
            )
        self.console.print(table)

        scored = [r for r in results if r.ok and r.score is not None]
        failed = [r for r in results if not r.ok]
        if not scored:
            return
        average = sum(r.score for r in scored) / len(scored)
        best = max(scored, key=lambda r: r.score)
        worst = min(scored, key=lambda r: r.score)
        stats = (
            ("Targets", str(len(results)), "hs.accent"),
            ("Average score", f"{average:.1f}", "bright_cyan"),
            ("Best", f"{best.score:.0f} · {_short_label(best, 15)}", "green"),
            ("Worst", f"{worst.score:.0f} · {_short_label(worst, 15)}", "red"),
            ("Failed", str(len(failed)), "hs.bad" if failed else "hs.dim"),
        )
        grid = Table.grid(expand=True, padding=(0, 1))
        for _ in stats:
            grid.add_column(justify="center", ratio=1, no_wrap=True, overflow="ellipsis")
        grid.add_row(*[Text(value, style=f"bold {style}", no_wrap=True, overflow="ellipsis") for _, value, style in stats])
        grid.add_row(*[Text(label, style="hs.dim") for label, _, _ in stats])
        self.console.print(
            Panel(grid, box=ROUNDED, border_style="hs.rule", title="Dashboard", title_align="left", padding=(1, 2))
        )

    # ------------------------------------------------------------------ #
    # Diff view
    # ------------------------------------------------------------------ #
    def diff_section(self, diff: Any) -> None:
        """Render a baseline comparison."""
        self.section("Header Changes", diff.label)
        if not (diff.added or diff.removed or diff.changed):
            self.console.print(Text(f"{self.icons.pass_} No header changes since the baseline.", style="hs.ok"))
        else:
            for name, value in diff.added:
                self.console.print(Text.assemble(("+ ", "hs.ok"), (name, "bold bright_white"), (f"  {truncate(value, 60)}", "hs.dim")))
            for name, value in diff.removed:
                self.console.print(Text.assemble(("- ", "hs.bad"), (name, "bold bright_white"), (f"  {truncate(value, 60)}", "hs.dim")))
            for name, old, new in diff.changed:
                self.console.print(Text.assemble(("~ ", "hs.warn"), (name, "bold bright_white")))
                self.console.print(Text(f"    was : {truncate(old, 80)}", style="hs.dim"))
                self.console.print(Text(f"    now : {truncate(new, 80)}", style="bright_white"))

        if diff.new_findings or diff.resolved_findings:
            self.section("Finding Changes")
            for finding in diff.new_findings:
                self.console.print(
                    Text.assemble(
                        ("NEW      ", "hs.bad"),
                        (f"[{finding['severity']}] ", f"sev.{finding['severity']}"),
                        (f"{finding['id']} {finding['title']}", "bright_white"),
                    )
                )
            for finding in diff.resolved_findings:
                self.console.print(
                    Text.assemble(
                        ("RESOLVED ", "hs.ok"),
                        (f"[{finding['severity']}] ", f"sev.{finding['severity']}"),
                        (f"{finding['id']} {finding['title']}", "bright_white"),
                    )
                )

        if diff.score_before is not None and diff.score_after is not None:
            delta = diff.score_after - diff.score_before
            style = "hs.ok" if delta >= 0 else "hs.bad"
            sign = "+" if delta >= 0 else ""
            self.console.print()
            self.console.print(
                Text.assemble(
                    ("Score  ", "hs.label"),
                    (f"{diff.score_before:.0f}", "hs.dim"),
                    (f" {self.icons.arrow} ", "hs.dim"),
                    (f"{diff.score_after:.0f}", "bold bright_white"),
                    (f"  ({sign}{delta:.1f})", style),
                )
            )

    # ------------------------------------------------------------------ #
    # Interactive menu
    # ------------------------------------------------------------------ #
    def menu(self, entries: Sequence[tuple[str, str]], title: str = "HeaderSpecter") -> None:
        """Render the interactive main menu."""
        table = Table.grid(padding=(0, 2))
        table.add_column(style="hs.accent", no_wrap=True)
        table.add_column(style="bright_white")
        for key, label in entries:
            table.add_row(f"[{key}]", label)
        self.console.print(
            Panel(table, title=title, box=HEAVY, border_style="hs.rule", title_align="left", padding=(1, 2))
        )

    def key_value_panel(self, title: str, data: dict[str, Any], border: str = "hs.rule") -> None:
        """Render a simple key/value panel (used by the config view)."""
        table = Table.grid(padding=(0, 2))
        table.add_column(style="hs.label", no_wrap=True)
        table.add_column(style="bright_white", overflow="fold")
        for key, value in data.items():
            table.add_row(str(key), str(value))
        self.console.print(Panel(table, title=title, box=ROUNDED, border_style=border, title_align="left", padding=(1, 2)))

    def footer(self, message: str = "Scan completed successfully.") -> None:
        """Render the closing line with author branding."""
        if self.quiet:
            return
        self.console.print()
        self.console.print(Text.assemble((f"{self.icons.pass_} ", "hs.ok"), (message, "bright_white")))
        self.footer_branding()

    def footer_branding(self) -> None:
        """Print the one-line author/branding footer."""
        if self.quiet:
            return
        self.console.print(
            Text.assemble(
                ("HeaderSpecter", "hs.title"),
                (f" v{__version__} · by ", "hs.dim"),
                (AUTHOR, "bright_yellow"),
                (f" · {self.icons.coffee} ", "hs.dim"),
                (AUTHOR_URL, "underline bright_blue"),
            )
        )


def _short_label(result: Any, limit: int = 24) -> str:
    """Compact target label used inside the batch dashboard cards."""
    url = result.final_url or result.target or ""
    for prefix in ("https://", "http://"):
        if url.startswith(prefix):
            url = url[len(prefix) :]
            break
    return truncate_middle(url.rstrip("/") or result.host, limit)


def iter_renderables(items: Iterable[RenderableType]) -> Group:
    """Group renderables for compact printing."""
    return Group(*items)
