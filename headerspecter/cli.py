"""HeaderSpecter command line interface.

Implements every operating mode:

* single target scan            ``headerspecter https://example.com``
* batch scan                    ``headerspecter -l targets.txt --threads 20``
* stdin pipeline                ``cat targets.txt | headerspecter``
* offline raw-header analysis   ``headerspecter --from-raw response.txt``
* baseline save / compare       ``--save-baseline`` / ``--compare``
* continuous monitoring         ``--watch --interval 60``
* interactive menu              ``--interactive``

The parser is argparse based (zero extra dependencies) but the help screen is
rendered with Rich so it matches the rest of the tool.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from rich.prompt import Confirm, IntPrompt, Prompt
from rich.text import Text

from . import AUTHOR, AUTHOR_URL, TAGLINE, __version__
from .analyzer import ScanResult, analyze_raw_headers
from .config import DEFAULT_USER_AGENT, OutputConfig, ScanConfig, ScoringConfig
from .findings import Severity
from .policy import HeaderPolicy, PolicyError
from .reporter import (
    compare_results,
    compare_to_baseline,
    load_baseline,
    render_batch_terminal,
    render_quiet,
    render_terminal,
    save_baseline,
    to_csv,
    to_json,
    to_markdown,
    write_report,
)
from .scanner import Scanner
from .ui import UI, build_console
from .utils import (
    HeaderSpecterError,
    InvalidTargetError,
    normalize_url,
    read_targets,
    setup_logging,
    truncate,
    write_text,
)

LOGGER = logging.getLogger("headerspecter.cli")

__all__ = ["main", "build_parser"]

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_THRESHOLD = 2
EXIT_INTERRUPTED = 130

EPILOG_EXAMPLES: tuple[tuple[str, str], ...] = (
    ("headerspecter https://example.com", "Full analysis of a single target"),
    ("headerspecter example.com --verbose", "Detailed findings, remediation templates and score breakdown"),
    ("headerspecter -l targets.txt --threads 20 --delay 0.2", "Polite concurrent batch scan"),
    ("cat targets.txt | headerspecter --json > report.json", "Pipeline / CI friendly JSON output"),
    ("headerspecter https://example.com --csp --cookies", "Only the CSP and cookie sections"),
    ("headerspecter https://example.com --html report.html", "Standalone dark-theme HTML report"),
    ("headerspecter https://example.com --save-baseline base.json", "Record a baseline for regression testing"),
    ("headerspecter https://example.com --compare base.json", "Diff the live target against the baseline"),
    ("headerspecter https://example.com --watch --interval 120", "Monitor a target and report changes"),
    ("headerspecter https://example.com --proxy http://127.0.0.1:8080", "Route the scan through Burp Suite / ZAP"),
    ("headerspecter https://example.com --policy examples/policy.yaml", "Enforce an organisation specific baseline"),
    ("headerspecter --interactive", "Guided menu driven mode"),
)


class HeaderSpecterParser(argparse.ArgumentParser):
    """Argparse parser with Rich help and friendly error reporting."""

    ui: UI | None = None

    def print_help(self, file: Any = None) -> None:  # noqa: D102 - argparse API
        ui = self.ui or UI()
        render_help(ui, self)

    def error(self, message: str) -> None:  # noqa: D102 - argparse API
        ui = self.ui or UI()
        ui.error(message, "Run 'headerspecter --help' to see all available options")
        raise SystemExit(EXIT_ERROR)


def render_help(ui: UI, parser: argparse.ArgumentParser) -> None:
    """Render the CLI help screen with Rich."""
    from rich.box import ROUNDED
    from rich.panel import Panel
    from rich.table import Table

    ui.banner(compact=True)
    usage = Text()
    usage.append("Usage:\n", style="hs.title")
    usage.append("  headerspecter [OPTIONS] TARGET\n", style="bright_white")
    usage.append("  headerspecter -l targets.txt [OPTIONS]\n", style="bright_white")
    usage.append("  cat targets.txt | headerspecter [OPTIONS]", style="bright_white")
    ui.print(usage)
    ui.print()

    for group in parser._action_groups:  # noqa: SLF001 - argparse exposes no public API
        actions = [action for action in group._group_actions if action.help != argparse.SUPPRESS]  # noqa: SLF001
        if not actions:
            continue
        table = Table(box=None, show_header=False, padding=(0, 2), expand=True)
        table.add_column(style="hs.accent", no_wrap=True, min_width=26)
        table.add_column(style="bright_white", overflow="fold")
        for action in actions:
            if action.option_strings:
                flags = ", ".join(action.option_strings)
                metavar = action.metavar or (action.dest.upper() if action.nargs != 0 else "")
                if action.nargs == 0 or isinstance(action.const, bool) or action.metavar == "":
                    label = flags
                else:
                    label = f"{flags} {metavar}" if metavar else flags
            else:
                label = action.metavar or action.dest.upper()
            help_text = (action.help or "").strip()
            default = action.default
            show_default = (
                default not in (None, False, argparse.SUPPRESS, "", 0, [])
                and not isinstance(default, bool)
                and "default" not in help_text.lower()
            )
            if show_default:
                rendered_default = truncate(str(default), 46)
                help_text += f" [dim](default: {rendered_default})[/dim]"
            table.add_row(label, help_text)
        ui.print(
            Panel(
                table,
                title=(group.title or "options").capitalize(),
                box=ROUNDED,
                border_style="hs.rule",
                title_align="left",
                padding=(0, 1),
            )
        )

    examples = Table(box=None, show_header=False, padding=(0, 2), expand=True)
    examples.add_column(style="bright_green", no_wrap=False)
    examples.add_column(style="hs.dim", overflow="fold")
    for command, description in EPILOG_EXAMPLES:
        examples.add_row(command, description)
    ui.print(Panel(examples, title="Examples", box=ROUNDED, border_style="hs.accent", title_align="left", padding=(0, 1)))

    ui.print(
        Text.assemble(
            ("HeaderSpecter", "hs.title"),
            (f" v{__version__} · ", "hs.dim"),
            (TAGLINE, "hs.subtitle"),
        )
    )
    ui.print(
        Text.assemble(
            ("Created by ", "hs.dim"),
            (AUTHOR, "bright_yellow"),
            (f"  {ui.icons.coffee} ", "hs.dim"),
            (AUTHOR_URL, "underline bright_blue"),
        )
    )
    ui.print(Text("Authorised testing only — scan systems you own or have permission to assess.", style="hs.dim"))


def build_parser() -> HeaderSpecterParser:
    """Build the argument parser."""
    parser = HeaderSpecterParser(
        prog="headerspecter",
        description=TAGLINE,
        add_help=False,
        allow_abbrev=False,
    )

    target = parser.add_argument_group("targets")
    target.add_argument("target", nargs="?", metavar="TARGET", help="URL or hostname to analyse")
    target.add_argument("-u", "--url", metavar="URL", help="Target URL (alternative to the positional argument)")
    target.add_argument("-l", "--list", dest="list_file", metavar="FILE", help="File with one target per line")
    target.add_argument(
        "--from-raw",
        metavar="FILE",
        help="Analyse a saved raw HTTP response head offline (no network traffic)",
    )
    target.add_argument("--stdin", action="store_true", help="Force reading targets from standard input")

    output = parser.add_argument_group("output")
    output.add_argument("-o", "--output", metavar="FILE", help="Write a report to FILE (format inferred from extension)")
    output.add_argument("--json", action="store_true", help="Print JSON to stdout (machine readable)")
    output.add_argument("--csv", metavar="FILE", help="Write findings as CSV")
    output.add_argument("--html", metavar="FILE", help="Write a standalone HTML report")
    output.add_argument("--markdown", "--md", dest="markdown", metavar="FILE", help="Write a Markdown report")
    output.add_argument("--raw", action="store_true", help="Show the raw response headers as received")
    output.add_argument("--no-banner", action="store_true", help="Do not print the ASCII banner")

    sections = parser.add_argument_group("sections (default: everything)")
    sections.add_argument("--headers", action="store_true", help="Show the header security table")
    sections.add_argument("--cookies", action="store_true", help="Show the cookie analysis")
    sections.add_argument("--csp", action="store_true", help="Show the Content-Security-Policy analysis")
    sections.add_argument("--cors", action="store_true", help="Show the CORS analysis")
    sections.add_argument("--tls", action="store_true", help="Show the TLS analysis")
    sections.add_argument("--redirects", action="store_true", help="Show the redirect chain")
    sections.add_argument("--score", action="store_true", help="Show only the security score")
    sections.add_argument("--findings", action="store_true", help="Show only the findings list")

    network = parser.add_argument_group("network")
    network.add_argument("--timeout", type=float, default=15.0, metavar="SECONDS", help="Per-request timeout")
    network.add_argument("--retries", type=int, default=2, metavar="N", help="Retries for transport errors")
    network.add_argument("-t", "--threads", type=int, default=10, metavar="N", help="Concurrent targets in batch mode")
    network.add_argument("--delay", type=float, default=0.0, metavar="SECONDS", help="Delay before each request")
    network.add_argument("--proxy", metavar="URL", help="Proxy URL, e.g. http://127.0.0.1:8080 (Burp/ZAP)")
    network.add_argument("--user-agent", metavar="STRING", default=DEFAULT_USER_AGENT, help="Custom User-Agent")
    network.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        metavar="'Name: value'",
        help="Extra request header (repeatable)",
    )
    network.add_argument("--method", default="GET", metavar="VERB", help="HTTP method for the main request")
    network.add_argument(
        "--follow-redirects",
        dest="follow_redirects",
        action="store_true",
        default=True,
        help="Follow redirects (default)",
    )
    network.add_argument(
        "--no-follow-redirects",
        dest="follow_redirects",
        action="store_false",
        help="Do not follow redirects",
    )
    network.add_argument("--max-redirects", type=int, default=10, metavar="N", help="Maximum redirects to follow")
    network.add_argument("--verify-tls", action="store_true", help="Abort on invalid certificates instead of reporting them")
    network.add_argument("--no-tls-check", action="store_true", help="Skip the TLS handshake inspection")
    network.add_argument(
        "--no-probes",
        action="store_true",
        help="Skip the passive CORS Origin probe and the HTTP→HTTPS upgrade check",
    )

    modes = parser.add_argument_group("modes")
    modes.add_argument("-i", "--interactive", action="store_true", help="Launch the interactive menu")
    modes.add_argument("--watch", action="store_true", help="Re-scan periodically and report changes")
    modes.add_argument("--interval", type=int, default=60, metavar="SECONDS", help="Watch mode interval")
    modes.add_argument("--iterations", type=int, default=0, metavar="N", help="Stop watch mode after N scans (0 = forever)")
    modes.add_argument("--save-baseline", metavar="FILE", help="Save this scan as a baseline JSON file")
    modes.add_argument("--compare", metavar="FILE", help="Compare this scan against a baseline JSON file")
    modes.add_argument("--policy", metavar="FILE", help="Custom header policy (YAML or JSON)")
    modes.add_argument(
        "--fail-on",
        metavar="SEVERITY",
        choices=["critical", "high", "medium", "low", "info"],
        help="Exit with code 2 when a finding of this severity or worse exists",
    )
    modes.add_argument("--min-score", type=float, metavar="N", help="Exit with code 2 when the score is below N")

    general = parser.add_argument_group("general")
    general.add_argument("-q", "--quiet", action="store_true", help="Only print essential output")
    general.add_argument("-v", "--verbose", action="store_true", help="Detailed findings, templates and score breakdown")
    general.add_argument("--debug", action="store_true", help="Debug logging and full tracebacks")
    general.add_argument("--no-color", action="store_true", help="Disable colours (scripting friendly)")
    general.add_argument("-V", "--version", action="store_true", help="Show version information and exit")
    general.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")

    return parser


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _log_level(args: argparse.Namespace) -> int:
    if args.debug:
        return logging.DEBUG
    if args.verbose:
        return logging.INFO
    if args.quiet:
        return logging.ERROR
    return logging.WARNING


def _parse_extra_headers(values: Sequence[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in values:
        if ":" not in item:
            raise HeaderSpecterError(
                f"Invalid header {item!r}", hint="Use the format -H 'Name: value'"
            )
        name, _, value = item.partition(":")
        headers[name.strip()] = value.strip()
    return headers


def build_scan_config(args: argparse.Namespace) -> ScanConfig:
    """Translate CLI arguments into a :class:`ScanConfig`."""
    return ScanConfig(
        timeout=max(0.5, args.timeout),
        retries=max(0, args.retries),
        concurrency=max(1, args.threads),
        delay=max(0.0, args.delay),
        proxy=args.proxy,
        user_agent=args.user_agent,
        method=args.method.upper(),
        follow_redirects=args.follow_redirects,
        max_redirects=max(0, args.max_redirects),
        verify_tls=args.verify_tls,
        extra_probes=not args.no_probes,
        tls_probe=not args.no_tls_check,
        extra_headers=_parse_extra_headers(args.header),
    )


def build_output_config(args: argparse.Namespace) -> OutputConfig:
    """Translate the section flags into an :class:`OutputConfig`."""
    selected = {
        "show_headers": args.headers,
        "show_cookies": args.cookies,
        "show_csp": args.csp,
        "show_cors": args.cors,
        "show_tls": args.tls,
        "show_redirects": args.redirects,
        "show_score": args.score,
        "show_findings": args.findings,
    }
    if any(selected.values()):
        cfg = OutputConfig.only(**{key: value for key, value in selected.items() if value})
        cfg.show_response = True
        cfg.show_hsts = args.headers
        cfg.show_disclosure = args.headers
        cfg.show_recommendations = args.findings or args.score
    else:
        cfg = OutputConfig()
    cfg.show_raw = args.raw
    cfg.verbose_findings = args.verbose
    return cfg


def collect_targets(args: argparse.Namespace, ui: UI) -> list[str]:
    """Resolve targets from the positional argument, ``-u``, ``-l`` or stdin."""
    raw_targets: list[str] = []
    if args.target:
        raw_targets.append(args.target)
    if args.url:
        raw_targets.append(args.url)

    if args.list_file:
        path = Path(args.list_file).expanduser()
        if not path.exists():
            raise HeaderSpecterError(f"Target list not found: {path}")
        targets, errors = read_targets(path.read_text(encoding="utf-8").splitlines())
        for line, message in errors:
            ui.warn(f"Skipping {line!r}: {message}")
        raw_targets.extend(targets)

    stdin_requested = args.stdin or (not raw_targets and not sys.stdin.isatty())
    if stdin_requested:
        try:
            data = sys.stdin.read()
        except (OSError, ValueError) as exc:  # closed/captured stdin
            LOGGER.debug("stdin unavailable: %s", exc)
            data = ""
        targets, errors = read_targets(data.splitlines())
        for line, message in errors:
            ui.warn(f"Skipping {line!r}: {message}")
        raw_targets.extend(targets)

    normalized: list[str] = []
    for item in raw_targets:
        try:
            normalized.append(normalize_url(item))
        except InvalidTargetError as exc:
            ui.warn(f"Skipping {item!r}: {exc}")
    # de-duplicate, preserving order
    seen: set[str] = set()
    unique = [target for target in normalized if not (target in seen or seen.add(target))]
    return unique


def determine_exit_code(results: Sequence[ScanResult], args: argparse.Namespace, policy: HeaderPolicy | None) -> int:
    """Apply ``--fail-on`` / ``--min-score`` / policy thresholds."""
    if any(not result.ok for result in results):
        exit_code = EXIT_ERROR
    else:
        exit_code = EXIT_OK

    threshold_name = args.fail_on
    if threshold_name:
        threshold = Severity.parse(threshold_name)
        for result in results:
            if result.analysis is None:
                continue
            for finding in result.analysis.findings:
                if finding.is_issue and finding.severity.rank <= threshold.rank:
                    return EXIT_THRESHOLD

    min_score = args.min_score if args.min_score is not None else (policy.min_score if policy else None)
    if min_score is not None:
        for result in results:
            if result.score is not None and result.score < min_score:
                return EXIT_THRESHOLD
    return exit_code


def write_outputs(results: Sequence[ScanResult], args: argparse.Namespace, ui: UI) -> None:
    """Write every requested report file."""
    written: list[tuple[str, Path]] = []
    if args.output:
        suffix = Path(args.output).suffix.lower()
        fmt = {".json": "json", ".csv": "csv", ".html": "html", ".htm": "html", ".md": "markdown"}.get(suffix, "json")
        written.append((fmt.upper(), write_report(results, args.output, fmt)))
    if args.csv:
        written.append(("CSV", write_text(args.csv, to_csv(results))))
    if args.html:
        written.append(("HTML", write_report(results, args.html, "html")))
    if args.markdown:
        written.append(("Markdown", write_text(args.markdown, to_markdown(results))))
    for label, path in written:
        ui.success(f"{label} report written to {path}")


# --------------------------------------------------------------------------- #
# Scan flows
# --------------------------------------------------------------------------- #
async def _scan_targets(
    targets: Sequence[str],
    config: ScanConfig,
    policy: HeaderPolicy | None,
    scoring: ScoringConfig | None,
    ui: UI,
    show_progress: bool,
) -> list[ScanResult]:
    async with Scanner(config, policy, scoring) as scanner:
        if len(targets) == 1 or not show_progress:
            if len(targets) == 1:
                with ui.status(f"Requesting {targets[0]} …"):
                    return [await scanner.scan(targets[0], normalize=False)]
            return await scanner.scan_many(list(targets), normalize=False)

        progress = ui.progress(len(targets))
        task_id = progress.task_ids[0]
        with progress:
            def on_result(result: ScanResult) -> None:
                progress.advance(task_id)
                if not ui.quiet:
                    status = f"{result.grade:<2} {result.score:>3.0f}" if result.ok and result.score is not None else "ERR"
                    label = truncate(result.final_url or result.target, 52)
                    style = "hs.ok" if result.ok and (result.score or 0) >= 70 else "hs.warn" if result.ok else "hs.bad"
                    progress.console.print(
                        Text.assemble(
                            (f"  {ui.icons.bullet} ", "hs.dim"),
                            (f"{label:<54}", "bright_white"),
                            (status, style),
                        )
                    )

            return await scanner.scan_many(list(targets), on_result=on_result, normalize=False)


def run_scan(args: argparse.Namespace, ui: UI, targets: Sequence[str], policy: HeaderPolicy | None) -> int:
    """Run a one-shot scan of one or many targets."""
    config = build_scan_config(args)
    output_cfg = build_output_config(args)
    scoring = ScoringConfig()

    results = asyncio.run(
        _scan_targets(targets, config, policy, scoring, ui, show_progress=len(targets) > 1 and not args.json)
    )

    diff = None
    if args.compare and results:
        try:
            baseline = load_baseline(args.compare)
        except (OSError, ValueError) as exc:
            raise HeaderSpecterError(f"Could not read baseline: {exc}") from exc
        diff = compare_to_baseline(results[0], baseline)

    if args.json:
        if diff is not None:
            payload = {
                "tool": "HeaderSpecter",
                "version": __version__,
                "results": [result.to_dict() for result in results],
                "diff": diff.to_dict(),
            }
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            print(to_json(results))
    elif args.quiet:
        render_quiet(ui, results)
    else:
        if len(results) == 1:
            render_terminal(ui, results[0], output_cfg)
        else:
            render_batch_terminal(ui, results, output_cfg, detail=args.verbose)
        if diff is not None:
            ui.diff_section(diff)

    write_outputs(results, args, ui)

    if args.save_baseline and results:
        path = save_baseline(results[0], args.save_baseline)
        ui.success(f"Baseline saved to {path}")

    if not args.json and not args.quiet:
        ok = sum(1 for result in results if result.ok)
        if ok == len(results):
            ui.footer(f"Scan completed — {ok}/{len(results)} target(s) analysed.")
        else:
            ui.blank()
            ui.warn(f"Scan finished with errors — {ok}/{len(results)} target(s) analysed.")
            ui.footer_branding()

    return determine_exit_code(results, args, policy)


def run_watch(args: argparse.Namespace, ui: UI, target: str, policy: HeaderPolicy | None) -> int:
    """Continuously re-scan a target and report changes."""
    config = build_scan_config(args)
    output_cfg = build_output_config(args)
    interval = max(5, args.interval)
    previous: ScanResult | None = None
    iteration = 0

    ui.info(f"Watch mode — scanning {target} every {interval}s. Press Ctrl+C to stop.")
    try:
        while True:
            iteration += 1
            results = asyncio.run(_scan_targets([target], config, policy, None, ui, show_progress=False))
            result = results[0]
            ui.blank()
            ui.print(
                Text.assemble(
                    (f"── scan #{iteration} ", "hs.accent"),
                    (result.scanned_at, "hs.dim"),
                    (f"  status={result.status_code} score={result.score if result.score is not None else 'n/a'}", "bright_white"),
                )
            )
            if previous is None:
                render_terminal(ui, result, output_cfg)
            else:
                diff = compare_results(previous, result)
                if diff.has_changes:
                    ui.warn("Changes detected since the previous scan")
                    ui.diff_section(diff)
                else:
                    ui.success("No changes since the previous scan")
            previous = result

            if args.iterations and iteration >= args.iterations:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        ui.blank()
        ui.info(f"Watch mode stopped after {iteration} scan(s).")
        return EXIT_INTERRUPTED
    return EXIT_OK


def run_raw(args: argparse.Namespace, ui: UI, policy: HeaderPolicy | None) -> int:
    """Analyse a saved raw response head without touching the network."""
    path = Path(args.from_raw).expanduser()
    if not path.exists():
        raise HeaderSpecterError(f"Raw header file not found: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    url = args.target or args.url or "https://raw.input.local/"
    result = analyze_raw_headers(text, target=str(path), url=normalize_url(url), policy=policy)
    output_cfg = build_output_config(args)
    output_cfg.show_tls = False
    output_cfg.show_redirects = False
    if args.json:
        print(to_json([result]))
    elif args.quiet:
        render_quiet(ui, [result])
    else:
        ui.info(f"Offline analysis of {path} (no requests were sent)")
        render_terminal(ui, result, output_cfg)
    write_outputs([result], args, ui)
    if args.save_baseline:
        ui.success(f"Baseline saved to {save_baseline(result, args.save_baseline)}")
    return determine_exit_code([result], args, policy)


# --------------------------------------------------------------------------- #
# Interactive mode
# --------------------------------------------------------------------------- #
MENU_ENTRIES: tuple[tuple[str, str], ...] = (
    ("1", "Scan URL"),
    ("2", "Scan target list"),
    ("3", "Analyze raw headers"),
    ("4", "Compare baseline"),
    ("5", "Generate report from last scan"),
    ("6", "Configuration"),
    ("7", "About"),
    ("0", "Exit"),
)


def run_interactive(args: argparse.Namespace, ui: UI, policy: HeaderPolicy | None) -> int:
    """Menu driven mode for operators who prefer prompts over flags."""
    config = build_scan_config(args)
    last_results: list[ScanResult] = []
    ui.banner()

    while True:
        ui.blank()
        ui.menu(MENU_ENTRIES, title=f"HeaderSpecter v{__version__} · interactive")
        choice = Prompt.ask(
            Text("Select an option", style="hs.label"),
            choices=[key for key, _ in MENU_ENTRIES],
            default="1",
            console=ui.console,
        )

        try:
            if choice == "0":
                ui.info("Goodbye — stay safe out there.")
                return EXIT_OK

            if choice == "1":
                target = Prompt.ask(Text("Target URL", style="hs.label"), console=ui.console)
                url = normalize_url(target)
                results = asyncio.run(_scan_targets([url], config, policy, None, ui, show_progress=False))
                last_results = results
                render_terminal(ui, results[0], OutputConfig(verbose_findings=args.verbose))

            elif choice == "2":
                path = Prompt.ask(Text("Path to target list", style="hs.label"), console=ui.console)
                file_path = Path(path).expanduser()
                if not file_path.exists():
                    ui.error(f"File not found: {file_path}")
                    continue
                targets, errors = read_targets(file_path.read_text(encoding="utf-8").splitlines())
                for line, message in errors:
                    ui.warn(f"Skipping {line!r}: {message}")
                if not targets:
                    ui.error("No usable targets in that file")
                    continue
                config.concurrency = IntPrompt.ask(
                    Text("Concurrency", style="hs.label"), default=config.concurrency, console=ui.console
                )
                results = asyncio.run(_scan_targets(targets, config, policy, None, ui, show_progress=True))
                last_results = results
                render_batch_terminal(ui, results, OutputConfig())

            elif choice == "3":
                source = Prompt.ask(
                    Text("Read headers from [f]ile or [p]aste", style="hs.label"),
                    choices=["f", "p"],
                    default="f",
                    console=ui.console,
                )
                if source == "f":
                    path = Prompt.ask(Text("Path to raw header file", style="hs.label"), console=ui.console)
                    file_path = Path(path).expanduser()
                    if not file_path.exists():
                        ui.error(f"File not found: {file_path}")
                        continue
                    text = file_path.read_text(encoding="utf-8", errors="replace")
                else:
                    ui.info("Paste the response head, then finish with a single '.' on its own line")
                    lines: list[str] = []
                    while True:
                        line = input()
                        if line.strip() == ".":
                            break
                        lines.append(line)
                    text = "\n".join(lines)
                url = Prompt.ask(
                    Text("Origin URL for context", style="hs.label"),
                    default="https://raw.input.local/",
                    console=ui.console,
                )
                result = analyze_raw_headers(text, target="raw-input", url=normalize_url(url), policy=policy)
                last_results = [result]
                cfg = OutputConfig(verbose_findings=args.verbose)
                cfg.show_tls = False
                cfg.show_redirects = False
                render_terminal(ui, result, cfg)

            elif choice == "4":
                baseline_path = Prompt.ask(Text("Baseline JSON file", style="hs.label"), console=ui.console)
                target = Prompt.ask(Text("Target URL to compare", style="hs.label"), console=ui.console)
                baseline = load_baseline(baseline_path)
                results = asyncio.run(_scan_targets([normalize_url(target)], config, policy, None, ui, show_progress=False))
                last_results = results
                ui.diff_section(compare_to_baseline(results[0], baseline))

            elif choice == "5":
                if not last_results:
                    ui.warn("Run a scan first — there is nothing to report on yet.")
                    continue
                fmt = Prompt.ask(
                    Text("Format", style="hs.label"),
                    choices=["html", "json", "csv", "markdown"],
                    default="html",
                    console=ui.console,
                )
                default_name = f"reports/headerspecter-{last_results[0].host or 'report'}.{'md' if fmt == 'markdown' else fmt}"
                path = Prompt.ask(Text("Output file", style="hs.label"), default=default_name, console=ui.console)
                written = write_report(last_results, path, fmt)
                ui.success(f"{fmt.upper()} report written to {written}")

            elif choice == "6":
                ui.key_value_panel(
                    "Current configuration",
                    {
                        "Timeout (s)": config.timeout,
                        "Retries": config.retries,
                        "Concurrency": config.concurrency,
                        "Delay (s)": config.delay,
                        "Proxy": config.proxy or "none",
                        "User-Agent": config.user_agent,
                        "Follow redirects": config.follow_redirects,
                        "TLS inspection": config.tls_probe,
                        "Passive probes": config.extra_probes,
                        "Policy": policy.name if policy else "built-in defaults",
                    },
                )
                if Confirm.ask(Text("Change settings?", style="hs.label"), default=False, console=ui.console):
                    config.timeout = float(
                        Prompt.ask(Text("Timeout (s)", style="hs.label"), default=str(config.timeout), console=ui.console)
                    )
                    config.concurrency = IntPrompt.ask(
                        Text("Concurrency", style="hs.label"), default=config.concurrency, console=ui.console
                    )
                    proxy = Prompt.ask(
                        Text("Proxy (blank for none)", style="hs.label"), default=config.proxy or "", console=ui.console
                    )
                    config.proxy = proxy or None
                    config.user_agent = Prompt.ask(
                        Text("User-Agent", style="hs.label"), default=config.user_agent, console=ui.console
                    )
                    ui.success("Configuration updated for this session.")

            elif choice == "7":
                ui.about()

        except HeaderSpecterError as exc:
            ui.error(str(exc), exc.hint)
        except KeyboardInterrupt:
            ui.blank()
            ui.info("Cancelled — returning to the menu.")


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def _print_version(ui: UI) -> None:
    ui.print(
        Text.assemble(
            ("HeaderSpecter ", "hs.title"),
            (f"v{__version__}\n", "bright_white"),
            (f"{TAGLINE}\n", "hs.subtitle"),
            (f"Created by {AUTHOR} · {AUTHOR_URL}", "hs.dim"),
        )
    )


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns the process exit code."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    console = build_console(no_color=args.no_color, quiet=False)
    ui = UI(console=console, no_color=args.no_color, quiet=args.quiet)
    parser.ui = ui
    setup_logging(_log_level(args), console if not args.no_color else None)

    if args.help:
        render_help(ui, parser)
        return EXIT_OK
    if args.version:
        _print_version(ui)
        return EXIT_OK

    try:
        policy: HeaderPolicy | None = None
        if args.policy:
            policy = HeaderPolicy.load(args.policy)
            ui.info(f"Loaded policy '{policy.name}' from {args.policy}")

        if args.interactive:
            return run_interactive(args, ui, policy)

        if args.from_raw:
            if not args.quiet and not args.json and not args.no_banner:
                ui.banner()
            return run_raw(args, ui, policy)

        targets = collect_targets(args, ui)
        if not targets:
            render_help(ui, parser)
            ui.blank()
            ui.error("No target supplied", "Provide a URL, use -l targets.txt, or pipe targets via stdin")
            return EXIT_ERROR

        if not args.quiet and not args.json and not args.no_banner:
            ui.banner()
            ui.legal_notice()

        if args.watch:
            if len(targets) > 1:
                ui.warn(f"Watch mode monitors a single target — using {targets[0]}")
            return run_watch(args, ui, targets[0], policy)

        return run_scan(args, ui, targets, policy)

    except KeyboardInterrupt:
        ui.blank()
        ui.warn("Interrupted by user — exiting cleanly.")
        return EXIT_INTERRUPTED
    except PolicyError as exc:
        ui.error(str(exc), exc.hint)
        return EXIT_ERROR
    except HeaderSpecterError as exc:
        ui.error(str(exc), exc.hint)
        return EXIT_ERROR
    except OSError as exc:
        ui.error(f"File system error: {exc}", "Check the path and permissions")
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 - last resort guard
        if args.debug:
            console.print_exception(show_locals=False)
        else:
            ui.error(f"Unexpected error: {exc}", "Re-run with --debug for the full traceback")
        LOGGER.debug("unhandled exception", exc_info=True)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
