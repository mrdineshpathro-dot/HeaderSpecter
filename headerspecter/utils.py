"""Small, dependency-light helpers shared across HeaderSpecter.

Includes URL normalisation, target de-duplication, raw header parsing (so the
tool can analyse a saved response offline), terminal capability detection and
logging helpers.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import sys
from collections.abc import Iterable, Iterator, Sequence
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urlunparse

__all__ = [
    "HeaderSpecterError",
    "InvalidTargetError",
    "ScanFailure",
    "normalize_url",
    "dedupe_targets",
    "read_targets",
    "host_of",
    "port_of",
    "is_https",
    "same_site",
    "registrable_suffix",
    "human_duration",
    "human_bytes",
    "truncate",
    "truncate_middle",
    "utc_now",
    "iso_now",
    "slugify",
    "parse_raw_headers",
    "supports_unicode",
    "terminal_width",
    "setup_logging",
    "write_text",
    "clamp",
]

LOGGER = logging.getLogger("headerspecter")

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*\.?$"
)
_STATUS_LINE_RE = re.compile(
    r"^(?P<proto>HTTP/(?P<version>[0-9.]+))\s+(?P<code>\d{3})(?:\s+(?P<reason>.*))?$",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #
class HeaderSpecterError(Exception):
    """Base class for all errors raised intentionally by HeaderSpecter."""

    hint: str | None = None

    def __init__(self, message: str, hint: str | None = None) -> None:
        """Store the message plus an optional actionable hint."""
        super().__init__(message)
        self.hint = hint


class InvalidTargetError(HeaderSpecterError):
    """Raised when a target string cannot be turned into a usable URL."""


class ScanFailure(HeaderSpecterError):
    """Raised when a target could not be scanned (DNS, TLS, timeout, ...)."""

    def __init__(self, message: str, kind: str = "error", hint: str | None = None) -> None:
        """Store the failure message, its kind and an optional hint."""
        super().__init__(message, hint)
        self.kind = kind


# --------------------------------------------------------------------------- #
# URL helpers
# --------------------------------------------------------------------------- #
def normalize_url(raw: str, default_scheme: str = "https") -> str:
    """Normalise a user supplied target into an absolute URL.

    ``example.com`` becomes ``https://example.com/``; whitespace, stray quotes
    and duplicate slashes are cleaned up.  Raises :class:`InvalidTargetError`
    for anything that is clearly not a web target.

    >>> normalize_url("example.com")
    'https://example.com/'
    >>> normalize_url("HTTP://Example.COM:80/a/b?x=1#frag")
    'http://example.com/a/b?x=1'
    """
    if raw is None:
        raise InvalidTargetError("Empty target")

    candidate = raw.strip().strip("'\"").rstrip(",")
    if not candidate:
        raise InvalidTargetError("Empty target")
    if candidate.startswith("//"):
        candidate = f"{default_scheme}:{candidate}"
    had_scheme = bool(_SCHEME_RE.match(candidate))
    if not had_scheme:
        candidate = f"{default_scheme}://{candidate}"

    parsed = urlparse(candidate)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise InvalidTargetError(
            f"Unsupported URL scheme {scheme!r}", hint="Only http:// and https:// targets are supported"
        )

    if not parsed.hostname:
        raise InvalidTargetError(f"Could not determine a hostname from {raw!r}")

    hostname = parsed.hostname.lower()
    explicit = had_scheme or parsed.port is not None
    if not _is_valid_host(hostname, explicit=explicit):
        raise InvalidTargetError(
            f"{raw!r} does not look like a valid hostname or IP address",
            hint="Expected something like example.com or https://10.0.0.5:8443",
        )

    netloc = hostname
    if ":" in hostname and not hostname.startswith("["):  # IPv6 literal
        netloc = f"[{hostname}]"
    if parsed.username:
        credentials = parsed.username
        if parsed.password:
            credentials += f":{parsed.password}"
        netloc = f"{credentials}@{netloc}"
    port = parsed.port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{netloc}:{port}"

    path = re.sub(r"/{2,}", "/", parsed.path) or "/"
    return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))


def _is_valid_host(host: str, explicit: bool = False) -> bool:
    """Validate a hostname or IP literal.

    Single-label hosts (``localhost`` aside) are only accepted when the user
    was explicit about them — i.e. they supplied a scheme or a port — so that a
    typo such as ``not a url`` does not silently become three targets.
    """
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if not _HOSTNAME_RE.match(host):
        return False
    return not ("." not in host and host != "localhost" and not explicit)


def dedupe_targets(targets: Iterable[str]) -> list[str]:
    """De-duplicate normalised targets while preserving input order."""
    seen: set[str] = set()
    ordered: list[str] = []
    for target in targets:
        if target not in seen:
            seen.add(target)
            ordered.append(target)
    return ordered


def read_targets(lines: Iterable[str], default_scheme: str = "https") -> tuple[list[str], list[tuple[str, str]]]:
    """Parse a target list (file or stdin).

    Blank lines and ``#`` comments are ignored.  Returns ``(targets, errors)``
    where errors are ``(raw_line, message)`` pairs for unusable entries.
    """
    targets: list[str] = []
    errors: list[tuple[str, str]] = []
    for line in lines:
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        raw = re.split(r"\s+#", raw, maxsplit=1)[0].strip()  # strip inline comments
        for chunk in (part.strip() for part in raw.split(",")):
            if not chunk:
                continue
            try:
                targets.append(normalize_url(chunk, default_scheme=default_scheme))
            except InvalidTargetError as exc:
                errors.append((chunk, str(exc)))
    return dedupe_targets(targets), errors


def host_of(url: str) -> str:
    """Return the lowercase hostname of ``url`` (empty string when absent)."""
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:  # pragma: no cover - urlparse is very tolerant
        return ""


def port_of(url: str) -> int:
    """Return the effective port for ``url`` (scheme default when implicit)."""
    parsed = urlparse(url)
    if parsed.port:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80


def is_https(url: str) -> bool:
    """True when ``url`` uses the https scheme."""
    return urlparse(url).scheme.lower() == "https"


def registrable_suffix(host: str) -> str:
    """Best-effort eTLD+1 without bundling the public suffix list.

    ``www.shop.example.co.uk`` -> ``example.co.uk``.  Good enough to spot
    overly broad cookie domains; never used for security decisions on its own.
    """
    host = host.strip(".").lower()
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two_level = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "mil"}
    if len(parts) >= 3 and parts[-2] in two_level and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def same_site(host_a: str, host_b: str) -> bool:
    """True when both hosts share a registrable domain."""
    if not host_a or not host_b:
        return False
    return registrable_suffix(host_a) == registrable_suffix(host_b)


# --------------------------------------------------------------------------- #
# Formatting helpers
# --------------------------------------------------------------------------- #
def human_duration(milliseconds: float | None) -> str:
    """Render a duration in ms/s with sensible precision."""
    if milliseconds is None:
        return "n/a"
    if milliseconds < 1000:
        return f"{milliseconds:.0f} ms"
    return f"{milliseconds / 1000:.2f} s"


def human_bytes(value: int | str | None) -> str:
    """Render a byte count using binary units."""
    if value is None:
        return "n/a"
    try:
        size = float(value)
    except (TypeError, ValueError):
        return str(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"  # pragma: no cover - unreachable


def truncate(text: str | None, limit: int = 96, suffix: str = "…") -> str:
    """Shorten ``text`` to ``limit`` characters."""
    if not text:
        return ""
    collapsed = " ".join(str(text).split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: max(0, limit - len(suffix))] + suffix


def truncate_middle(text: str, limit: int = 32, marker: str = "…") -> str:
    """Shorten ``text`` in the middle, keeping both ends readable.

    Useful for URLs where the tail (path) is as informative as the host.

    >>> truncate_middle("127.0.0.1:8080/weak", 16)
    '127.0.…080/weak'
    """
    text = " ".join(str(text or "").split())
    if len(text) <= limit:
        return text
    keep = max(1, (limit - len(marker)) // 2)
    return text[:keep] + marker + text[-(limit - len(marker) - keep) :]


def utc_now() -> datetime:
    """Timezone-aware current UTC timestamp."""
    return datetime.now(timezone.utc)


def iso_now() -> str:
    """ISO-8601 UTC timestamp (seconds resolution)."""
    return utc_now().replace(microsecond=0).isoformat()


def slugify(value: str, max_length: int = 60) -> str:
    """Turn a URL/host into a filesystem-friendly slug."""
    cleaned = re.sub(r"^[a-z]+://", "", value.strip().lower())
    cleaned = re.sub(r"[^a-z0-9._-]+", "-", cleaned).strip("-._")
    return (cleaned or "target")[:max_length]


def clamp(value: float, low: float, high: float) -> float:
    """Clamp ``value`` into the ``[low, high]`` interval."""
    return max(low, min(high, value))


# --------------------------------------------------------------------------- #
# Raw header parsing (offline analysis support)
# --------------------------------------------------------------------------- #
def parse_raw_headers(text: str) -> tuple[dict[str, object], list[tuple[str, str]]]:
    """Parse a raw HTTP response head into metadata plus header pairs.

    Accepts a full response head (``HTTP/1.1 200 OK`` + headers), a bare list
    of ``Name: value`` lines, and RFC 7230 obs-fold continuation lines.  Used
    by ``--from-raw`` and the interactive "Analyze Raw Headers" mode.

    Returns ``(meta, headers)`` where *meta* may contain ``status_code``,
    ``reason`` and ``http_version``.
    """
    meta: dict[str, object] = {}
    headers: list[tuple[str, str]] = []
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")

    for index, line in enumerate(lines):
        if not line.strip():
            if headers or meta:
                break  # end of header block
            continue
        match = _STATUS_LINE_RE.match(line.strip())
        if match and not headers:
            meta["status_code"] = int(match.group("code"))
            meta["reason"] = (match.group("reason") or "").strip()
            meta["http_version"] = match.group("proto").upper()
            continue
        if line[:1] in " \t" and headers:  # obs-fold continuation
            name, value = headers[-1]
            headers[-1] = (name, f"{value} {line.strip()}")
            continue
        if ":" not in line:
            if index == 0:
                continue  # tolerate a request line / garbage first line
            continue
        name, _, value = line.partition(":")
        name = name.strip()
        if not name:
            continue
        headers.append((name, value.strip()))
    return meta, headers


# --------------------------------------------------------------------------- #
# Terminal / logging
# --------------------------------------------------------------------------- #
def supports_unicode(stream: object | None = None) -> bool:
    """Detect whether the active stdout encoding can render box/emoji glyphs."""
    if os.environ.get("HEADERSPECTER_ASCII"):
        return False
    target = stream if stream is not None else sys.stdout
    encoding = getattr(target, "encoding", None) or ""
    if not encoding:
        return False
    try:
        "✓ ✗ ⚠ ━ ╭ ░ █ →".encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def terminal_width(default: int = 100, maximum: int = 118) -> int:
    """Return a comfortable render width for the current terminal."""
    try:
        columns = os.get_terminal_size().columns
    except OSError:
        columns = int(os.environ.get("COLUMNS", default))
    return max(60, min(columns, maximum))


def setup_logging(level: int = logging.WARNING, rich_console: object | None = None) -> logging.Logger:
    """Configure the ``headerspecter`` logger.

    Uses :class:`rich.logging.RichHandler` when a console is supplied, so debug
    output matches the rest of the UI.
    """
    logger = logging.getLogger("headerspecter")
    logger.setLevel(level)
    logger.handlers.clear()
    handler: logging.Handler
    if rich_console is not None:
        try:
            from rich.logging import RichHandler

            handler = RichHandler(
                console=rich_console,  # type: ignore[arg-type]
                show_path=False,
                rich_tracebacks=True,
                markup=False,
                log_time_format="[%H:%M:%S]",
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
        except Exception:  # pragma: no cover - rich always available in practice
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
    else:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
    handler.setLevel(level)
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def write_text(path: str | Path, content: str) -> Path:
    """Write ``content`` to ``path`` (creating parents) and return the path."""
    target = Path(path).expanduser()
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


def chunked(items: Sequence[object], size: int) -> Iterator[Sequence[object]]:
    """Yield ``size``-sized chunks from ``items``."""
    for start in range(0, len(items), size):
        yield items[start : start + size]
