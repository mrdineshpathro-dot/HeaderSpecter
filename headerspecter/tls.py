"""TLS / HTTPS posture inspection.

A single, standard TLS handshake is performed against the target (exactly what
any browser does) to read the negotiated protocol version, cipher suite and
certificate metadata.  Nothing intrusive happens here: no downgrade attempts,
no cipher enumeration, no renegotiation games.

When strict verification fails, HeaderSpecter retries once without verification
purely to *describe* the certificate (issuer, validity window, SAN list) so the
report can explain why validation failed.
"""

from __future__ import annotations

import contextlib
import socket
import ssl
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .findings import Finding, Severity, make_finding

__all__ = ["TLSInfo", "inspect_tls", "analyze_tls", "match_hostname"]

#: Protocol versions considered obsolete.
OBSOLETE_PROTOCOLS: frozenset[str] = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})


@dataclass(slots=True)
class TLSInfo:
    """Everything HeaderSpecter learned from the TLS handshake."""

    enabled: bool = False
    handshake_ok: bool = False
    verified: bool = False
    hostname_valid: bool = False
    protocol: str | None = None
    cipher: str | None = None
    cipher_bits: int | None = None
    alpn: str | None = None
    issuer: str | None = None
    subject: str | None = None
    serial: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_remaining: int | None = None
    expired: bool = False
    subject_alt_names: list[str] = field(default_factory=list)
    error: str | None = None
    host: str = ""
    port: int = 443

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "enabled": self.enabled,
            "handshake_ok": self.handshake_ok,
            "verified": self.verified,
            "hostname_valid": self.hostname_valid,
            "protocol": self.protocol,
            "cipher": self.cipher,
            "cipher_bits": self.cipher_bits,
            "alpn": self.alpn,
            "issuer": self.issuer,
            "subject": self.subject,
            "serial": self.serial,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "days_remaining": self.days_remaining,
            "expired": self.expired,
            "subject_alt_names": list(self.subject_alt_names),
            "error": self.error,
            "host": self.host,
            "port": self.port,
        }


def _format_name(name: Sequence[Sequence[tuple[str, str]]] | None) -> str | None:
    """Render an ssl module RDN structure as ``CN=…, O=…``."""
    if not name:
        return None
    pieces: list[str] = []
    for rdn in name:
        for attribute in rdn:
            if len(attribute) == 2:
                key, value = attribute
                pieces.append(f"{key}={value}")
    return ", ".join(pieces) if pieces else None


def _friendly_issuer(issuer: str | None) -> str | None:
    """Pick the most useful component (O= then CN=) from an issuer string."""
    if not issuer:
        return None
    parts = [part.strip() for part in issuer.split(",")]
    organisation = next((p[2:] for p in parts if p.startswith("O=")), None)
    common = next((p[3:] for p in parts if p.startswith("CN=")), None)
    if organisation and common:
        return f"{organisation} ({common})"
    return organisation or common or issuer


def _parse_cert_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def match_hostname(cert: dict[str, Any], hostname: str) -> bool:
    """Validate ``hostname`` against a certificate dict (SAN first, then CN).

    Implements the subset of RFC 6125 that browsers actually use: exact match
    and single left-most wildcard labels.

    >>> match_hostname({"subjectAltName": (("DNS", "*.example.com"),)}, "api.example.com")
    True
    """
    host = hostname.strip().rstrip(".").lower()
    names: list[str] = []
    for kind, value in cert.get("subjectAltName", ()) or ():
        if kind.lower() == "dns" or kind.lower() == "ip address":
            names.append(value.lower())
    if not names:
        subject = cert.get("subject", ())
        for rdn in subject:
            for attribute in rdn:
                if len(attribute) == 2 and attribute[0] == "commonName":
                    names.append(str(attribute[1]).lower())

    for candidate in names:
        if candidate == host:
            return True
        if candidate.startswith("*."):
            suffix = candidate[2:]
            if host.endswith("." + suffix) and host.count(".") == candidate.count("."):
                return True
    return False


def _decode_unverified_cert(der: bytes) -> dict[str, Any] | None:
    """Decode a DER certificate using the stdlib's test helper.

    ``ssl._ssl._test_decode_cert`` is a private CPython helper, but it is the
    only way to inspect an *untrusted* certificate without pulling in the
    ``cryptography`` package.  Failures are swallowed — the report simply says
    the details are unavailable.
    """
    try:  # pragma: no cover - depends on CPython internals
        import ssl as _ssl

        decoder = getattr(_ssl._ssl, "_test_decode_cert", None)  # type: ignore[attr-defined]
        if decoder is None:
            return None
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
            handle.write(pem)
            temp_path = Path(handle.name)
        try:
            return decoder(str(temp_path))
        finally:
            temp_path.unlink(missing_ok=True)
    except Exception:  # pragma: no cover - best effort only
        return None


def inspect_tls(host: str, port: int = 443, timeout: float = 10.0) -> TLSInfo:
    """Perform a TLS handshake against ``host:port`` and describe the result.

    This function is synchronous and safe to run inside a thread executor.
    """
    info = TLSInfo(host=host, port=port, enabled=True)

    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    with contextlib.suppress(NotImplementedError):  # pragma: no cover - platform dependent
        context.set_alpn_protocols(["h2", "http/1.1"])

    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as raw_sock,
            context.wrap_socket(raw_sock, server_hostname=host) as tls_sock,
        ):
            info.handshake_ok = True
            info.verified = True
            info.hostname_valid = True
            _fill_connection_details(info, tls_sock)
            cert = tls_sock.getpeercert()
            if isinstance(cert, dict):
                _fill_certificate_details(info, cert, host)
            return info
    except ssl.SSLCertVerificationError as exc:
        info.error = f"certificate verification failed: {exc.verify_message or exc.reason or exc}"
        info.verified = False
    except ssl.SSLError as exc:
        info.error = f"TLS error: {exc.reason or exc}"
    except TimeoutError:
        info.error = "TLS handshake timed out"
        return info
    except (OSError, ValueError) as exc:
        info.error = f"connection failed: {exc}"
        return info

    # Second, non-verifying pass purely to describe the certificate.
    permissive = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    permissive.check_hostname = False
    permissive.verify_mode = ssl.CERT_NONE
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as raw_sock,
            permissive.wrap_socket(raw_sock, server_hostname=host) as tls_sock,
        ):
            info.handshake_ok = True
            _fill_connection_details(info, tls_sock)
            der = tls_sock.getpeercert(binary_form=True)
            if der:
                decoded = _decode_unverified_cert(der)
                if decoded:
                    _fill_certificate_details(info, decoded, host)
    except (OSError, ssl.SSLError, ValueError) as exc:  # pragma: no cover - network dependent
        if not info.error:
            info.error = f"connection failed: {exc}"
    return info


def _fill_connection_details(info: TLSInfo, tls_sock: ssl.SSLSocket) -> None:
    info.protocol = tls_sock.version()
    cipher = tls_sock.cipher()
    if cipher:
        info.cipher = cipher[0]
        info.cipher_bits = cipher[2] if len(cipher) > 2 else None
    try:
        info.alpn = tls_sock.selected_alpn_protocol()
    except Exception:  # pragma: no cover - platform dependent
        info.alpn = None


def _fill_certificate_details(info: TLSInfo, cert: dict[str, Any], host: str) -> None:
    info.issuer = _format_name(cert.get("issuer"))
    info.subject = _format_name(cert.get("subject"))
    info.serial = cert.get("serialNumber")
    info.not_before = cert.get("notBefore")
    info.not_after = cert.get("notAfter")
    info.subject_alt_names = [value for kind, value in cert.get("subjectAltName", ()) or () if kind.lower() == "dns"]

    expires_at = _parse_cert_time(info.not_after)
    if expires_at is not None:
        delta = expires_at - datetime.now(timezone.utc)
        info.days_remaining = int(delta.total_seconds() // 86400)
        info.expired = delta.total_seconds() <= 0
    if not info.verified:
        info.hostname_valid = match_hostname(cert, host)


def analyze_tls(
    info: TLSInfo | None,
    is_https: bool,
    warn_days: int = 30,
) -> tuple[list[tuple[str, Severity, str]], list[Finding]]:
    """Turn a :class:`TLSInfo` into display rows plus findings."""
    rows: list[tuple[str, Severity, str]] = []
    findings: list[Finding] = []

    if not is_https:
        rows.append(("HTTPS", Severity.HIGH, "not in use — traffic is sent in clear text"))
        return rows, findings

    if info is None:
        rows.append(("TLS inspection", Severity.INFO, "skipped"))
        return rows, findings

    if not info.handshake_ok:
        rows.append(("TLS handshake", Severity.MEDIUM, info.error or "failed"))
        findings.append(
            make_finding(
                "HS-016",
                reason=info.error or "The TLS handshake could not be completed.",
                value=f"{info.host}:{info.port}",
            )
        )
        return rows, findings

    rows.append(("HTTPS enabled", Severity.PASS, f"{info.host}:{info.port}"))

    if info.verified:
        rows.append(("Certificate chain", Severity.PASS, "valid and trusted"))
    else:
        rows.append(("Certificate chain", Severity.HIGH, info.error or "verification failed"))
        findings.append(
            make_finding(
                "HS-014",
                reason=info.error or "The certificate chain could not be validated against the system trust store.",
                value=info.issuer or info.subject or info.host,
            )
        )

    if info.hostname_valid:
        rows.append(("Hostname", Severity.PASS, f"matches certificate ({info.host})"))
    else:
        rows.append(("Hostname", Severity.HIGH, f"certificate does not cover {info.host}"))
        findings.append(
            make_finding(
                "HS-012",
                reason=f"The certificate does not list {info.host} in its subjectAltName / commonName.",
                value=", ".join(info.subject_alt_names[:6]) or info.subject or "",
            )
        )

    if info.expired:
        rows.append(("Validity", Severity.CRITICAL, f"expired on {info.not_after}"))
        findings.append(
            make_finding(
                "HS-010",
                reason=f"The certificate expired on {info.not_after}.",
                value=info.not_after,
            )
        )
    elif info.days_remaining is not None:
        if info.days_remaining <= warn_days:
            rows.append(("Validity", Severity.MEDIUM, f"expires in {info.days_remaining} day(s) ({info.not_after})"))
            findings.append(
                make_finding(
                    "HS-011",
                    reason=f"The certificate expires in {info.days_remaining} day(s) on {info.not_after}.",
                    value=info.not_after,
                )
            )
        else:
            rows.append(("Validity", Severity.PASS, f"{info.days_remaining} days remaining ({info.not_after})"))

    if info.protocol:
        if info.protocol in OBSOLETE_PROTOCOLS:
            rows.append(("Protocol", Severity.HIGH, f"{info.protocol} is obsolete"))
            findings.append(
                make_finding(
                    "HS-013",
                    reason=f"The server negotiated {info.protocol}, which is deprecated.",
                    value=info.protocol,
                )
            )
        elif info.protocol == "TLSv1.3":
            rows.append(("Protocol", Severity.PASS, info.protocol))
        else:
            rows.append(("Protocol", Severity.INFO, f"{info.protocol} (TLS 1.3 not negotiated)"))
            findings.append(
                make_finding(
                    "HS-015",
                    reason=f"The handshake negotiated {info.protocol}; TLS 1.3 was not selected.",
                    value=info.protocol,
                )
            )

    if info.cipher:
        rows.append(("Cipher", Severity.INFO, f"{info.cipher}" + (f" ({info.cipher_bits} bit)" if info.cipher_bits else "")))
    if info.issuer:
        rows.append(("Issuer", Severity.INFO, _friendly_issuer(info.issuer) or info.issuer))
    if info.subject_alt_names:
        preview = ", ".join(info.subject_alt_names[:4])
        if len(info.subject_alt_names) > 4:
            preview += f" (+{len(info.subject_alt_names) - 4} more)"
        rows.append(("SAN", Severity.INFO, preview))
    if info.alpn:
        rows.append(("ALPN", Severity.INFO, info.alpn))

    return rows, findings


def friendly_issuer(info: TLSInfo | None) -> str:
    """Short issuer label for summary tables."""
    if info is None:
        return "n/a"
    return _friendly_issuer(info.issuer) or "unknown"


def iter_rows(rows: Iterable[tuple[str, Severity, str]]) -> list[dict[str, str]]:
    """Convert display rows into JSON-friendly dictionaries."""
    return [{"label": label, "status": status.value, "detail": detail} for label, status, detail in rows]
