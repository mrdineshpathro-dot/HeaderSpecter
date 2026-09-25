#!/usr/bin/env python3
"""HeaderSpecter demo target — a tiny local lab server.

Serves several deliberately different header profiles so you can explore the
analyzer without touching third-party infrastructure:

============  =========================================================
Path          Profile
============  =========================================================
``/``         Hardened baseline (strict CSP, HSTS, COOP/COEP, cookies)
``/weak``     Weak/legacy configuration (unsafe CSP, bad cookies, CORS)
``/legacy``   Deprecated headers (HPKP, Expect-CT, X-XSS-Protection)
``/api``      Permissive CORS endpoint that reflects the Origin header
``/redirect`` Three-hop redirect chain ending at ``/``
``/plain``    No security headers at all
============  =========================================================

Usage::

    python3 examples/demo_server.py --port 8080
    headerspecter http://127.0.0.1:8080/ --no-tls-check
    headerspecter http://127.0.0.1:8080/weak --verbose

Only bind this to localhost or a lab network — it intentionally serves
insecure configurations.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STRONG_CSP = (
    "default-src 'self'; script-src 'self' 'nonce-r4nd0mBASE64value123456' 'strict-dynamic'; "
    "style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; "
    "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; "
    "upgrade-insecure-requests; report-to csp-endpoint"
)

WEAK_CSP = (
    "default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval' data:; "
    "style-src * 'unsafe-inline'; img-src *; frame-ancestors *; report-uri /csp-report"
)

PROFILES: dict[str, list[tuple[str, str]]] = {
    "/": [
        ("Content-Security-Policy", STRONG_CSP),
        ("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        (
            "Permissions-Policy",
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), "
            "microphone=(), payment=(), usb=(), interest-cohort=()",
        ),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Cross-Origin-Resource-Policy", "same-origin"),
        ("Cross-Origin-Embedder-Policy", "require-corp"),
        ("X-Permitted-Cross-Domain-Policies", "none"),
        ("Cache-Control", "no-store"),
        ("Reporting-Endpoints", 'csp-endpoint="https://example.com/csp-reports"'),
        ("Set-Cookie", "__Host-session=7f3c9a2b; Path=/; Secure; HttpOnly; SameSite=Lax"),
    ],
    "/weak": [
        ("Content-Security-Policy", WEAK_CSP),
        ("Strict-Transport-Security", "max-age=300"),
        ("X-Frame-Options", "ALLOW-FROM https://partner.example.com"),
        ("X-XSS-Protection", "1; mode=block"),
        ("Referrer-Policy", "unsafe-url"),
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Credentials", "true"),
        ("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, TRACE"),
        ("Access-Control-Allow-Headers", "*"),
        ("Server", "nginx/1.18.0 (Ubuntu)"),
        ("X-Powered-By", "PHP/7.4.3"),
        ("X-AspNet-Version", "4.0.30319"),
        ("Cache-Control", "public, max-age=86400"),
        ("Set-Cookie", "PHPSESSID=8b1f0c2d9e; Path=/; Domain=localhost"),
        ("Set-Cookie", "tracking=1; Path=/; Max-Age=63072000; SameSite=None"),
    ],
    "/legacy": [
        ("Public-Key-Pins", 'pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="; max-age=5184000'),
        ("Expect-CT", "max-age=86400, enforce"),
        ("X-XSS-Protection", "1"),
        ("Pragma", "no-cache"),
        ("Feature-Policy", "camera 'none'; microphone 'none'"),
        ("X-Permitted-Cross-Domain-Policies", "all"),
        ("Server", "Apache/2.4.29 (Ubuntu)"),
        ("X-Generator", "Drupal 7 (https://www.drupal.org)"),
        ("Via", "1.1 internal-cache-03.dc1.local"),
    ],
    "/api": [
        ("Content-Type", "application/json"),
        ("Access-Control-Allow-Credentials", "true"),
        ("Access-Control-Expose-Headers", "X-Internal-Request-Id, X-Debug-Token"),
        ("Cache-Control", "no-store"),
        ("X-Backend-Server", "api-node-7.internal.lab"),
    ],
    "/plain": [],
}

BODY = b"""<!doctype html><html><head><meta charset="utf-8"><title>HeaderSpecter demo target</title>
</head><body><h1>HeaderSpecter demo target</h1>
<p>Try /, /weak, /legacy, /api, /redirect and /plain.</p></body></html>
"""


class DemoHandler(BaseHTTPRequestHandler):
    """Serve the demo header profiles."""

    server_version = "HeaderSpecterDemo/1.0"
    sys_version = ""

    def _send(self, status: int, headers: list[tuple[str, str]], body: bytes = BODY) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        """Handle GET requests."""
        path = self.path.split("?")[0]

        if path == "/redirect":
            self._send(301, [("Location", "/redirect2")], b"")
            return
        if path == "/redirect2":
            self._send(302, [("Location", "/")], b"")
            return

        if path == "/api":
            origin = self.headers.get("Origin")
            headers = list(PROFILES["/api"])
            # Deliberately insecure: reflect any origin (the analyzer flags this).
            headers.append(("Access-Control-Allow-Origin", origin or "*"))
            self._send(200, headers, b'{"status":"ok","demo":true}')
            return

        profile = PROFILES.get(path)
        if profile is None:
            self._send(404, [], b"<h1>404</h1>")
            return
        self._send(200, list(profile))

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        """Handle HEAD requests the same way as GET."""
        self.do_GET()

    def log_message(self, fmt: str, *args: object) -> None:
        """Keep the demo server quiet unless something goes wrong."""
        return


def main() -> int:
    """Run the demo server."""
    parser = argparse.ArgumentParser(description="HeaderSpecter demo target server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), DemoHandler)
    print(f"HeaderSpecter demo target listening on http://{args.host}:{args.port}/")
    print("Profiles: /  /weak  /legacy  /api  /redirect  /plain      (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
