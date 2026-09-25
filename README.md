<div align="center">

```
██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗
██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝
██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗
██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝
        ░▒▓  S P E C T E R  ▓▒░  v1.0.0
```

# HeaderSpecter

**HTTP Security Header Analyzer & Security Posture Scanner**

*See what your headers reveal — before an attacker does.*

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-22d3ee)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux%20%7C%20Linux%20%7C%20macOS%20%7C%20WSL-a78bfa)](#installation)
[![Tests](https://img.shields.io/badge/tests-194%20passing-34d399)](#development--testing)
[![Defensive Security](https://img.shields.io/badge/scope-defensive%20only-ff7849)](#legal-disclaimer)

Created by **Mr Dinesh Pathro** · ☕ [buymeacoffee.com/mrdineshpathro](https://buymeacoffee.com/mrdineshpathro)

</div>

---

## Table of contents

- [What is HeaderSpecter?](#what-is-headerspecter)
- [Features](#features)
- [Sample output](#sample-output)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Command line reference](#command-line-reference)
- [Usage examples](#usage-examples)
- [Output formats](#output-formats)
- [Scoring model](#scoring-model)
- [Finding catalogue](#finding-catalogue)
- [Custom policies](#custom-policies)
- [Baselines, watch mode and CI](#baselines-watch-mode-and-ci)
- [Interactive mode](#interactive-mode)
- [Local demo lab](#local-demo-lab)
- [Project structure](#project-structure)
- [Development & testing](#development--testing)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Legal disclaimer](#legal-disclaimer)
- [Contributing](#contributing)
- [Author & support](#author--support)
- [License](#license)

---

## What is HeaderSpecter?

HeaderSpecter is a **defensive security tool** that fetches a URL, inspects every HTTP response
header the server returns, and explains — in plain language — what the configuration means for the
people using that site.

Most header checkers stop at *"header present / header missing"*. HeaderSpecter goes further:

- it **parses** the values (a full CSP directive parser, HSTS token parser, cookie attribute parser,
  Permissions-Policy structured-header parser, CORS reflection detection, TLS certificate inspection),
- it **reasons** about combinations (`X-Frame-Options` vs `frame-ancestors`, `COOP` + `COEP` isolation,
  `'unsafe-inline'` neutralised by a nonce, `SameSite=None` without `Secure`),
- it **explains impact and gives the exact fix**, with copy-paste Nginx / Apache / Cloudflare / Express
  snippets,
- and it turns all of that into a **transparent, auditable score** you can track over time.

It is built for blue teams hardening their own estate, pentesters and bug-bounty hunters doing
authorised reconnaissance, DevOps engineers wiring header regressions into CI, and anyone who wants
to understand *why* a header matters.

> **Defensive by design.** HeaderSpecter sends ordinary GET/HEAD requests — the same thing a browser
> does. It never exploits anything, never sends payloads, never brute-forces, never floods a target.

---

## Features

### Deep header analysis
- **Content-Security-Policy** — full directive parser with `default-src` fallback resolution,
  `'unsafe-inline'` / `'unsafe-eval'` / `'unsafe-hashes'` detection, wildcard and dangerous-scheme
  sources, nonce entropy checks, `strict-dynamic` recognition, allow-list size review, Report-Only
  detection, multiple-policy handling, unknown-directive typo catching and reporting-endpoint checks.
- **HSTS** — `max-age` thresholds, `includeSubDomains`, `preload`, malformed tokens, `max-age=0`
  rollback and the "sent over plaintext HTTP so it is ignored" case.
- **Clickjacking** — `X-Frame-Options` (incl. the obsolete `ALLOW-FROM`) reconciled with CSP
  `frame-ancestors`, including conflict detection between the two.
- **MIME sniffing** — `X-Content-Type-Options` presence and token validity.
- **Referrer-Policy** — all eight tokens, comma-separated fallback lists, effective-policy resolution
  and privacy-leak classification.
- **Permissions-Policy** — structured-header parser, wildcard grants, malformed directives, unrestricted
  sensitive features, plus deprecated `Feature-Policy` detection.
- **Cross-origin isolation** — `COOP`, `CORP`, `COEP`, invalid tokens and *incompatible combinations*
  (e.g. `COEP: require-corp` without `COOP: same-origin` never achieves `crossOriginIsolated`).
- **CORS** — wildcard origins, `null` origin, credentials combinations, **arbitrary origin reflection**
  (detected with a passive `Origin:` probe), missing `Vary: Origin`, over-broad methods/headers.
- **Cookies** — every `Set-Cookie` parsed individually: `Secure`, `HttpOnly`, `SameSite`,
  `Domain` scope, `Path`, lifetime, `__Secure-`/`__Host-` prefix rules. Cookie values are always
  redacted in output.
- **TLS posture** — certificate validity/expiry, hostname (SAN/CN wildcard) matching, chain trust,
  negotiated protocol and cipher, ALPN — via one standard handshake, nothing intrusive.
- **Redirect chain** — every hop with status and timing, HTTPS→HTTP downgrades, cross-host jumps,
  loops and excessive length.
- **Information disclosure** — `Server`, `X-Powered-By`, ASP.NET version headers, `Via`,
  `X-Backend-Server`, `X-Generator` and friends, clearly labelled as observations rather than bugs.
- **Legacy & deprecated headers** — `X-XSS-Protection`, `Expect-CT`, `Public-Key-Pins`, `Pragma`,
  `Feature-Policy`, `X-Permitted-Cross-Domain-Policies`, marked **DEPRECATED** / **LEGACY**.
- **Caching** — `Cache-Control` review, sensitive-response caching, `Clear-Site-Data` usage.

### Reporting & workflow
- 🎨 **Beautiful terminal UI** — Rich-powered panels, tables, gradient ASCII banner, progress bars,
  icons **plus** text labels (never colour alone), ASCII fallback and full `--no-color` support.
- 📊 **Transparent scoring** — 0–100 with an A+…F grade and a line-by-line breakdown of every deduction.
- 🧾 **Five output formats** — terminal, JSON (stdout or file), CSV, Markdown and a standalone dark-theme
  HTML report with **zero external dependencies** (no CDN, no JavaScript).
- ⚡ **Async batch scanning** — `-l targets.txt`, configurable concurrency, polite delay, retries with
  backoff, live progress and a comparison scoreboard.
- 🔁 **Baselines & watch mode** — save a baseline, diff against it later, or monitor a target
  continuously and get notified only about *meaningful* changes (volatile headers are ignored).
- 📋 **Custom policies** — YAML/JSON files defining required/forbidden headers, allowed values
  (literal or regex), severity overrides, scoring weights and a minimum score.
- 🧪 **CI ready** — `--fail-on`, `--min-score`, machine-readable JSON, meaningful exit codes.
- 🖥️ **Interactive mode** — a guided menu for operators who prefer prompts over flags.
- 📴 **Offline mode** — `--from-raw` analyses a saved response head with zero network traffic.
- 🧰 **Built-in demo lab** — `examples/demo_server.py` serves hardened/weak/legacy profiles so you can
  learn the tool without touching third-party infrastructure.

---

## Sample output

```text
╭────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                    │
│                  ██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗                   │
│                  ██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗                  │
│                  ███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝                  │
│                  ██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗                  │
│                  ██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║                  │
│                  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝                  │
│                  ░▒▓ S P E C T E R  ▓▒░  v1.0.0                                    │
│                                                                                    │
│      HTTP Security Header Analyzer & Security Posture Scanner                      │
│      Created by Mr Dinesh Pathro   ☕ https://buymeacoffee.com/mrdineshpathro      │
│                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────╯
Authorised use only — scan systems you own or have written permission to test.
╭─ Response ─────────────────────────────────────────────────────────────────────────╮
│  Target        https://hardened.example.com/                                       │
│  Status        200 OK                                                              │
│  Protocol      HTTPS · HTTP/2                                                      │
│  Response      214 ms                                                              │
│  Cookies       1                                                                   │
│  Headers       17                                                                  │
╰────────────────────────────────────────────────────────────────────────────────────╯
╭─ Security Score ───────────────────────────────────────────────────────────────────╮
│  96 / 100   Grade A+                                                               │
│  ███████████████████████████████████████░                                          │
│                                                                                    │
│  ⛔ Critical 0   ✗ High     0   ⚠ Medium   0   ▲ Low      1   ℹ Info     1         │
│  base 100  −3.5 deductions  +4.0 bonus                                             │
╰────────────────────────────────────────────────────────────────────────────────────╯

HEADER SECURITY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     Header                         Status       Value / Note
──────────────────────────────────────────────────────────────────────────────────────
✓    Content-Security-Policy        PASS         default-src 'self'; script-src 'self'…
✓    Strict-Transport-Security      PASS         max-age=63072000; includeSubDomains; …
✓    X-Content-Type-Options         PASS         nosniff
✓    X-Frame-Options                PASS         DENY
✓    Referrer-Policy                PASS         strict-origin-when-cross-origin
✓    Permissions-Policy             PASS         camera=(), microphone=(), geolocation…
✓    Cross-Origin-Opener-Policy     PASS         same-origin
✓    Cross-Origin-Resource-Policy   PASS         same-origin
✓    Cross-Origin-Embedder-Policy   PASS         require-corp
```

A weak target produces per-finding detail panels instead:

```text
╭─ [HIGH] HS-101  CSP allows 'unsafe-inline' scripts ────────────────────────────────╮
│  Observed  : script-src: 'self' 'unsafe-inline' 'unsafe-eval' http://cdn.example   │
│  Detail    : script-src allows 'unsafe-inline', so inline scripts and event        │
│              handlers execute.                                                     │
│                                                                                    │
│  Impact    : 'unsafe-inline' in a script directive permits inline <script> blocks  │
│  and event handlers, which is exactly the capability an XSS payload needs — the    │
│  policy stops being a meaningful mitigation.                                       │
│                                                                                    │
│  Fix       : Move inline scripts to external files, or adopt a nonce/hash based    │
│  strict CSP with 'strict-dynamic' for third-party loaders.                         │
│                                                                                    │
│  Recommended header                                                                │
│    Content-Security-Policy: script-src 'nonce-{RANDOM}' 'strict-dynamic' https:;   │
│    object-src 'none'; base-uri 'self'                                              │
╰────────────────────────────────────────────────────────────────────────────────────╯
```

Ready-made examples live in [`reports/`](reports): `sample-report.html` (open it in a browser),
`sample-report.md`, `sample-batch.json` and `sample-findings.csv`.

---

## Installation

### Kali Linux / Debian / Ubuntu (recommended: virtual environment)

Modern Kali images ship a *externally managed* Python, so install into a venv:

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git

git clone https://github.com/mrdineshpathro-dot/HeaderSpecter.git
cd HeaderSpecter

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
pip install -e .                 # installs the `headerspecter` command

headerspecter --version
```

Add it to your `PATH` permanently (optional):

```bash
sudo ln -s "$(pwd)/.venv/bin/headerspecter" /usr/local/bin/headerspecter
```

### With pipx (isolated, always on PATH)

```bash
sudo apt install -y pipx
pipx install git+https://github.com/mrdineshpathro-dot/HeaderSpecter.git
```

### Run without installing

```bash
git clone https://github.com/mrdineshpathro-dot/HeaderSpecter.git
cd HeaderSpecter
pip install -r requirements.txt
python3 -m headerspecter https://example.com
```

### Optional extras

```bash
pip install 'headerspecter[http2]'   # HTTP/2 negotiation via the h2 package
pip install -r requirements-dev.txt  # pytest, respx, ruff
```

**Requirements:** Python 3.10+, `rich`, `httpx`, `PyYAML`. Everything else is standard library.

---

## Quick start

```bash
# 1. Scan a site (the scheme is optional — example.com becomes https://example.com/)
headerspecter example.com

# 2. Get the full story: every finding, remediation templates and the score breakdown
headerspecter https://example.com --verbose

# 3. Produce a shareable report
headerspecter https://example.com --html report.html

# 4. Scan a whole list, politely and in parallel
headerspecter -l targets.txt --threads 20 --delay 0.2

# 5. Feed a pipeline
headerspecter https://example.com --json | jq '.analysis.score.score'
```

---

## Command line reference

### Targets

| Option | Description |
|---|---|
| `TARGET` | URL or hostname (`example.com`, `https://example.com/app`, `10.0.0.5:8443`) |
| `-u, --url URL` | Target URL (alternative to the positional argument) |
| `-l, --list FILE` | File with one target per line (`#` comments and blanks ignored, duplicates removed) |
| `--from-raw FILE` | Analyse a **saved raw response head** offline — no network traffic at all |
| `--stdin` | Force reading targets from standard input (auto-detected when piped) |

### Output

| Option | Description |
|---|---|
| `-o, --output FILE` | Write a report; the format is inferred from the extension (`.json`, `.csv`, `.html`, `.md`) |
| `--json` | Print JSON to stdout (machine readable, pipe-friendly) |
| `--csv FILE` | Write findings as CSV (one row per finding) |
| `--html FILE` | Write a standalone dark-theme HTML report |
| `--markdown FILE`, `--md FILE` | Write a Markdown report |
| `--raw` | Also print the raw response headers exactly as received |
| `--no-banner` | Suppress the ASCII banner |

### Sections (default: everything)

`--headers` · `--cookies` · `--csp` · `--cors` · `--tls` · `--redirects` · `--score` · `--findings`

Combine them freely — `headerspecter example.com --csp --cookies` shows only those two analyses.

### Network

| Option | Default | Description |
|---|---|---|
| `--timeout SECONDS` | `15` | Per-request timeout |
| `--retries N` | `2` | Retries for transport errors (exponential backoff) |
| `-t, --threads N` | `10` | Concurrent targets in batch mode |
| `--delay SECONDS` | `0` | Delay before each request (be polite) |
| `--proxy URL` | – | Route through Burp Suite / ZAP / a corporate proxy |
| `--user-agent STRING` | browser-like | Custom `User-Agent` |
| `-H, --header 'Name: value'` | – | Extra request header (repeatable) |
| `--method VERB` | `GET` | HTTP method for the main request |
| `--no-follow-redirects` | follow | Do not follow redirects |
| `--max-redirects N` | `10` | Maximum redirects to follow |
| `--verify-tls` | off | Abort on invalid certificates instead of reporting them |
| `--no-tls-check` | – | Skip the TLS handshake inspection |
| `--no-probes` | – | Skip the passive CORS `Origin` probe and the HTTP→HTTPS upgrade check |

### Modes

| Option | Description |
|---|---|
| `-i, --interactive` | Launch the guided menu |
| `--watch` | Re-scan periodically and report changes |
| `--interval SECONDS` | Watch interval (default `60`, minimum `5`) |
| `--iterations N` | Stop watch mode after N scans (`0` = run until Ctrl+C) |
| `--save-baseline FILE` | Save this scan as a baseline JSON file |
| `--compare FILE` | Diff the current scan against a baseline |
| `--policy FILE` | Apply a custom header policy (YAML or JSON) |
| `--fail-on SEVERITY` | Exit `2` when a finding of this severity or worse exists |
| `--min-score N` | Exit `2` when the score is below N |

### General

`-q, --quiet` (one compact line per target) · `-v, --verbose` · `--debug` · `--no-color` · `-V, --version` · `-h, --help`

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, thresholds satisfied |
| `1` | Usage error, unreachable target, unreadable file |
| `2` | Threshold breached (`--fail-on` / `--min-score` / policy `min_score`) |
| `130` | Interrupted with Ctrl+C |

---

## Usage examples

```bash
# Full analysis with remediation templates and score breakdown
headerspecter https://example.com --verbose

# Only the CSP and cookie sections
headerspecter https://example.com --csp --cookies

# Raw headers plus the score, nothing else
headerspecter https://example.com --raw --score

# Batch scan with a progress bar and a comparison scoreboard
headerspecter -l examples/targets.txt --threads 20 --delay 0.1

# Pipe targets in from another tool (subfinder, httpx, cat, ...)
cat subdomains.txt | headerspecter --json > estate.json

# Route everything through Burp Suite for inspection
headerspecter https://example.com --proxy http://127.0.0.1:8080

# Authenticated scan with custom headers
headerspecter https://app.example.com \
  -H 'Authorization: Bearer eyJhbGciOi...' \
  -H 'X-Tenant: acme'

# Analyse a response captured earlier (fully offline)
curl -sD headers.txt -o /dev/null https://example.com
headerspecter --from-raw headers.txt -u https://example.com

# Save a baseline today, compare after the next deployment
headerspecter https://example.com --save-baseline baseline.json
headerspecter https://example.com --compare baseline.json

# Monitor a target every two minutes and report only real changes
headerspecter https://example.com --watch --interval 120

# Enforce the corporate baseline and fail the pipeline on regressions
headerspecter https://example.com --policy examples/policy.yaml --fail-on high

# Everything at once: HTML for humans, JSON for machines, CSV for the ticket system
headerspecter -l targets.txt --html report.html -o report.json --csv findings.csv
```

---

## Output formats

| Format | Flag | Best for |
|---|---|---|
| **Terminal** | *(default)* | Interactive review, live triage |
| **JSON** | `--json`, `-o report.json` | Automation, `jq`, dashboards, diffing |
| **HTML** | `--html report.html` | Sharing with developers and management (single self-contained file) |
| **Markdown** | `--md report.md` | Pull requests, wikis, engagement notes |
| **CSV** | `--csv findings.csv` | Spreadsheets, ticket imports, metrics |

The JSON schema is stable and versioned (`"schema": 1`). A single-target scan emits the bare result
object; a batch emits an envelope with `target_count`, `average_score` and a `results` array.

```bash
headerspecter https://example.com --json | jq '{
  score: .score,
  grade: .grade,
  critical: .analysis.counts.CRITICAL,
  top: [.analysis.findings[] | select(.severity=="HIGH") | .id]
}'
```

---

## Scoring model

Every target starts at **100** points. The engine is intentionally boring and completely auditable —
there are no hidden constants, and every deduction is printed with `--verbose` (or found in
`analysis.score.deductions` in the JSON).

```
score = 100
        − Σ (severity_weight × header_multiplier)     # capped per finding and per category
        + bonuses (max +4)
```

| Severity | Default weight | Typical examples |
|---|---|---|
| CRITICAL | 28 | Expired TLS certificate |
| HIGH | 15 | Missing HSTS, `'unsafe-inline'` scripts, CORS reflection with credentials |
| MEDIUM | 7 | Short HSTS `max-age`, missing `nosniff`, weak Referrer-Policy |
| LOW | 3 | Missing COOP/CORP, version disclosure, missing `form-action` |
| INFO | 0.5 | No CSP reporting endpoint, deprecated `Expect-CT` present |
| PASS | 0 | Check passed |

**Header multipliers** weight the headers that matter most (CSP ×1.25, HSTS ×1.20, `Server` ×0.60 …),
**per-category caps** stop one noisy area (twenty insecure cookies) from dominating the result, and a
small **bonus** rewards going beyond the baseline: HSTS preload (+1.5), nonce/hash-based CSP (+2.0) and
cross-origin isolation (+1.5).

| Grade | Score | Meaning |
|---|---|---|
| **A+** | 95–100 | Exemplary — modern, strict configuration |
| **A** | 90–94 | Strong |
| **B** | 80–89 | Good, with room to tighten |
| **C** | 70–79 | Acceptable but several gaps |
| **D** | 60–69 | Weak |
| **E** | 40–59 | Poor |
| **F** | 0–39 | Critical gaps — treat as a priority |

Every weight, multiplier, cap and bonus can be overridden in a [policy file](#custom-policies).

---

## Finding catalogue

Each check has a stable identifier, so you can track, suppress or reference a specific issue over
time and across reports.

| Range | Area | Examples |
|---|---|---|
| **HS-0xx** | Transport & TLS | `HS-001` missing HSTS · `HS-007` plaintext HTTP · `HS-010` expired certificate · `HS-013` obsolete TLS |
| **HS-1xx** | Content-Security-Policy | `HS-100` missing CSP · `HS-101` `'unsafe-inline'` · `HS-109` `data:` in `script-src` · `HS-122` weak nonce |
| **HS-2xx** | Framing, MIME, referrer, permissions | `HS-200` no clickjacking protection · `HS-210` missing `nosniff` · `HS-221` weak Referrer-Policy · `HS-231` wildcard feature grant |
| **HS-3xx** | Cross-origin isolation & CORS | `HS-305` incomplete isolation · `HS-311` wildcard + credentials · `HS-312` origin reflection with credentials · `HS-314` `null` origin |
| **HS-4xx** | Cookies | `HS-400` no `Secure` · `HS-401` no `HttpOnly` · `HS-403` `SameSite=None` without `Secure` · `HS-405` prefix violation |
| **HS-5xx** | Disclosure & deprecated headers | `HS-500` server version · `HS-510` `X-XSS-Protection` · `HS-513` HPKP · `HS-515` permissive cross-domain policy |
| **HS-6xx** | Caching | `HS-600` no `Cache-Control` · `HS-601` cacheable sensitive response |
| **HS-7xx** | Redirects & response | `HS-700` HTTPS→HTTP downgrade · `HS-701` long chain · `HS-704` server error |
| **HS-9xx** | Custom policy violations | `HS-900` required header missing · `HS-901` forbidden header · `HS-902` value mismatch |

Every finding carries: **ID · severity · header · observed value · reason · impact · recommendation ·
remediation template · references**.

---

## Custom policies

Describe your own baseline once and enforce it everywhere:

```yaml
name: Corporate web baseline

required:
  - content-security-policy
  - strict-transport-security
  - x-content-type-options

forbidden:
  - x-powered-by
  - public-key-pins

values:
  x-frame-options: [DENY, SAMEORIGIN]
  referrer-policy: "re:^(no-referrer|strict-origin.*)$"

severity:
  HS-100: critical          # missing CSP blocks our releases
  x-powered-by: medium

scoring:
  severity_weights: { HIGH: 16 }
  category_caps:   { csp: 34 }

min_score: 80
```

```bash
headerspecter https://example.com --policy examples/policy.yaml
```

Violations appear as `HS-900` / `HS-901` / `HS-902` findings, severity overrides are applied to every
matching finding (by ID **or** header name), and `min_score` makes the process exit with code `2`
when the target falls below the bar. A fully commented template lives in
[`examples/policy.yaml`](examples/policy.yaml).

---

## Baselines, watch mode and CI

**Baselines** capture the full header state of a target so you can prove nothing regressed:

```bash
headerspecter https://example.com --save-baseline baselines/example.json
# ... after the next release ...
headerspecter https://example.com --compare baselines/example.json
```

```text
HEADER CHANGES  baseline 2026-09-01T09:00:00+00:00 → now
+ Cross-Origin-Opener-Policy  same-origin
- X-Powered-By                PHP/8.2.4
~ Content-Security-Policy
    was : default-src 'self' 'unsafe-inline'
    now : default-src 'self'; script-src 'self' 'nonce-…'
RESOLVED [HIGH] HS-101 CSP allows 'unsafe-inline' scripts
Score  74 → 91  (+17.0)
```

**Watch mode** keeps scanning and only speaks up when something meaningful changes (`Date`, `ETag`,
request-ids and cookie *values* are ignored):

```bash
headerspecter https://example.com --watch --interval 300
```

**GitHub Actions** example:

```yaml
name: Security headers
on: [push, schedule]

jobs:
  headers:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install git+https://github.com/mrdineshpathro-dot/HeaderSpecter.git
      - name: Audit production headers
        run: |
          headerspecter https://example.com \
            --policy .github/header-policy.yaml \
            --fail-on high \
            --no-color \
            -o headerspecter-report.json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: headerspecter-report
          path: headerspecter-report.json
```

---

## Interactive mode

```bash
headerspecter --interactive
```

```text
┏━ HeaderSpecter v1.0.0 · interactive ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  [1]  Scan URL                                                                   ┃
┃  [2]  Scan target list                                                           ┃
┃  [3]  Analyze raw headers                                                        ┃
┃  [4]  Compare baseline                                                           ┃
┃  [5]  Generate report from last scan                                             ┃
┃  [6]  Configuration                                                              ┃
┃  [7]  About                                                                      ┃
┃  [0]  Exit                                                                       ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

Option **3** accepts a file *or* a pasted response head (finish with a single `.` on its own line) —
handy for analysing headers captured with `curl -I`, Burp or a browser's devtools.

---

## Local demo lab

A self-contained target server ships with the project so you can explore every code path safely:

```bash
python3 examples/demo_server.py --port 8080          # terminal 1

headerspecter http://127.0.0.1:8080/        --no-tls-check   # hardened profile
headerspecter http://127.0.0.1:8080/weak    --verbose        # unsafe CSP, bad cookies, CORS
headerspecter http://127.0.0.1:8080/legacy                   # HPKP, Expect-CT, Feature-Policy
headerspecter http://127.0.0.1:8080/api                      # reflects any Origin header
headerspecter http://127.0.0.1:8080/redirect --redirects     # three-hop chain
headerspecter -l examples/targets.txt --threads 5            # the whole lab at once
```

---

## Project structure

```
HeaderSpecter/
├── headerspecter/
│   ├── __init__.py          # version and project metadata
│   ├── __main__.py          # python3 -m headerspecter
│   ├── cli.py               # argument parsing, modes, orchestration
│   ├── config.py            # ScanConfig / ScoringConfig / OutputConfig, grade bands
│   ├── scanner.py           # async httpx engine, retries, probes, error mapping
│   ├── analyzer.py          # analysis orchestrator + ScanResult model (pure, testable)
│   ├── headers.py           # header registry, HeaderBag, per-header analyzers
│   ├── csp.py               # Content-Security-Policy parser and analyzer
│   ├── cookies.py           # Set-Cookie parser and cookie hardening rules
│   ├── cors.py              # CORS analysis incl. origin-reflection detection
│   ├── tls.py               # TLS handshake inspection and certificate checks
│   ├── redirects.py         # redirect chain analysis
│   ├── findings.py          # severity model + the HS-### check catalogue
│   ├── scoring.py           # transparent scoring engine
│   ├── policy.py            # custom YAML/JSON policies
│   ├── reporter.py          # terminal rendering, JSON/CSV/Markdown, baseline diffing
│   ├── html_report.py       # standalone HTML report generator
│   └── ui.py                # Rich UI: banner, panels, tables, progress, menu
├── tests/                   # 194 offline unit tests (pytest)
├── examples/
│   ├── policy.yaml          # fully commented policy template
│   ├── targets.txt          # example target list
│   ├── demo_server.py       # local lab target with several header profiles
│   └── raw-headers-*.txt    # fixtures for --from-raw
├── reports/                 # generated reports (samples committed)
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml
├── LICENSE
└── README.md
```

---

## Development & testing

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .

pytest                     # 194 tests, fully offline (network is mocked with respx)
pytest -v tests/test_csp.py
ruff check headerspecter   # lint
```

The analysis engine is a **pure function** over captured response data, so every analyzer can be
tested from fixtures without a network. Contributions should keep it that way: add a fixture, add a
check to `findings.py`, wire it into the relevant analyzer, and add a test.

---

## Troubleshooting

<details>
<summary><strong>“externally-managed-environment” when running pip on Kali</strong></summary>

Debian/Kali protect the system Python. Use a virtual environment (recommended):

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
```

or install with `pipx`. Avoid `pip install --break-system-packages` unless you know why you need it.
</details>

<details>
<summary><strong>`headerspecter: command not found` after installing</strong></summary>

The console script lives inside the venv. Either activate it (`source .venv/bin/activate`), call it
directly (`.venv/bin/headerspecter`), symlink it into `/usr/local/bin`, or use
`python3 -m headerspecter`.
</details>

<details>
<summary><strong>“TLS handshake failed — the port does not appear to speak HTTPS”</strong></summary>

A bare `host:port` target defaults to `https://`. If the service is plaintext, be explicit:
`headerspecter http://127.0.0.1:8080/`.
</details>

<details>
<summary><strong>Certificate errors block the scan</strong></summary>

By default HeaderSpecter still analyses the headers and *reports* the certificate problem as a
finding (`HS-010`/`HS-012`/`HS-014`). Use `--verify-tls` if you would rather abort on invalid
certificates, or `--no-tls-check` to skip the handshake inspection entirely.
</details>

<details>
<summary><strong>Timeouts or throttling on large batches</strong></summary>

Lower the concurrency and add a delay: `--threads 5 --delay 0.5 --timeout 30 --retries 3`.
WAFs may rate-limit aggressive scans — be polite, especially on third-party estates.
</details>

<details>
<summary><strong>Boxes render as `?` or the colours look wrong</strong></summary>

Your terminal is not UTF-8 or does not support colour. HeaderSpecter falls back automatically, but
you can force it: `--no-color`, or `export HEADERSPECTER_ASCII=1` for ASCII icons. For plain logs,
combine `--no-color --quiet`.
</details>

<details>
<summary><strong>The CORS/upgrade probes are not welcome on this target</strong></summary>

`--no-probes` disables the extra `Origin:` request and the plaintext HTTP check, leaving exactly one
request per target.
</details>

<details>
<summary><strong>Scanning through Burp/ZAP fails</strong></summary>

Make sure the proxy is listening and reachable: `--proxy http://127.0.0.1:8080`. Intercepting proxies
re-sign TLS, which HeaderSpecter will honestly report as a chain-validation failure — that is the
proxy, not the site.
</details>

---

## FAQ

**Does HeaderSpecter attack the target?**
No. It performs a normal `GET` (plus an optional `Origin`-carrying `GET` and one `HEAD` to the
plaintext port). No payloads, no fuzzing, no brute force, no DoS.

**Why is my score lower than another online checker's?**
HeaderSpecter grades *values*, not just presence. A CSP containing `'unsafe-inline'` and `*` scores
far below a strict nonce-based policy even though both "have a CSP".

**Can I suppress a finding I have accepted as a risk?**
Use a policy file to lower its severity (`severity: { HS-004: info }`) or its scoring weight. Every
finding keeps its stable ID so exceptions stay readable in review.

**Does it store cookie values or secrets?**
No. Cookie values are redacted to a 4-character prefix plus a length in every output format.

**Can I run it fully offline?**
Yes — `--from-raw response.txt` analyses saved headers with zero network traffic, and the whole test
suite runs offline.

---

## Legal disclaimer

> **HeaderSpecter is a defensive security tool intended for authorised testing only.**
>
> Scan systems you own or for which you have **explicit written permission** to test. Unauthorised
> scanning of third-party systems may violate the Computer Misuse Act 1990 (UK), the Computer Fraud
> and Abuse Act (US), the EU NIS2/​national equivalents and similar legislation in your jurisdiction.
>
> The author and contributors accept **no liability** for misuse, for damages arising from use of this
> software, or for actions taken based on its output. Remediation templates are starting points that
> must be reviewed against your application's real resource requirements — deploying a strict CSP
> without testing *will* break pages. You are responsible for how you use this tool.
>
> HeaderSpecter performs **no exploitation, payload delivery, credential theft, persistence or
> denial-of-service activity** of any kind, by design.

---

## Contributing

Issues and pull requests are welcome.

1. Fork the repository and create a feature branch.
2. Keep the analysis layer pure (no I/O) so it stays testable.
3. Add tests for new checks — every `HS-###` should have at least one.
4. Run `pytest` and `ruff check headerspecter` before opening the PR.
5. Describe the security rationale for new checks (impact + remediation), not just the detection.

---

## Author & support

**Mr Dinesh Pathro**

If HeaderSpecter saved you time, consider supporting its development:

☕ **[buymeacoffee.com/mrdineshpathro](https://buymeacoffee.com/mrdineshpathro)**

⭐ Star the repository — it genuinely helps other defenders find the project.

---

## License

Released under the [MIT License](LICENSE).

<div align="center">

**HeaderSpecter** · *See what your headers reveal — before an attacker does.*

Made with care for the security community by Mr Dinesh Pathro

</div>
