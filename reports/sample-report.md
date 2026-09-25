# HeaderSpecter Security Report

*Generated 2026-09-25T12:09:47+00:00 by HeaderSpecter v1.0.0 — Mr Dinesh Pathro (https://buymeacoffee.com/mrdineshpathro)*

## http://127.0.0.1:8080/weak

| Field | Value |
|---|---|
| Status | 200 OK |
| Final URL | http://127.0.0.1:8080/weak |
| Protocol | HTTP/1.0 |
| Response time | 22 ms |
| Security score | **0 / 100** (grade F) |
| Scanned at | 2026-09-25T12:09:47+00:00 |

**Findings:** 0 critical · 11 high · 11 medium · 16 low · 6 info

### Header security

| Header | Status | Value |
|---|---|---|
| Content-Security-Policy | FAIL | default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval' d… |
| Strict-Transport-Security | WARNING | max-age=300 |
| X-Content-Type-Options | MISSING | MIME sniffing not disabled |
| X-Frame-Options | WARNING | ALLOW-FROM https://partner.example.com |
| Referrer-Policy | WARNING | unsafe-url |
| Permissions-Policy | MISSING | Browser feature defaults apply |
| Cross-Origin-Opener-Policy | MISSING | Browsing context not isolated |
| Cross-Origin-Resource-Policy | MISSING | Embedding not restricted |
| Cross-Origin-Embedder-Policy | MISSING | Not cross-origin isolated |
| Access-Control-Allow-Origin | FAIL | * |
| X-XSS-Protection | DEPRECATED | 1; mode=block |
| X-Permitted-Cross-Domain-Policies | MISSING | Legacy Adobe clients fall back to crossdomain.xml |

### Findings

#### [HIGH] HS-007 — Target served over plaintext HTTP

- **Observed:** `http://127.0.0.1:8080/weak`
- **Detail:** The target was served over plaintext HTTP (http://127.0.0.1:8080/weak); no transport encryption protects the response or its cookies.
- **Impact:** All traffic — including cookies, tokens and form data — is transmitted in the clear and can be read or modified by anyone on the network path.
- **Recommendation:** Terminate TLS for this host and permanently redirect HTTP to HTTPS.

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

#### [HIGH] HS-101 — CSP allows 'unsafe-inline' scripts

- **Header:** `content-security-policy`
- **Observed:** `script-src: * 'unsafe-inline' 'unsafe-eval' data:`
- **Detail:** script-src allows 'unsafe-inline', so inline scripts and event handlers execute.
- **Impact:** 'unsafe-inline' in a script directive permits inline <script> blocks and event handlers, which is exactly the capability an XSS payload needs — the policy stops being a meaningful mitigation.
- **Recommendation:** Move inline scripts to external files, or adopt a nonce/hash based strict CSP with 'strict-dynamic' for third-party loaders.

```http
Content-Security-Policy: script-src 'nonce-{RANDOM}' 'strict-dynamic' https:; object-src 'none'; base-uri 'self'
```

#### [HIGH] HS-103 — CSP directive uses a wildcard source

- **Header:** `content-security-policy`
- **Observed:** `default-src: * 'unsafe-inline' 'unsafe-eval'`
- **Detail:** default-src contains the wildcard source '*', allowing resources from any matching origin.
- **Impact:** A wildcard source lets the page load that resource type from any origin, so an attacker-controlled host is an acceptable source as far as the browser is concerned.
- **Recommendation:** Replace '*' with the explicit origins the application actually needs.

```http
Content-Security-Policy: default-src 'self'; img-src 'self' https://cdn.example.com
```

#### [HIGH] HS-103 — CSP directive uses a wildcard source

- **Header:** `content-security-policy`
- **Observed:** `script-src: * 'unsafe-inline' 'unsafe-eval' data:`
- **Detail:** script-src contains the wildcard source '*', allowing resources from any matching origin.
- **Impact:** A wildcard source lets the page load that resource type from any origin, so an attacker-controlled host is an acceptable source as far as the browser is concerned.
- **Recommendation:** Replace '*' with the explicit origins the application actually needs.

```http
Content-Security-Policy: default-src 'self'; img-src 'self' https://cdn.example.com
```

#### [HIGH] HS-109 — CSP allows a dangerous scheme source

- **Header:** `content-security-policy`
- **Observed:** `script-src: data:`
- **Detail:** Dangerous scheme source(s) in an executable context: script-src: data:.
- **Impact:** data:, blob: or filesystem: in a script/object directive lets an attacker encode a payload directly into a URI and execute it, bypassing origin restrictions.
- **Recommendation:** Remove data:/blob: from script-src and object-src; keep them only for img-src or media where genuinely required.

```http
Content-Security-Policy: script-src 'self' 'nonce-{RANDOM}'; object-src 'none'
```

#### [HIGH] HS-117 — CSP frame-ancestors allows any origin

- **Header:** `content-security-policy`
- **Observed:** `frame-ancestors: *`
- **Detail:** frame-ancestors * allows any site to frame this page.
- **Impact:** frame-ancestors * lets any site frame the page, which enables clickjacking and UI redress attacks against authenticated users.
- **Recommendation:** Set frame-ancestors 'none' or list the specific origins allowed to embed the page.

```http
Content-Security-Policy: frame-ancestors 'none'
```

#### [HIGH] HS-311 — CORS wildcard combined with credentials

- **Header:** `access-control-allow-origin`
- **Observed:** `* + credentials`
- **Detail:** Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is true.
- **Impact:** A wildcard origin together with Access-Control-Allow-Credentials: true is rejected by browsers but signals a misconfigured CORS layer; if the wildcard is ever replaced by origin reflection, any site could read authenticated responses.
- **Recommendation:** Never combine credentials with a wildcard. Echo one validated origin and keep the allow-list short.

```http
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Credentials: true
Vary: Origin
```

#### [HIGH] HS-400 — Cookie without Secure attribute (PHPSESSID)

- **Header:** `set-cookie`
- **Observed:** `PHPSESSID=8b1f0c2d9e; Path=/; Domain=localhost`
- **Detail:** Cookie 'PHPSESSID' is missing the Secure attribute.
- **Impact:** The cookie can be transmitted over plaintext HTTP, so an on-path attacker or a single mixed-content request can capture it.
- **Recommendation:** Add the Secure attribute to every cookie and serve the site exclusively over HTTPS.

```http
Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax; Path=/
```

#### [HIGH] HS-403 — SameSite=None cookie without Secure (tracking)

- **Header:** `set-cookie`
- **Observed:** `tracking=1; Path=/; Max-Age=63072000; SameSite=None`
- **Detail:** Cookie 'tracking' uses SameSite=None without the Secure attribute; browsers reject it.
- **Impact:** SameSite=None requires Secure. Browsers reject the cookie, and if it is accepted anywhere it is sent cross-site over plaintext connections.
- **Recommendation:** Always pair SameSite=None with Secure, and question whether cross-site delivery is really needed.

```http
Set-Cookie: session=...; Secure; HttpOnly; SameSite=None
```

#### [HIGH] HS-407 — Cookie set over plaintext HTTP (PHPSESSID)

- **Header:** `set-cookie`
- **Observed:** `PHPSESSID=8b1f0c2d9e; Path=/; Domain=localhost`
- **Detail:** Cookie 'PHPSESSID' was set over a plaintext HTTP response.
- **Impact:** The cookie was delivered over an unencrypted channel and can be read by anyone on the path, regardless of its attributes.
- **Recommendation:** Serve the application over HTTPS only and set cookies from HTTPS responses.

```http
Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax
```

#### [HIGH] HS-407 — Cookie set over plaintext HTTP (tracking)

- **Header:** `set-cookie`
- **Observed:** `tracking=1; Path=/; Max-Age=63072000; SameSite=None`
- **Detail:** Cookie 'tracking' was set over a plaintext HTTP response.
- **Impact:** The cookie was delivered over an unencrypted channel and can be read by anyone on the path, regardless of its attributes.
- **Recommendation:** Serve the application over HTTPS only and set cookies from HTTPS responses.

```http
Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax
```

#### [MEDIUM] HS-002 — HSTS max-age is too short

- **Header:** `strict-transport-security`
- **Observed:** `max-age=300`
- **Detail:** max-age is 300 seconds (~0 days); at least 31536000 (1 year) is recommended.
- **Impact:** A short max-age shrinks the window in which the browser enforces HTTPS. Once it expires the next navigation can be downgraded to HTTP again.
- **Recommendation:** Use max-age=31536000 (one year). Ramp up gradually (300 → 86400 → 31536000) if the estate is still being migrated.

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

#### [MEDIUM] HS-102 — CSP allows 'unsafe-eval'

- **Header:** `content-security-policy`
- **Observed:** `script-src: * 'unsafe-inline' 'unsafe-eval' data:`
- **Detail:** script-src allows 'unsafe-eval'.
- **Impact:** 'unsafe-eval' re-enables eval(), new Function() and string timers, giving injected content a direct route from data to executable code.
- **Recommendation:** Remove 'unsafe-eval' and migrate templating/JSON parsing away from eval-based helpers (use JSON.parse and pre-compiled templates).

```http
Content-Security-Policy: script-src 'self' 'nonce-{RANDOM}'
```

#### [MEDIUM] HS-103 — CSP directive uses a wildcard source

- **Header:** `content-security-policy`
- **Observed:** `img-src: *`
- **Detail:** img-src contains the wildcard source '*', allowing resources from any matching origin.
- **Impact:** A wildcard source lets the page load that resource type from any origin, so an attacker-controlled host is an acceptable source as far as the browser is concerned.
- **Recommendation:** Replace '*' with the explicit origins the application actually needs.

```http
Content-Security-Policy: default-src 'self'; img-src 'self' https://cdn.example.com
```

#### [MEDIUM] HS-103 — CSP directive uses a wildcard source

- **Header:** `content-security-policy`
- **Observed:** `style-src: * 'unsafe-inline'`
- **Detail:** style-src contains the wildcard source '*', allowing resources from any matching origin.
- **Impact:** A wildcard source lets the page load that resource type from any origin, so an attacker-controlled host is an acceptable source as far as the browser is concerned.
- **Recommendation:** Replace '*' with the explicit origins the application actually needs.

```http
Content-Security-Policy: default-src 'self'; img-src 'self' https://cdn.example.com
```

#### [MEDIUM] HS-104 — CSP does not restrict object-src

- **Header:** `content-security-policy`
- **Observed:** `default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval' data:; style-src * 'unsafe-inline'; img-src *; frame-ancestors *; report-uri /csp-report`
- **Detail:** object-src (via default-src) is * 'unsafe-inline' 'unsafe-eval' instead of 'none'.
- **Impact:** Plugin content (<object>, <embed>, <applet>) can execute scripts in the page's context and has historically been used to bypass CSP entirely.
- **Recommendation:** Add object-src 'none' — virtually no modern application needs plugin content.

```http
Content-Security-Policy: object-src 'none'
```

#### [MEDIUM] HS-105 — CSP does not restrict base-uri

- **Header:** `content-security-policy`
- **Observed:** `default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval' data:; style-src * 'unsafe-inline'; img-src *; frame-ancestors *; report-uri /csp-report`
- **Detail:** base-uri is not set (it does not fall back to default-src).
- **Impact:** Without base-uri an injected <base> tag can re-point every relative URL on the page (scripts, forms, links) at an attacker-controlled host.
- **Recommendation:** Add base-uri 'self' (or 'none' for pages with no relative-base requirements).

```http
Content-Security-Policy: base-uri 'self'
```

#### [MEDIUM] HS-202 — X-Frame-Options uses obsolete ALLOW-FROM

- **Header:** `x-frame-options`
- **Observed:** `ALLOW-FROM https://partner.example.com`
- **Detail:** ALLOW-FROM is not supported by modern browsers, so the page is effectively unprotected.
- **Impact:** ALLOW-FROM was never implemented by Chrome/Safari and was removed from Firefox, so the directive provides no protection in current browsers.
- **Recommendation:** Replace it with CSP frame-ancestors listing the permitted embedding origins.

```http
Content-Security-Policy: frame-ancestors https://partner.example.com
```

#### [MEDIUM] HS-210 — Missing X-Content-Type-Options

- **Header:** `x-content-type-options`
- **Detail:** X-Content-Type-Options was not returned.
- **Impact:** Without nosniff, browsers may MIME-sniff responses and execute a user-uploaded or text response as script or stylesheet.
- **Recommendation:** Send X-Content-Type-Options: nosniff on every response and make sure Content-Type values are correct.

```http
X-Content-Type-Options: nosniff
```

#### [MEDIUM] HS-221 — Weak Referrer-Policy value

- **Header:** `referrer-policy`
- **Observed:** `unsafe-url`
- **Detail:** Effective policy 'unsafe-url': Sends the full URL (path and query) to every destination, including plaintext HTTP origins.
- **Impact:** This policy sends full URLs (potentially including session identifiers, reset tokens or internal paths) to third parties, and some variants leak over plaintext downgrades.
- **Recommendation:** Switch to strict-origin-when-cross-origin, same-origin or no-referrer.

```http
Referrer-Policy: strict-origin-when-cross-origin
```

#### [MEDIUM] HS-400 — Cookie without Secure attribute (tracking)

- **Header:** `set-cookie`
- **Observed:** `tracking=1; Path=/; Max-Age=63072000; SameSite=None`
- **Detail:** Cookie 'tracking' is missing the Secure attribute.
- **Impact:** The cookie can be transmitted over plaintext HTTP, so an on-path attacker or a single mixed-content request can capture it.
- **Recommendation:** Add the Secure attribute to every cookie and serve the site exclusively over HTTPS.

```http
Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax; Path=/
```

#### [MEDIUM] HS-401 — Cookie without HttpOnly attribute (PHPSESSID)

- **Header:** `set-cookie`
- **Observed:** `PHPSESSID=8b1f0c2d9e; Path=/; Domain=localhost`
- **Detail:** Cookie 'PHPSESSID' is readable by JavaScript (no HttpOnly attribute). The name suggests it carries session state.
- **Impact:** JavaScript can read this cookie, so a single XSS flaw turns into full session theft.
- **Recommendation:** Add HttpOnly to all cookies that do not need to be read by client-side scripts.

```http
Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax; Path=/
```

#### [LOW] HS-003 — HSTS does not cover subdomains

- **Header:** `strict-transport-security`
- **Observed:** `max-age=300`
- **Detail:** The policy does not include subdomains.
- **Impact:** Without includeSubDomains an attacker can target a forgotten subdomain over HTTP and set or read domain-scoped cookies from there.
- **Recommendation:** Add includeSubDomains after verifying that every subdomain (including internal ones) is reachable over HTTPS.

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

#### [LOW] HS-113 — CSP style-src allows 'unsafe-inline'

- **Header:** `content-security-policy`
- **Observed:** `style-src: * 'unsafe-inline'`
- **Detail:** style-src allows 'unsafe-inline' for stylesheets.
- **Impact:** Inline styles enable CSS-based data exfiltration and UI redressing tricks, though the impact is lower than for scripts.
- **Recommendation:** Move inline styles into stylesheets or apply nonces/hashes to style blocks.

```http
Content-Security-Policy: style-src 'self' 'nonce-{RANDOM}'
```

#### [LOW] HS-114 — CSP does not restrict form-action

- **Header:** `content-security-policy`
- **Observed:** `default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval' data:; style-src * 'unsafe-inline'; img-src *; frame-ancestors *; report-uri /csp-report`
- **Detail:** form-action is not set, so form submissions are unrestricted.
- **Impact:** Without form-action an injected or modified form can post user credentials to an attacker-controlled endpoint.
- **Recommendation:** Add form-action 'self' (plus any legitimate payment/SSO endpoints).

```http
Content-Security-Policy: form-action 'self'
```

#### [LOW] HS-230 — Missing Permissions-Policy

- **Header:** `permissions-policy`
- **Detail:** No Permissions-Policy header was returned.
- **Impact:** Powerful browser features (camera, microphone, geolocation, payment) are left at their default availability for the page and for any embedded third-party frames.
- **Recommendation:** Send a deny-by-default Permissions-Policy and only enable what the app needs.

```http
Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()
```

#### [LOW] HS-300 — Missing Cross-Origin-Opener-Policy

- **Header:** `cross-origin-opener-policy`
- **Detail:** No Cross-Origin-Opener-Policy header was returned.
- **Impact:** Without COOP, a window opened by (or opening) this page keeps a cross-origin reference to it, enabling XS-Leaks and tab-nabbing style attacks.
- **Recommendation:** Send Cross-Origin-Opener-Policy: same-origin (use same-origin-allow-popups when OAuth popups are required).

```http
Cross-Origin-Opener-Policy: same-origin
```

#### [LOW] HS-302 — Missing Cross-Origin-Resource-Policy

- **Header:** `cross-origin-resource-policy`
- **Detail:** No Cross-Origin-Resource-Policy header was returned.
- **Impact:** CORP tells the browser who may embed this resource. Without it, responses can be pulled into cross-origin documents and abused for side-channel (Spectre-class) leaks.
- **Recommendation:** Send Cross-Origin-Resource-Policy: same-origin for private resources, same-site for shared internal assets, cross-origin only for public CDN content.

```http
Cross-Origin-Resource-Policy: same-origin
```

#### [LOW] HS-316 — CORS allows unsafe methods broadly

- **Header:** `access-control-allow-methods`
- **Observed:** `GET, POST, PUT, DELETE, TRACE`
- **Detail:** Cross-origin callers may use DELETE, PUT, TRACE.
- **Impact:** Allowing every method (including wildcards or state-changing verbs) from other origins widens the CSRF/abuse surface of the API.
- **Recommendation:** List only the methods the endpoint actually implements.

```http
Access-Control-Allow-Methods: GET, POST, OPTIONS
```

#### [LOW] HS-317 — CORS allows arbitrary request headers

- **Header:** `access-control-allow-headers`
- **Observed:** `*`
- **Detail:** Access-Control-Allow-Headers is '*', allowing any custom request header cross-origin.
- **Impact:** A wildcard header allow-list lets cross-origin callers send custom headers such as Authorization or X-Requested-With, which some backends treat as trusted.
- **Recommendation:** Enumerate the accepted headers explicitly.

```http
Access-Control-Allow-Headers: Content-Type, Authorization
```

#### [LOW] HS-401 — Cookie without HttpOnly attribute (tracking)

- **Header:** `set-cookie`
- **Observed:** `tracking=1; Path=/; Max-Age=63072000; SameSite=None`
- **Detail:** Cookie 'tracking' is readable by JavaScript (no HttpOnly attribute).
- **Impact:** JavaScript can read this cookie, so a single XSS flaw turns into full session theft.
- **Recommendation:** Add HttpOnly to all cookies that do not need to be read by client-side scripts.

```http
Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax; Path=/
```

#### [LOW] HS-402 — Cookie without SameSite attribute (PHPSESSID)

- **Header:** `set-cookie`
- **Observed:** `PHPSESSID=8b1f0c2d9e; Path=/; Domain=localhost`
- **Detail:** Cookie 'PHPSESSID' does not set SameSite explicitly.
- **Impact:** Cross-site requests may carry this cookie depending on the browser's default, which keeps classic CSRF viable on older clients.
- **Recommendation:** Set SameSite=Lax (or Strict for sensitive session cookies) explicitly.

```http
Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax
```

#### [LOW] HS-404 — Cookie scoped to a broad parent domain (PHPSESSID)

- **Header:** `set-cookie`
- **Observed:** `PHPSESSID=8b1f0c2d9e; Path=/; Domain=localhost`
- **Detail:** Cookie 'PHPSESSID' is scoped to the parent domain 'localhost', so every subdomain receives it.
- **Impact:** A cookie scoped to the registrable domain is sent to every subdomain, so a compromised or attacker-controlled subdomain can read or overwrite it.
- **Recommendation:** Drop the Domain attribute to make the cookie host-only, or use the __Host- prefix.

```http
Set-Cookie: __Host-session=...; Secure; HttpOnly; SameSite=Lax; Path=/
```

#### [LOW] HS-500 — Server software version disclosed

- **Header:** `server`
- **Observed:** `HeaderSpecterDemo/1.0, nginx/1.18.0 (Ubuntu)`
- **Detail:** The Server header exposes a specific version: HeaderSpecterDemo/1.0, nginx/1.18.0 (Ubuntu).
- **Impact:** Exact software versions let an attacker map the target to known CVEs without touching the application, speeding up reconnaissance.
- **Recommendation:** Suppress or genericise the Server banner (nginx: server_tokens off; Apache: ServerTokens Prod).

```http
Server: nginx
```

#### [LOW] HS-501 — Technology disclosed via X-Powered-By

- **Header:** `x-powered-by`
- **Observed:** `PHP/7.4.3`
- **Detail:** X-Powered-By discloses: PHP/7.4.3.
- **Impact:** The header advertises the application stack and often its exact version, which is pure reconnaissance value for an attacker.
- **Recommendation:** Remove the header (PHP: expose_php=Off; Express: app.disable('x-powered-by')).

#### [LOW] HS-502 — Framework version headers exposed

- **Header:** `x-aspnet-version`
- **Observed:** `4.0.30319`
- **Detail:** X-AspNet-Version discloses the framework version: 4.0.30319.
- **Impact:** ASP.NET/MVC version headers identify the exact framework build in use.
- **Recommendation:** Remove them via <httpRuntime enableVersionHeader="false" /> and MvcHandler.DisableMvcResponseHeader = true.

#### [LOW] HS-511 — X-XSS-Protection filtering enabled

- **Header:** `x-xss-protection`
- **Observed:** `1; mode=block`
- **Detail:** X-XSS-Protection is set to '1; mode=block'; the legacy auditor is removed from modern browsers and was itself a source of vulnerabilities.
- **Impact:** Value '1' without mode=block enables legacy filtering that was itself exploitable for XS-leaks and content injection in older browsers.
- **Recommendation:** Set X-XSS-Protection: 0 and deploy a CSP instead.

```http
X-XSS-Protection: 0
```

#### [LOW] HS-601 — Potentially sensitive response is cacheable

- **Header:** `cache-control`
- **Observed:** `public, max-age=86400`
- **Detail:** The response sets cookies but does not use Cache-Control: no-store, so a shared cache may store user-specific content.
- **Impact:** The response sets cookies or looks user-specific, yet allows shared/public caching, which can leak one user's content to another via a proxy or CDN.
- **Recommendation:** Send Cache-Control: no-store (plus private where appropriate) for user-specific responses.

```http
Cache-Control: no-store, private
```

#### [INFO] HS-004 — HSTS preload not requested

- **Header:** `strict-transport-security`
- **Observed:** `max-age=300`
- **Detail:** The policy does not request HSTS preloading.
- **Impact:** Without preloading, the very first visit from a fresh browser profile can still be made over HTTP (trust-on-first-use gap).
- **Recommendation:** Once max-age >= 31536000 and includeSubDomains is set, add the preload token and submit the domain at hstspreload.org. Preloading is hard to undo — plan first.

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

#### [INFO] HS-006 — HSTS sent over plaintext HTTP

- **Header:** `strict-transport-security`
- **Observed:** `max-age=300`
- **Detail:** The HSTS header was returned over HTTP, where browsers ignore it.
- **Impact:** HSTS headers received over HTTP are ignored by browsers, so the policy is not actually applied.
- **Recommendation:** Redirect HTTP to HTTPS first and send the HSTS header on the HTTPS response.

#### [INFO] HS-120 — CSP uses deprecated report-uri only

- **Header:** `content-security-policy`
- **Observed:** `/csp-report`
- **Detail:** Only the deprecated report-uri directive is configured.
- **Impact:** report-uri is deprecated in favour of the Reporting API; newer browsers prefer report-to and may drop report-uri support.
- **Recommendation:** Keep report-uri for legacy clients but add report-to with a Reporting-Endpoints header.

```http
Reporting-Endpoints: csp-endpoint="https://example.com/csp-reports"
```

#### [INFO] HS-304 — Missing Cross-Origin-Embedder-Policy

- **Header:** `cross-origin-embedder-policy`
- **Detail:** No Cross-Origin-Embedder-Policy header was returned.
- **Impact:** Without COEP the document cannot become cross-origin isolated, so powerful APIs (SharedArrayBuffer, high-resolution timers) stay disabled and Spectre-class mitigations are weaker.
- **Recommendation:** Send Cross-Origin-Embedder-Policy: require-corp (or credentialless) together with COOP: same-origin when you need cross-origin isolation.

```http
Cross-Origin-Embedder-Policy: require-corp
```

#### [INFO] HS-406 — Long-lived persistent cookie (tracking)

- **Header:** `set-cookie`
- **Observed:** `tracking=1; Path=/; Max-Age=63072000; SameSite=None`
- **Detail:** Cookie 'tracking' persists for roughly 730 days.
- **Impact:** Very long lifetimes extend the window in which a stolen cookie remains valid.
- **Recommendation:** Prefer short-lived session cookies with server-side revocation for authentication state.

#### [INFO] HS-516 — Missing X-Permitted-Cross-Domain-Policies

- **Header:** `x-permitted-cross-domain-policies`
- **Detail:** X-Permitted-Cross-Domain-Policies was not returned.
- **Impact:** Legacy Adobe clients fall back to looking for a /crossdomain.xml policy file.
- **Recommendation:** Send X-Permitted-Cross-Domain-Policies: none (defence in depth, zero cost).

```http
X-Permitted-Cross-Domain-Policies: none
```

### CSP analysis

| Check | Status | Detail |
|---|---|---|
| Enforcement | PASS | Enforcing policy present |
| 'unsafe-inline' (scripts) | HIGH | detected |
| 'unsafe-eval' | MEDIUM | detected |
| 'unsafe-inline' (styles) | LOW | detected |
| Wildcard sources | MEDIUM | default-src, frame-ancestors, img-src, script-src, style-src |
| Dangerous schemes | HIGH | script-src: data: |
| default-src | MEDIUM | * 'unsafe-inline' 'unsafe-eval' — permissive fallback |
| object-src | MEDIUM | not restricted to 'none' |
| base-uri | MEDIUM | missing |
| frame-ancestors | PASS | * |
| form-action | LOW | missing |
| Violation reporting | INFO | report-uri only (deprecated) |
| Allow-list size | PASS | 1 host source(s) |

### Cookies

| Cookie | Secure | HttpOnly | SameSite | Issues |
|---|---|---|---|---|
| `PHPSESSID` | NO | NO | not set | set over HTTP, missing Secure, missing HttpOnly, missing SameSite, broad Domain scope |
| `tracking` | NO | NO | None | set over HTTP, missing Secure, missing HttpOnly, SameSite=None without Secure, long lifetime (~730 days) |

### Recommendations

- Terminate TLS for this host and permanently redirect HTTP to HTTPS.
- Move inline scripts to external files, or adopt a nonce/hash based strict CSP with 'strict-dynamic' for third-party loaders.
- Replace '*' with the explicit origins the application actually needs.
- Remove data:/blob: from script-src and object-src; keep them only for img-src or media where genuinely required.
- Set frame-ancestors 'none' or list the specific origins allowed to embed the page.
- Never combine credentials with a wildcard.
- Add the Secure attribute to every cookie and serve the site exclusively over HTTPS.
- Always pair SameSite=None with Secure, and question whether cross-site delivery is really needed.

<details><summary>Raw headers</summary>

```http
HTTP/1.0 200 OK
server: HeaderSpecterDemo/1.0
date: Fri, 25 Sep 2026 12:09:47 GMT
content-type: text/html; charset=utf-8
content-length: 210
content-security-policy: default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval' data:; style-src * 'unsafe-inline'; img-src *; frame-ancestors *; report-uri /csp-report
strict-transport-security: max-age=300
x-frame-options: ALLOW-FROM https://partner.example.com
x-xss-protection: 1; mode=block
referrer-policy: unsafe-url
access-control-allow-origin: *
access-control-allow-credentials: true
access-control-allow-methods: GET, POST, PUT, DELETE, TRACE
access-control-allow-headers: *
server: nginx/1.18.0 (Ubuntu)
x-powered-by: PHP/7.4.3
x-aspnet-version: 4.0.30319
cache-control: public, max-age=86400
set-cookie: PHPSESSID=8b1f0c2d9e; Path=/; Domain=localhost
set-cookie: tracking=1; Path=/; Max-Age=63072000; SameSite=None
```

</details>


---

Report produced with [HeaderSpecter](https://github.com/mrdineshpathro-dot/HeaderSpecter) — authorised security testing only. Support the author: https://buymeacoffee.com/mrdineshpathro
