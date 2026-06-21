# HTTP Security Headers Analyzer

A lightweight, single-page web tool to check whether a website is sending the baseline HTTP security headers — and what each one actually does, in plain English.

**Live demo:** [add your URL]

## Why this matters

HTTP security headers are the cheapest defense a web server has. They tell the *browser* — which the server doesn't control — how to behave when handling the page: which scripts to trust, whether to allow framing, whether to force HTTPS, and so on. Misconfigured or missing headers are one of the most common findings in real-world web audits, because they're invisible to users and easy for developers to overlook.

This tool checks the six headers I treat as the baseline for any production site:

| Header | What it defends against |
|---|---|
| `Content-Security-Policy` | Cross-site scripting (XSS) by restricting where scripts can come from |
| `Strict-Transport-Security` | HTTPS downgrade and man-in-the-middle attacks |
| `X-Frame-Options` | Clickjacking via hidden iframes |
| `X-Content-Type-Options` | MIME-type sniffing attacks |
| `Referrer-Policy` | Leaking sensitive URLs to third parties |
| `Permissions-Policy` | Unauthorized use of camera, mic, geolocation, etc. |

Each header gets one of three statuses: **Present** (good), **Weak** (set but with risky values, e.g. CSP with `unsafe-inline`), or **Missing**. The site gets a letter grade based on the count.

## How it works

Plain HTML + CSS + JavaScript, single file, no build step. Drop it on any static host.

The browser blocks reading cross-origin response headers directly (this is the same-origin policy — itself a security control), so the request is routed through a public CORS proxy. The tool then parses the response headers and evaluates each one against the rules in the script.

## Known limitations (honest list)

Security tools should be transparent about what they don't check, because false confidence is worse than no check:

- **Routes through a third-party proxy.** Don't analyze sensitive URLs with the live demo — the proxy sees the request. A production version would use a self-hosted backend.
- **Snapshot only.** Headers can vary by route, method, or auth state. The tool checks one URL with a GET request.
- **Doesn't catch everything.** Real audits also evaluate CSP nonce/hash strategy, HSTS preload-list eligibility, COOP/COEP, cookie flags (`Secure`, `HttpOnly`, `SameSite`), and TLS configuration. This tool is a starting point, not a substitute.

## Local use

Clone or download, open `headers-analyzer.html` in a browser. No install, no dependencies.

## Roadmap

- Self-hosted fetch backend (kill the proxy dependency)
- Cookie flag analysis
- COOP / COEP / CORP checks
- Export results to JSON or markdown report

## Author

Built as part of my move from web development into security. Web developers ship the apps; security folks find the gaps. Building tools like this is how I'm closing the loop between the two.
