import type { CheckId, Report } from "./types.js";

export type Platform = "nginx" | "apache" | "caddy" | "express" | "netlify" | "cloudflare" | "vercel";

export const PLATFORMS: { id: Platform; label: string }[] = [
  { id: "nginx", label: "nginx" },
  { id: "apache", label: "Apache" },
  { id: "caddy", label: "Caddy" },
  { id: "express", label: "Express" },
  { id: "vercel", label: "Vercel" },
  { id: "netlify", label: "Netlify" },
  { id: "cloudflare", label: "Cloudflare Pages" },
];

export interface HeaderFix {
  header: string;
  value: string;
  note?: string;
}

/** Safe starting values. CSP needs tuning per site, so it ships with a note. */
export const RECOMMENDED: Partial<Record<CheckId, HeaderFix[]>> = {
  csp: [{
    header: "Content-Security-Policy",
    value: "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'; upgrade-insecure-requests",
    note: "Start in Content-Security-Policy-Report-Only, watch for violations, then enforce. For inline scripts, switch to nonces with 'strict-dynamic'.",
  }],
  hsts: [{ header: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains", note: "Add '; preload' and submit to hstspreload.org once every subdomain is on HTTPS." }],
  framing: [{ header: "X-Frame-Options", value: "DENY", note: "Also covered by CSP frame-ancestors, which modern browsers prefer." }],
  "content-type-options": [{ header: "X-Content-Type-Options", value: "nosniff" }],
  "referrer-policy": [{ header: "Referrer-Policy", value: "strict-origin-when-cross-origin" }],
  "permissions-policy": [{ header: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()" }],
  "cross-origin-isolation": [{ header: "Cross-Origin-Opener-Policy", value: "same-origin", note: "Use same-origin-allow-popups if you rely on OAuth or payment popups." }],
  legacy: [{ header: "X-XSS-Protection", value: "0" }],
};

/** Headers to add or replace for every check that didn't pass. */
export function fixesFor(report: Report): HeaderFix[] {
  const out: HeaderFix[] = [];
  for (const c of report.checks) {
    if (c.status === "pass") continue;
    if (c.id === "cross-origin-isolation" && c.status !== "info") continue;
    if (c.id === "legacy" && !c.findings.some((f) => f.id === "legacy.xss-protection")) continue;
    out.push(...(RECOMMENDED[c.id] ?? []));
  }
  return out;
}

const q = (s: string) => s.replace(/"/g, '\\"');

/** Render header fixes as a ready-to-paste config block for one platform. */
export function renderConfig(platform: Platform, fixes: HeaderFix[]): string {
  if (!fixes.length) return "# Nothing to add — every header check passed.";
  switch (platform) {
    case "nginx":
      return ["# inside your server { } block", ...fixes.map((f) => `add_header ${f.header} "${q(f.value)}" always;`)].join("\n");
    case "apache":
      return ["# .htaccess or <VirtualHost> (needs mod_headers)", ...fixes.map((f) => `Header always set ${f.header} "${q(f.value)}"`)].join("\n");
    case "caddy":
      return ["header {", ...fixes.map((f) => `\t${f.header} "${q(f.value)}"`), "}"].join("\n");
    case "express":
      return [
        "app.use((req, res, next) => {",
        ...fixes.map((f) => `  res.setHeader("${f.header}", "${q(f.value)}");`),
        "  next();",
        "});",
        'app.disable("x-powered-by");',
      ].join("\n");
    case "netlify":
    case "cloudflare":
      return ["# _headers", "/*", ...fixes.map((f) => `  ${f.header}: ${f.value}`)].join("\n");
    case "vercel":
      return JSON.stringify({
        headers: [{ source: "/(.*)", headers: fixes.map((f) => ({ key: f.header, value: f.value })) }],
      }, null, 2);
  }
}
