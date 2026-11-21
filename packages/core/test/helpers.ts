import { analyze, type AnalyzeInput, type CheckId, type HeaderInput } from "../src/index.js";

export const STRONG: HeaderInput = {
  "content-security-policy": "default-src 'self'; script-src 'nonce-r4nd0m' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
  "cross-origin-opener-policy": "same-origin",
  "set-cookie": ["__Host-session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"],
};

export function scan(headers: HeaderInput, extra: Partial<AnalyzeInput> = {}) {
  return analyze({ url: "https://example.com/", headers, now: new Date("2026-01-01T00:00:00Z"), ...extra });
}

export function check(headers: HeaderInput, id: CheckId, extra: Partial<AnalyzeInput> = {}) {
  const c = scan(headers, extra).checks.find((x) => x.id === id);
  if (!c) throw new Error(`no check ${id}`);
  return c;
}

export const ids = (c: { findings: { id: string }[] }) => c.findings.map((f) => f.id);
