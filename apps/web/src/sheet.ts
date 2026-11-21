import { fixesFor, looksLikeSession, parseSetCookie, type CheckId, type HeaderInput, type Report } from "@sentinel/core";
import { DISCLOSURE_NOTE, NOTES } from "./notes";

type Mark = "ok" | "warn" | "fail" | "ins" | "del" | "dim";
interface Line { mark: Mark; key: string; value: string; note?: string; positive?: boolean }

const OWNER: Record<string, CheckId> = {
  "content-security-policy": "csp",
  "content-security-policy-report-only": "csp",
  "strict-transport-security": "hsts",
  "x-frame-options": "framing",
  "x-content-type-options": "content-type-options",
  "referrer-policy": "referrer-policy",
  "permissions-policy": "permissions-policy",
  "feature-policy": "permissions-policy",
  "set-cookie": "cookies",
  "access-control-allow-origin": "cors",
  "access-control-allow-credentials": "cors",
  "cross-origin-opener-policy": "cross-origin-isolation",
  "cross-origin-embedder-policy": "cross-origin-isolation",
  "cross-origin-resource-policy": "cross-origin-isolation",
  "x-xss-protection": "legacy",
  "public-key-pins": "legacy",
  "expect-ct": "legacy",
};

const SR: Record<Mark, string> = { ok: "passes", warn: "needs attention", fail: "fails", ins: "missing, add", del: "remove", dim: "" };
const GUTTER: Record<Mark, string> = { ok: "✓", warn: "~", fail: "✗", ins: "‸", del: "−", dim: "" };

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

function cookieNote(raw: string, https: boolean): { mark: Mark; note?: string } {
  const c = parseSetCookie(raw);
  if (!c) return { mark: "dim" };
  const session = looksLikeSession(c.name);
  const missing: string[] = [];
  if (https && !c.secure) missing.push("Secure");
  if (session && !c.httpOnly) missing.push("HttpOnly");
  if (missing.length) return { mark: session ? "fail" : "warn", note: `Add ${missing.join(" and ")}.` };
  if (!c.sameSite) return { mark: "ok", note: "Set SameSite explicitly." };
  return { mark: "ok" };
}

export function buildLines(report: Report, headers: HeaderInput): Line[] {
  const checks = new Map(report.checks.map((c) => [c.id, c]));
  const https = report.finalUrl.startsWith("https:");
  const lines: Line[] = [];
  const present = new Set<string>();

  for (const [rawKey, rawVal] of Object.entries(headers)) {
    const key = rawKey.toLowerCase();
    present.add(key);
    for (const value of [rawVal ?? ""].flat()) {
      const disclosure = checks.get("disclosure")?.findings.find((f) => f.evidence?.toLowerCase().startsWith(`${key}:`));
      if (disclosure) {
        lines.push({ mark: "del", key, value, note: DISCLOSURE_NOTE });
        continue;
      }
      if (key === "set-cookie") {
        lines.push({ key, value, ...cookieNote(value, https) });
        continue;
      }
      const owner = OWNER[key];
      const check = owner && checks.get(owner);
      if (!check) {
        lines.push({ mark: "dim", key, value });
        continue;
      }
      if (owner === "legacy") {
        const f = check.findings.find((x) => x.evidence === value);
        lines.push(f ? { mark: "del", key, value, note: NOTES[f.id] } : { mark: "ok", key, value });
        continue;
      }
      if (key === "content-security-policy-report-only" && checks.get("csp")?.status !== "fail") {
        lines.push({ mark: "dim", key, value });
        continue;
      }
      const problem = check.findings.find((f) => f.modifier < 0);
      const bonus = check.findings.find((f) => f.modifier > 0);
      const mark: Mark = check.status === "pass" || check.status === "info" ? "ok" : check.status;
      const note = problem ? NOTES[problem.id] : bonus ? NOTES[bonus.id] : undefined;
      lines.push({ mark, key, value, note, positive: !problem && !!bonus });
    }
  }

  for (const fix of fixesFor(report)) {
    const key = fix.header.toLowerCase();
    if (present.has(key)) continue;
    const owner = OWNER[key] ?? (key === "x-frame-options" ? "framing" : undefined);
    const check = owner ? checks.get(owner) : undefined;
    const f = check?.findings.find((x) => x.modifier < 0) ?? check?.findings[0];
    lines.push({ mark: "ins", key, value: fix.value, note: f ? NOTES[f.id] : undefined });
  }
  return lines;
}

const clip = (s: string, n = 160) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

export function renderSheet(el: HTMLElement, report: Report, headers: HeaderInput, status?: number) {
  const lines = buildLines(report, headers);
  const http = !report.finalUrl.startsWith("https:");
  let i = 0;
  const rows = lines.map((l) => {
    // Stagger index goes in a data attribute: the site's CSP forbids inline style attributes.
    const delay = l.mark === "dim" ? "" : ` data-i="${i++}"`;
    return `<li class="ln ln-${l.mark}"${delay}>
      <span class="gut" aria-hidden="true">${GUTTER[l.mark]}</span>
      <code class="hdr"${l.value.length > 160 ? ` title="${esc(l.value)}"` : ""}>${SR[l.mark] ? `<span class="visually-hidden">${SR[l.mark]}: </span>` : ""}<span class="k">${esc(l.key)}</span><span class="p">: </span><span class="v">${esc(clip(l.value))}</span></code>
      ${l.note ? `<span class="note${l.positive ? " note-good" : ""}">${esc(l.note)}</span>` : ""}
    </li>`;
  }).join("");

  const statusText = status ? `${status}` : "";
  el.innerHTML = `
    <div class="sheet-head">
      <code><span class="verb">GET</span> ${esc(report.finalUrl)}</code>
      ${statusText ? `<code class="status">HTTP ${esc(statusText)}</code>` : ""}
      ${http ? `<span class="note head-note">Not HTTPS. Anyone on the network can read this.</span>` : ""}
    </div>
    ${report.redirects.length ? `<p class="redirects">Redirected ${report.redirects.length}× from ${esc(report.redirects[0]!.url)}</p>` : ""}
    <ol class="lines">${rows}</ol>
    <div class="stamp stamp-${report.grade[0]!.toLowerCase()}" role="img" aria-label="Grade ${esc(report.grade)}, ${report.score} out of 100">
      <span class="stamp-grade">${esc(report.grade)}</span>
      <span class="stamp-score">${report.score}/100</span>
    </div>`;

  // CSSOM writes are allowed under style-src 'self'; parsed style="" attributes are not.
  el.querySelectorAll<HTMLElement>("[data-i]").forEach((n) => n.style.setProperty("--i", n.dataset.i!));

  // Replay the markup animation: commit the undrawn state, then draw.
  el.classList.remove("drawn");
  void el.offsetWidth;
  el.classList.add("drawn");
}
