import { analyzeScripts, effectiveSources, parseHeader, type ParsedPolicy } from "../csp.js";
import type { Finding } from "../types.js";
import { type Check, result } from "./context.js";

/** Script-execution findings for one policy. Exported for tests. */
export function scriptFindings(p: ParsedPolicy): Finding[] {
  const f: Finding[] = [];
  const s = analyzeScripts(p.directives);
  if (!s) {
    f.push({
      id: "csp.no-script-restriction",
      severity: "high",
      message: "The policy has no script-src or default-src, so it doesn't restrict where scripts load from.",
      modifier: -20,
    });
    return f;
  }
  const ev = `${s.from} ${s.sources.join(" ")}`;
  if (s.unsafeInline) {
    f.push({
      id: "csp.unsafe-inline",
      severity: "high",
      message: "'unsafe-inline' lets injected <script> tags and event handlers run, which cancels most of CSP's XSS protection.",
      modifier: -20,
      evidence: ev,
    });
  }
  if (s.wildcard) {
    f.push({
      id: "csp.wildcard",
      severity: "high",
      message: "A bare * allows scripts from any host on the internet.",
      modifier: -20,
      evidence: ev,
    });
  }
  if (s.broadSchemes.length) {
    f.push({
      id: "csp.broad-scheme",
      severity: "high",
      message: `${s.broadSchemes.join(", ")} allows scripts from any URL with that scheme${s.broadSchemes.includes("data:") ? " — data: lets an attacker inline a whole script" : ""}.`,
      modifier: -15,
      evidence: ev,
    });
  }
  if (s.unsafeEval) {
    f.push({
      id: "csp.unsafe-eval",
      severity: "medium",
      message: "'unsafe-eval' allows eval() and new Function(), turning string injection into code execution.",
      modifier: -10,
      evidence: ev,
    });
  }
  if (s.bypassHosts.length) {
    f.push({
      id: "csp.bypassable-host",
      severity: "medium",
      message: `${s.bypassHosts.join(", ")} hosts JSONP or user-uploaded files that can be used to run attacker script past the allowlist.`,
      modifier: -5,
      evidence: ev,
    });
  }
  if (s.hasNonceOrHash && s.strictDynamic && !s.unsafeEval) {
    f.push({
      id: "csp.strict",
      severity: "info",
      message: "Uses nonces or hashes with 'strict-dynamic' — the setup Google and OWASP recommend.",
      modifier: 5,
    });
  }
  return f;
}

const penalty = (fs: Finding[]) => fs.reduce((n, x) => n + Math.min(0, x.modifier), 0);

export const csp: Check = ({ headers }) => {
  const base = {
    id: "csp" as const,
    title: "Content-Security-Policy",
    headers: ["content-security-policy", "content-security-policy-report-only"],
    defends: "Cross-site scripting (XSS) and data injection",
    floor: -25,
  };
  const enforced = headers.all("content-security-policy");
  const reportOnly = headers.joined("content-security-policy-report-only");

  if (!enforced.length) {
    const f: Finding[] = [reportOnly
      ? {
          id: "csp.report-only",
          severity: "high",
          message: "Only a Report-Only policy is set: violations are logged but nothing is blocked.",
          modifier: -25,
          evidence: reportOnly,
        }
      : {
          id: "csp.missing",
          severity: "high",
          message: "No Content-Security-Policy, so any script an attacker manages to inject will run.",
          modifier: -25,
        }];
    return result({ ...base, summary: reportOnly ? "Report-only — nothing is enforced" : "Missing", status: "fail", value: reportOnly }, f);
  }

  const value = enforced.join(", ");
  const policies = enforced.flatMap(parseHeader);
  const f: Finding[] = [];

  // Every policy is enforced, so the strictest one decides what scripts can run.
  const perPolicy = policies.map(scriptFindings);
  const best = perPolicy.reduce((a, b) => (penalty(b) > penalty(a) ? b : a), perPolicy[0] ?? []);
  f.push(...best);

  const objectOk = policies.some((p) => {
    const o = effectiveSources(p.directives, "object-src");
    return o !== null && o.sources.length === 1 && o.sources[0]!.toLowerCase() === "'none'";
  });
  if (!objectOk) {
    f.push({
      id: "csp.object-src",
      severity: "medium",
      message: "object-src isn't 'none', so plugin content (<object>, <embed>) can be used to run script.",
      modifier: -5,
    });
  }

  if (!policies.some((p) => p.directives.has("base-uri"))) {
    f.push({
      id: "csp.base-uri",
      severity: "low",
      message: "No base-uri, so an injected <base> tag can point relative script URLs at an attacker's server.",
      modifier: -2,
    });
  }

  for (const p of policies) {
    for (const name of p.unknown) {
      f.push({ id: "csp.unknown-directive", severity: "info", message: `"${name}" isn't a CSP directive — browsers ignore it. Typo?`, modifier: 0, evidence: name });
    }
    for (const name of p.duplicates) {
      f.push({ id: "csp.duplicate-directive", severity: "info", message: `"${name}" appears twice; browsers ignore every copy after the first.`, modifier: 0, evidence: name });
    }
  }

  const blocking = f.filter((x) => x.modifier < 0 && (x.severity === "high" || x.severity === "critical"));
  const summary = blocking.length
    ? "Set, but scripts can still be injected"
    : f.some((x) => x.id === "csp.strict")
      ? "Strict, nonce-based policy"
      : f.some((x) => x.modifier < 0)
        ? "Set, with gaps"
        : "Restricts script sources";
  return result({ ...base, summary, value }, f);
};
