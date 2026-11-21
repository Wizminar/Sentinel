import type { Finding } from "../types.js";
import { type Check, isHttps, result } from "./context.js";

const SIX_MONTHS = 15552000;
const ONE_YEAR = 31536000;

export const hsts: Check = ({ headers, url }) => {
  const base = {
    id: "hsts" as const,
    title: "Strict-Transport-Security",
    headers: ["strict-transport-security"],
    defends: "HTTPS downgrade and SSL-stripping attacks",
  };
  if (!isHttps(url)) {
    return result({ ...base, summary: "Not applicable over plain HTTP", status: "info" }, [
      { id: "hsts.not-applicable", severity: "info", message: "Browsers ignore HSTS on plain-HTTP responses. Serve the site over HTTPS first.", modifier: 0 },
    ]);
  }
  const all = headers.all("strict-transport-security");
  const value = all[0];
  if (!value) {
    return result({ ...base, summary: "Missing", status: "fail" }, [
      { id: "hsts.missing", severity: "high", message: "Without HSTS, a first visit over http:// can be intercepted and kept on plain HTTP by an attacker.", modifier: -20 },
    ]);
  }

  const parts = value.split(";").map((p) => p.trim().toLowerCase()).filter(Boolean);
  const maxAgePart = parts.find((p) => p.startsWith("max-age"));
  const m = maxAgePart ? /^max-age\s*=\s*"?(\d+)"?$/.exec(maxAgePart) : null;
  const subdomains = parts.includes("includesubdomains");
  const preload = parts.includes("preload");
  const f: Finding[] = [];

  if (!m) {
    f.push({ id: "hsts.invalid", severity: "high", message: "The header has no valid max-age, so browsers ignore it.", modifier: -20, evidence: value });
    return result({ ...base, summary: "Invalid", value }, f);
  }
  const age = Number(m[1]);
  const days = Math.round(age / 86400);
  if (age === 0) {
    f.push({ id: "hsts.zero", severity: "high", message: "max-age=0 tells browsers to forget the HSTS policy.", modifier: -20, evidence: value });
  } else if (age < SIX_MONTHS) {
    f.push({ id: "hsts.short", severity: "medium", message: `max-age is ${days} day${days === 1 ? "" : "s"}. Use at least 180 days; one year is the norm.`, modifier: -10, evidence: value });
  }
  if (!subdomains) {
    f.push({ id: "hsts.no-subdomains", severity: "info", message: "Subdomains aren't covered. Add includeSubDomains once every subdomain serves HTTPS.", modifier: 0 });
  }
  if (preload && subdomains && age >= ONE_YEAR) {
    f.push({ id: "hsts.preload-ready", severity: "info", message: "Meets the requirements for the browser HSTS preload list.", modifier: 5 });
  }
  if (all.length > 1) {
    f.push({ id: "hsts.duplicate", severity: "info", message: `Sent ${all.length} times; browsers only use the first.`, modifier: 0 });
  }
  const summary = age === 0 ? "Disabled (max-age=0)" : age < SIX_MONTHS ? `Set, but only ${days} days` : preload && subdomains ? "Long-lived and preload-ready" : `Enforced for ${days} days`;
  return result({ ...base, summary, value }, f);
};
