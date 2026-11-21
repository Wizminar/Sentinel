import { type Check, isHttps, result } from "./context.js";
import type { Finding } from "../types.js";

export const transport: Check = ({ url, requested, redirects }) => {
  const f: Finding[] = [];
  const base = {
    id: "transport" as const,
    title: "HTTPS",
    headers: ["location"],
    defends: "Eavesdropping and tampering in transit",
  };

  if (!isHttps(url)) {
    f.push({
      id: "transport.plain-http",
      severity: "critical",
      message: "The page is served over plain HTTP, so anyone on the network can read or change it.",
      modifier: -40,
    });
    return result({ ...base, summary: "Served over plain HTTP", status: "fail" }, f);
  }

  const hops = redirects.map((r) => {
    try { return new URL(r.url); } catch { return null; }
  }).filter((u): u is URL => u !== null);
  const chain = [...hops, url];

  for (let i = 1; i < chain.length; i++) {
    const prev = chain[i - 1]!, next = chain[i]!;
    if (isHttps(prev) && !isHttps(next)) {
      f.push({
        id: "transport.downgrade",
        severity: "high",
        message: `A redirect drops from HTTPS to HTTP (${prev.host} → ${next.host}).`,
        modifier: -20,
        evidence: next.href,
      });
      break;
    }
  }

  if (!isHttps(requested)) {
    const first = chain[1] ?? url;
    if (first.host !== requested.host) {
      f.push({
        id: "transport.redirect-host",
        severity: "low",
        message: `The first redirect from http://${requested.host} goes to a different host, so that host never receives an HSTS header over HTTPS.`,
        modifier: -5,
        evidence: first.href,
      });
    }
  }

  const summary = !isHttps(requested) ? "Redirects HTTP to HTTPS" : "Served over HTTPS";
  return result({ ...base, summary }, f);
};
