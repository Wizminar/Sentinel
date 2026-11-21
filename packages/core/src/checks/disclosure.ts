import type { Finding } from "../types.js";
import { type Check, result } from "./context.js";

const LEAKY = ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-runtime", "x-drupal-cache", "x-varnish-version"];

export const disclosure: Check = ({ headers }) => {
  const base = {
    id: "disclosure" as const,
    title: "Information disclosure",
    headers: ["server", ...LEAKY],
    defends: "Attackers matching your stack to known CVEs",
    floor: -5,
  };
  const f: Finding[] = [];
  const server = headers.first("server");
  if (server && /\d+(\.\d+)+/.test(server)) {
    f.push({ id: "disclosure.server-version", severity: "low", message: `The Server header reveals an exact version (${server}), which makes it easy to look up known vulnerabilities.`, modifier: -2, evidence: `server: ${server}` });
  }
  for (const h of LEAKY) {
    const v = headers.first(h);
    if (v) f.push({ id: `disclosure.${h}`, severity: "low", message: `${h} announces the software behind the site (${v}). Remove it.`, modifier: -2, evidence: `${h}: ${v}` });
  }
  const value = f.map((x) => x.evidence).join("\n") || undefined;
  return result({ ...base, summary: f.length ? `${f.length} header${f.length === 1 ? "" : "s"} reveal the stack` : "No software versions exposed", value }, f);
};
