import type { Finding } from "../types.js";
import { type Check, result } from "./context.js";

export const crossOriginIsolation: Check = ({ headers }) => {
  const base = {
    id: "cross-origin-isolation" as const,
    title: "Cross-origin isolation",
    headers: ["cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy"],
    defends: "Cross-site leaks and Spectre-style side channels",
  };
  const coop = headers.first("cross-origin-opener-policy")?.toLowerCase().split(";")[0]?.trim();
  const coep = headers.first("cross-origin-embedder-policy")?.toLowerCase().split(";")[0]?.trim();
  const corp = headers.first("cross-origin-resource-policy")?.toLowerCase().trim();
  const value = [
    coop && `COOP: ${coop}`,
    coep && `COEP: ${coep}`,
    corp && `CORP: ${corp}`,
  ].filter(Boolean).join("\n") || undefined;
  const f: Finding[] = [];

  if (coop === "same-origin" || coop === "same-origin-allow-popups" || coop === "noopener-allow-popups") {
    f.push({ id: "isolation.coop", severity: "info", message: `COOP ${coop} cuts the link between this page and windows it didn't open.`, modifier: 5 });
  } else {
    f.push({ id: "isolation.no-coop", severity: "info", message: "Without Cross-Origin-Opener-Policy, a site that opens yours in a popup keeps a handle to it (cross-site leaks, tab-nabbing).", modifier: 0 });
  }
  const isolated = coop === "same-origin" && (coep === "require-corp" || coep === "credentialless");
  if (isolated) {
    f.push({ id: "isolation.full", severity: "info", message: "The page is cross-origin isolated, which also unlocks SharedArrayBuffer and precise timers.", modifier: 0 });
  }
  const summary = isolated ? "Fully cross-origin isolated" : coop && coop !== "unsafe-none" ? `COOP ${coop}` : "Not configured";
  return result({ ...base, summary, value, status: coop && coop !== "unsafe-none" ? "pass" : "info" }, f);
};
