import type { Finding } from "../types.js";
import { type Check, result } from "./context.js";

export const cors: Check = ({ headers, probeOrigin }) => {
  const base = {
    id: "cors" as const,
    title: "CORS",
    headers: ["access-control-allow-origin", "access-control-allow-credentials"],
    defends: "Other sites reading your users' data",
  };
  const acao = headers.first("access-control-allow-origin")?.trim();
  const creds = headers.first("access-control-allow-credentials")?.trim().toLowerCase() === "true";
  if (!acao) {
    return result({ ...base, summary: "No cross-origin reads allowed" }, []);
  }
  const value = `${acao}${creds ? " (with credentials)" : ""}`;
  const f: Finding[] = [];

  if (probeOrigin && acao === probeOrigin) {
    f.push(creds
      ? { id: "cors.reflect-credentials", severity: "critical", message: "The server echoes back any Origin and allows credentials, so any website can read logged-in users' responses.", modifier: -40, evidence: value }
      : { id: "cors.reflect", severity: "high", message: "The server echoes back whatever Origin it receives, so every website is allowed to read this response.", modifier: -15, evidence: value });
  } else if (acao === "null") {
    f.push({ id: "cors.null", severity: "high", message: "Allowing the \"null\" origin lets sandboxed iframes and data: URLs — which attackers control — read the response.", modifier: -15, evidence: value });
  } else if (acao === "*") {
    f.push(creds
      ? { id: "cors.wildcard-credentials", severity: "low", message: "* combined with credentials is rejected by browsers; this often means origin handling is broken elsewhere.", modifier: -2, evidence: value }
      : { id: "cors.wildcard", severity: "info", message: "Any site can read this response. Fine for public content; never for pages that show user data.", modifier: 0, evidence: value });
  }
  const summary = f[0]?.severity === "critical" || f[0]?.severity === "high" ? "Any origin can read responses" : acao === "*" ? "Public (*)" : `Allows ${acao}`;
  return result({ ...base, summary, value, status: f.length && f[0]!.severity === "info" ? "info" : undefined }, f);
};
