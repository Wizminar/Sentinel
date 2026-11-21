import type { Finding } from "../types.js";
import { type Check, isHttps, result } from "./context.js";

export interface ParsedCookie {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: "strict" | "lax" | "none" | string;
  domain?: string;
  path?: string;
  raw: string;
}

export function parseSetCookie(raw: string): ParsedCookie | null {
  const [pair, ...attrs] = raw.split(";");
  const eq = pair?.indexOf("=") ?? -1;
  const name = (eq > 0 ? pair!.slice(0, eq) : pair ?? "").trim();
  if (!name) return null;
  const c: ParsedCookie = { name, secure: false, httpOnly: false, raw };
  for (const a of attrs) {
    const [k = "", ...rest] = a.split("=");
    const key = k.trim().toLowerCase();
    const val = rest.join("=").trim();
    if (key === "secure") c.secure = true;
    else if (key === "httponly") c.httpOnly = true;
    else if (key === "samesite") c.sameSite = val.toLowerCase();
    else if (key === "domain") c.domain = val;
    else if (key === "path") c.path = val;
  }
  return c;
}

/** Names that usually carry a login session. CSRF tokens are left out: they are often read by JS on purpose. */
const SESSION = /(^|[_.-])(sess(ion)?|sid|auth|token|jwt|login|remember)([_.-]|$)|^(phpsessid|jsessionid|asp\.net_sessionid|connect\.sid|laravel_session|_session_id|session)$/i;
export const looksLikeSession = (name: string) => SESSION.test(name);

const list = (names: string[]) => names.length > 3 ? `${names.slice(0, 3).join(", ")} and ${names.length - 3} more` : names.join(", ");

export const cookies: Check = ({ headers, url }) => {
  const base = {
    id: "cookies" as const,
    title: "Cookies",
    headers: ["set-cookie"],
    defends: "Session theft and cross-site request forgery",
    floor: -40,
  };
  const parsed = headers.all("set-cookie").map(parseSetCookie).filter((c): c is ParsedCookie => c !== null);
  if (!parsed.length) {
    return result({ ...base, summary: "No cookies set on this response", status: "info" }, []);
  }

  const f: Finding[] = [];
  const https = isHttps(url);
  const noSecure = parsed.filter((c) => !c.secure);
  const sessionNoSecure = noSecure.filter((c) => looksLikeSession(c.name));
  if (https && sessionNoSecure.length) {
    f.push({ id: "cookies.session-no-secure", severity: "high", message: `${list(sessionNoSecure.map((c) => c.name))} look${sessionNoSecure.length === 1 ? "s" : ""} like session cookies but lack Secure, so they can leak over any HTTP request.`, modifier: -20 });
  } else if (https && noSecure.length) {
    f.push({ id: "cookies.no-secure", severity: "medium", message: `${list(noSecure.map((c) => c.name))} lack${noSecure.length === 1 ? "s" : ""} the Secure flag and can be sent over plain HTTP.`, modifier: -10 });
  }

  const sessionNoHttpOnly = parsed.filter((c) => looksLikeSession(c.name) && !c.httpOnly);
  if (sessionNoHttpOnly.length) {
    f.push({ id: "cookies.session-no-httponly", severity: "high", message: `${list(sessionNoHttpOnly.map((c) => c.name))} can be read by JavaScript, so a single XSS bug can steal the session. Add HttpOnly.`, modifier: -10 });
  }

  const noneNoSecure = parsed.filter((c) => c.sameSite === "none" && !c.secure);
  if (noneNoSecure.length) {
    f.push({ id: "cookies.samesite-none-insecure", severity: "medium", message: `${list(noneNoSecure.map((c) => c.name))} use SameSite=None without Secure, so browsers reject them.`, modifier: -5 });
  }

  const prefixBad = parsed.filter((c) =>
    (c.name.startsWith("__Host-") && (!c.secure || c.domain !== undefined || c.path !== "/")) ||
    (c.name.startsWith("__Secure-") && !c.secure));
  if (prefixBad.length) {
    f.push({ id: "cookies.prefix", severity: "medium", message: `${list(prefixBad.map((c) => c.name))} break the rules of their __Host-/__Secure- prefix, so browsers drop them.`, modifier: -5 });
  }

  const noSameSite = parsed.filter((c) => c.sameSite === undefined);
  if (noSameSite.length) {
    f.push({ id: "cookies.no-samesite", severity: "info", message: `${list(noSameSite.map((c) => c.name))} rely on the browser default (Lax). Set SameSite explicitly.`, modifier: 0 });
  }

  const bad = f.filter((x) => x.modifier < 0).length;
  const summary = bad ? `${parsed.length} cookie${parsed.length === 1 ? "" : "s"}, ${bad} issue${bad === 1 ? "" : "s"}` : `${parsed.length} cookie${parsed.length === 1 ? "" : "s"}, all flagged correctly`;
  return result({ ...base, summary, value: parsed.map((c) => c.raw).join("\n") }, f);
};
