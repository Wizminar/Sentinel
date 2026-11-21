import { parseHeader } from "../csp.js";
import type { Finding } from "../types.js";
import { type Check, result } from "./context.js";

export const framing: Check = ({ headers }) => {
  const base = {
    id: "framing" as const,
    title: "Frame protection",
    headers: ["x-frame-options", "content-security-policy"],
    defends: "Clickjacking through hidden iframes",
  };
  const xfo = headers.first("x-frame-options");
  const csp = headers.joined("content-security-policy");
  const ancestors = csp
    ? parseHeader(csp).map((p) => p.directives.get("frame-ancestors")).find((d) => d !== undefined)
    : undefined;

  if (ancestors) {
    const value = `frame-ancestors ${ancestors.join(" ")}`;
    const open = ancestors.some((s) => s === "*" || /^https?:$/i.test(s));
    const f: Finding[] = open
      ? [{ id: "framing.ancestors-open", severity: "high", message: "frame-ancestors allows any site to embed this page.", modifier: -20, evidence: value }]
      : [];
    if (xfo && !open) {
      f.push({ id: "framing.both", severity: "info", message: "X-Frame-Options is also set. Modern browsers use frame-ancestors and ignore it; keeping both covers old browsers.", modifier: 0 });
    }
    return result({ ...base, summary: open ? "Any site can frame this page" : "Restricted by CSP frame-ancestors", value }, f);
  }

  if (!xfo) {
    return result({ ...base, summary: "Missing", status: "fail" }, [
      { id: "framing.missing", severity: "high", message: "Any site can load this page in an invisible iframe and trick users into clicking it.", modifier: -20 },
    ]);
  }
  const v = xfo.trim().toLowerCase();
  if (v === "deny" || v === "sameorigin") {
    return result({ ...base, summary: v === "deny" ? "Framing denied" : "Same-origin framing only", value: xfo }, []);
  }
  const f: Finding = v.startsWith("allow-from")
    ? { id: "framing.allow-from", severity: "high", message: "ALLOW-FROM is obsolete and every current browser ignores it, so the page can be framed anywhere. Use CSP frame-ancestors.", modifier: -20, evidence: xfo }
    : { id: "framing.invalid", severity: "high", message: `"${xfo}" isn't a valid X-Frame-Options value, so browsers ignore it.`, modifier: -20, evidence: xfo };
  return result({ ...base, summary: "Set, but ignored by browsers", value: xfo }, [f]);
};
