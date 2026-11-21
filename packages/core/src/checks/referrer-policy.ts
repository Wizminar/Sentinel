import type { Finding } from "../types.js";
import { type Check, result } from "./context.js";

const VALID = new Set([
  "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
  "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url",
]);
const STRICT = new Set(["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"]);

export const referrerPolicy: Check = ({ headers }) => {
  const base = {
    id: "referrer-policy" as const,
    title: "Referrer-Policy",
    headers: ["referrer-policy"],
    defends: "Leaking private URLs to other sites",
  };
  const value = headers.joined("referrer-policy");
  // Browsers walk the list and use the last token they understand.
  const effective = value
    ?.split(",")
    .map((t) => t.trim().toLowerCase())
    .filter((t) => VALID.has(t))
    .pop();

  if (!effective) {
    return result({ ...base, summary: value ? "Unrecognised value" : "Not set — browser default applies", status: "info", value }, [
      { id: "referrer.missing", severity: "info", message: "Modern browsers default to strict-origin-when-cross-origin, which is safe. Set it explicitly so older browsers behave the same.", modifier: 0 },
    ]);
  }
  const f: Finding[] = [];
  if (effective === "unsafe-url") {
    f.push({ id: "referrer.unsafe-url", severity: "medium", message: "unsafe-url sends the full URL — path and query string included — to every site you link to, even over HTTP.", modifier: -5, evidence: effective });
  } else if (effective === "no-referrer-when-downgrade") {
    f.push({ id: "referrer.downgrade", severity: "low", message: "Full URLs, including any tokens in the query string, are sent to every other HTTPS site.", modifier: -3, evidence: effective });
  } else if (STRICT.has(effective)) {
    f.push({ id: "referrer.strict", severity: "info", message: `${effective} keeps paths and query strings private.`, modifier: 5 });
  }
  return result({ ...base, summary: effective, value }, f);
};
