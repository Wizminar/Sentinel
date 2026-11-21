import type { Finding } from "../types.js";
import { type Check, result } from "./context.js";

export const legacy: Check = ({ headers }) => {
  const base = {
    id: "legacy" as const,
    title: "Deprecated headers",
    headers: ["x-xss-protection", "public-key-pins", "expect-ct"],
    defends: "Configuration drift from retired browser features",
  };
  const f: Finding[] = [];
  const xxp = headers.first("x-xss-protection");
  if (xxp && xxp.trim().startsWith("1")) {
    f.push({ id: "legacy.xss-protection", severity: "low", message: "X-XSS-Protection turned on a filter no current browser ships; in old ones it could be abused to leak data. Set it to 0 or remove it.", modifier: 0, evidence: xxp });
  }
  const hpkp = headers.first("public-key-pins");
  if (hpkp) {
    f.push({ id: "legacy.hpkp", severity: "medium", message: "Public-Key-Pins was removed from browsers after it locked sites out when certificates changed. Remove it.", modifier: -5, evidence: hpkp });
  }
  const ect = headers.first("expect-ct");
  if (ect) {
    f.push({ id: "legacy.expect-ct", severity: "info", message: "Expect-CT is obsolete now that Certificate Transparency is always enforced. Safe to remove.", modifier: 0, evidence: ect });
  }
  const value = f.map((x) => x.evidence).join("\n") || undefined;
  return result({ ...base, summary: f.length ? `${f.length} retired header${f.length === 1 ? "" : "s"} still sent` : "None in use", value }, f);
};
