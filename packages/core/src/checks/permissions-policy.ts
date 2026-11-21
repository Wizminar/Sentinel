import type { Finding } from "../types.js";
import { type Check, result } from "./context.js";

const POWERFUL = ["camera", "microphone", "geolocation", "payment", "usb", "serial", "bluetooth", "hid", "display-capture", "midi"];

/** Parse "camera=(), geolocation=(self "https://maps.example")" into feature → allowlist. */
export function parsePermissionsPolicy(value: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const re = /([a-z0-9-]+)\s*=\s*(\([^)]*\)|\*|[^,\s]+)/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(value))) {
    const feature = m[1]!.toLowerCase();
    const raw = m[2]!.replace(/^\(|\)$/g, "").trim();
    out.set(feature, raw ? raw.split(/\s+/) : []);
  }
  return out;
}

export const permissionsPolicy: Check = ({ headers }) => {
  const base = {
    id: "permissions-policy" as const,
    title: "Permissions-Policy",
    headers: ["permissions-policy", "feature-policy"],
    defends: "Embedded content using camera, mic, location",
  };
  const value = headers.joined("permissions-policy");
  const legacy = headers.joined("feature-policy");

  if (!value) {
    const f: Finding[] = legacy
      ? [{ id: "permissions.feature-policy", severity: "low", message: "Only the deprecated Feature-Policy header is set. Browsers now read Permissions-Policy, which uses a different syntax.", modifier: -3, evidence: legacy }]
      : [{ id: "permissions.missing", severity: "low", message: "Embedded iframes can ask for powerful features like the camera or location. Turn off the ones you don't use.", modifier: -3 }];
    return result({ ...base, summary: legacy ? "Deprecated Feature-Policy only" : "Missing", value: legacy }, f);
  }

  const parsed = parsePermissionsPolicy(value);
  if (!parsed.size) {
    return result({ ...base, summary: "Unparseable", value }, [
      { id: "permissions.invalid", severity: "low", message: "The value doesn't follow the structured-header syntax (feature=(allowlist)), so browsers ignore it.", modifier: -3, evidence: value },
    ]);
  }
  const open = POWERFUL.filter((p) => parsed.get(p)?.includes("*"));
  const f: Finding[] = open.length
    ? [{ id: "permissions.wildcard", severity: "medium", message: `${open.join(", ")} ${open.length === 1 ? "is" : "are"} allowed for every origin, including third-party iframes.`, modifier: -5, evidence: value }]
    : [];
  const disabled = [...parsed.values()].filter((v) => v.length === 0).length;
  return result({ ...base, summary: `${parsed.size} feature${parsed.size === 1 ? "" : "s"} configured, ${disabled} disabled`, value }, f);
};
