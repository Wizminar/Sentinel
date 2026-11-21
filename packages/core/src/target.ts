/**
 * Target validation shared by every place that fetches a user-supplied URL.
 * The scanner is a server-side fetcher, which makes it an SSRF risk: without
 * these checks anyone could make it request cloud metadata endpoints
 * (169.254.169.254) or services on a private network.
 */

export type TargetResult = { ok: true; url: URL } | { ok: false; error: string };

export interface TargetOptions {
  /** Allow localhost and private networks — for scanning your own dev or staging servers from the CLI. */
  allowPrivate?: boolean;
}

const ALLOWED_PORTS = new Set(["", "80", "443", "8080", "8443"]);

export function normalizeTarget(raw: string, opts: TargetOptions = {}): TargetResult {
  let s = (raw ?? "").trim();
  if (!s) return { ok: false, error: "Enter a URL to scan." };
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = "https://" + s;
  let url: URL;
  try {
    url = new URL(s);
  } catch {
    return { ok: false, error: "That isn't a valid URL. Try something like example.com." };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return { ok: false, error: "Only http and https URLs can be scanned." };
  if (url.username || url.password) return { ok: false, error: "Remove the username and password from the URL." };
  if (opts.allowPrivate) {
    url.hash = "";
    return { ok: true, url };
  }
  if (!ALLOWED_PORTS.has(url.port)) return { ok: false, error: "Only ports 80, 443, 8080 and 8443 can be scanned." };
  if (!url.hostname.includes(".") && !url.hostname.startsWith("[")) return { ok: false, error: "Use a full domain name, like example.com." };
  if (isBlockedHost(url.hostname)) return { ok: false, error: "Private, local and internal addresses can't be scanned." };
  url.hash = "";
  return { ok: true, url };
}

function ipv4(host: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  return parts.every((n) => n <= 255) ? parts : null;
}

function blockedV4([a, b]: number[]): boolean {
  if (a === undefined || b === undefined) return true;
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||  // carrier-grade NAT
    (a === 169 && b === 254) ||            // link-local, cloud metadata
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0) ||
    (a === 198 && (b === 18 || b === 19)); // benchmarking
}

/**
 * True for hostnames that point inside a private network. WHATWG URL parsing
 * already normalises tricks like "http://2130706433" or "0x7f.1" to dotted
 * IPv4, so checking the parsed hostname is enough. DNS names that *resolve* to
 * private IPs are handled at fetch time by the runtime (Cloudflare Workers
 * can't reach private networks; the CLI resolves and re-checks).
 */
export function isBlockedHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/\.$/, "");
  if (h === "localhost" || /\.(localhost|local|internal|intranet|lan|home\.arpa)$/.test(h)) return true;
  if (h === "metadata.google.internal" || h === "metadata") return true;
  const v4 = ipv4(h);
  if (v4) return blockedV4(v4);
  if (h.startsWith("[") || h.includes(":")) {
    const v6 = h.replace(/^\[|\]$/g, "");
    if (v6 === "::" || v6 === "::1") return true;
    if (/^f[cd]/.test(v6) || /^fe[89ab]/.test(v6)) return true; // unique-local, link-local
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(v6);
    if (mapped) return blockedV4(ipv4(mapped[1]!) ?? []);
    if (/^::ffff:[0-9a-f]{1,4}:[0-9a-f]{1,4}$/.test(v6)) {
      const [hi, lo] = v6.slice(7).split(":").map((x) => parseInt(x, 16));
      return blockedV4([hi! >> 8, hi! & 255, lo! >> 8, lo! & 255]);
    }
  }
  return false;
}
