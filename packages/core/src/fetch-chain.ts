import { analyze } from "./analyze.js";
import { normalizeTarget, type TargetOptions } from "./target.js";
import type { RedirectHop } from "./types.js";

export const PROBE_ORIGIN = "https://sentinel-cors-probe.invalid";
const MAX_HOPS = 6;
const HOP_TIMEOUT_MS = 8000;

export interface ChainResult {
  finalUrl: string;
  status: number;
  headers: Record<string, string | string[]>;
  redirects: RedirectHop[];
  timingMs: number;
}

export interface FetchChainOptions extends TargetOptions {
  fetcher?: typeof fetch;
  /** Called before each request; throw to refuse a hop (e.g. after a DNS check). */
  beforeHop?: (url: URL) => Promise<void> | void;
  timeoutMs?: number;
  userAgent?: string;
}

export class ScanError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

/**
 * Follow redirects by hand so every hop is recorded and re-validated.
 * `redirect: "follow"` would let a public site 302 us to an internal address,
 * the classic SSRF bypass — so each Location is checked like user input.
 */
export async function fetchChain(start: URL, opts: FetchChainOptions = {}): Promise<ChainResult> {
  const fetcher = opts.fetcher ?? fetch;
  const timeout = opts.timeoutMs ?? HOP_TIMEOUT_MS;
  const t0 = Date.now();
  const redirects: RedirectHop[] = [];
  let url = start;

  for (let hop = 0; hop <= MAX_HOPS; hop++) {
    await opts.beforeHop?.(url);
    let res: Response;
    try {
      res = await fetcher(url.href, {
        method: "GET",
        redirect: "manual",
        signal: AbortSignal.timeout(timeout),
        headers: {
          "User-Agent": opts.userAgent ?? "Mozilla/5.0 (compatible; SentinelScanner/2.0; +https://github.com/Wizminar/Sentinel)",
          Accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
          Origin: PROBE_ORIGIN,
        },
      });
    } catch (e) {
      const msg = e instanceof Error && e.name === "TimeoutError" ? `${url.host} didn't respond within ${timeout / 1000} seconds.` : `Couldn't connect to ${url.host}.`;
      throw new ScanError(msg, 502);
    }
    // Only headers matter; don't download the body.
    await res.body?.cancel().catch(() => {});

    const location = res.headers.get("location");
    if (res.status >= 300 && res.status < 400 && location) {
      redirects.push({ url: url.href, status: res.status });
      let next: URL;
      try {
        next = new URL(location, url);
      } catch {
        throw new ScanError(`${url.host} redirected to an invalid URL.`, 502);
      }
      const checked = normalizeTarget(next.href, opts);
      if (!checked.ok) throw new ScanError(`Redirect to ${next.host} was blocked: ${checked.error}`, 400);
      url = checked.url;
      continue;
    }

    const headers: Record<string, string | string[]> = {};
    res.headers.forEach((value, key) => {
      if (key !== "set-cookie") headers[key] = value;
    });
    // getSetCookie() keeps each Set-Cookie separate (they can't be safely comma-joined).
    const h = res.headers as Headers & { getSetCookie?: () => string[] };
    const cookies = typeof h.getSetCookie === "function" ? h.getSetCookie() : [];
    if (cookies.length) headers["set-cookie"] = cookies;

    return { finalUrl: url.href, status: res.status, headers, redirects, timingMs: Date.now() - t0 };
  }
  throw new ScanError(`More than ${MAX_HOPS} redirects.`, 502);
}

/** Fetch a URL (following redirects safely) and grade its headers in one call. */
export async function scanUrl(target: URL, opts: FetchChainOptions = {}) {
  const chain = await fetchChain(target, opts);
  const report = analyze({
    url: target.href,
    finalUrl: chain.finalUrl,
    status: chain.status,
    headers: chain.headers,
    redirects: chain.redirects,
    probeOrigin: PROBE_ORIGIN,
  });
  const { finalUrl: _f, ...response } = chain;
  return { report, response };
}
