import { analyze, normalizeTarget, parseRawHeaders, type HeaderInput, type Report } from "@sentinel/core";

export interface ScanResult {
  report: Report;
  headers: HeaderInput;
  status?: number;
  /** "api": our own Worker (authoritative). "public": the free fallback lookup. */
  via: "api" | "public";
  cached?: boolean;
}

export class ScanFailure extends Error {}

const API_BASE: string = import.meta.env.VITE_API_BASE ?? "";

/** Thrown when there's no Sentinel API behind this page (e.g. a static-only deploy). */
class NoApi extends Error {}

async function viaApi(target: URL): Promise<ScanResult> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api/scan?url=${encodeURIComponent(target.href)}`, { headers: { Accept: "application/json" } });
  } catch {
    throw new NoApi();
  }
  if (!(res.headers.get("content-type") ?? "").includes("application/json")) throw new NoApi();
  const body = await res.json();
  if (!res.ok) throw new ScanFailure(body?.error ?? `The scan failed (HTTP ${res.status}).`);
  return { report: body.report, headers: body.response.headers, status: body.response.status, via: "api", cached: body.cached };
}

/**
 * Zero-backend fallback: a public header-lookup service, reached through a
 * CORS proxy so the browser can read the body. A plain CORS proxy isn't
 * enough on its own — browsers only expose a few "safe" response headers to
 * JavaScript, never CSP or HSTS — so the headers have to arrive as data.
 */
const LOOKUP = (t: string) => `https://api.hackertarget.com/httpheaders/?q=${encodeURIComponent(t)}`;
const PROXIES: { url: (t: string) => string; read: (r: Response) => Promise<string> }[] = [
  { url: (t) => `https://api.allorigins.win/get?url=${encodeURIComponent(LOOKUP(t))}`, read: async (r) => (await r.json())?.contents ?? "" },
  { url: (t) => `https://api.codetabs.com/v1/proxy/?quest=${encodeURIComponent(LOOKUP(t))}`, read: (r) => r.text() },
];

async function viaPublic(target: URL): Promise<ScanResult> {
  for (const p of PROXIES) {
    try {
      const res = await Promise.race([
        fetch(p.url(target.href), { cache: "no-store" }),
        new Promise<never>((_, rej) => setTimeout(() => rej(new Error("timeout")), 15000)),
      ]);
      if (!res.ok) continue;
      const text = await p.read(res);
      if (/API count exceeded/i.test(text)) throw new ScanFailure("The free lookup service has hit its daily limit. Try again later, or deploy the Sentinel Worker for unlimited scans.");
      const headers = parseRawHeaders(text);
      if (Object.keys(headers).length < 3) continue;
      const status = Number(/HTTP\/[\d.]+\s+(\d{3})/.exec(text.split(/\r?\n\s*\r?\n/).filter((b) => b.trim()).pop() ?? "")?.[1]) || undefined;
      return { report: analyze({ url: target.href, headers, status }), headers, status, via: "public" };
    } catch (e) {
      if (e instanceof ScanFailure) throw e;
    }
  }
  throw new ScanFailure(`Couldn't read the headers for ${target.host}. Check the address, or try again in a minute.`);
}

export async function scan(raw: string): Promise<ScanResult> {
  const t = normalizeTarget(raw);
  if (!t.ok) throw new ScanFailure(t.error);
  try {
    return await viaApi(t.url);
  } catch (e) {
    if (e instanceof NoApi) return viaPublic(t.url);
    throw e;
  }
}
