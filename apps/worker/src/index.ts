import { normalizeTarget, ScanError, scanUrl, type ChainResult, type Report } from "@sentinel/core";
import { badgeSvg } from "./badge.js";

export interface Env {
  ASSETS?: Fetcher;
  RATE_LIMITER?: { limit(opts: { key: string }): Promise<{ success: boolean }> };
  ALLOWED_ORIGINS?: string;
}

export interface ScanResponse {
  report: Report;
  response: Pick<ChainResult, "status" | "headers" | "redirects" | "timingMs">;
  cached: boolean;
}

const CACHE_TTL = 600;      // scan results: 10 minutes
const BADGE_TTL = 6 * 3600; // badges: 6 hours

/** The API eats its own cooking: every response carries strict headers. */
const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "Cross-Origin-Resource-Policy": "cross-origin",
};

function corsHeaders(req: Request, env: Env): Record<string, string> {
  const origin = req.headers.get("Origin");
  if (!origin) return {};
  const self = new URL(req.url).origin;
  const allowed = new Set([self, ...(env.ALLOWED_ORIGINS ?? "").split(",").map((s) => s.trim()).filter(Boolean)]);
  return allowed.has(origin) ? { "Access-Control-Allow-Origin": origin, Vary: "Origin" } : { Vary: "Origin" };
}

function json(body: unknown, status: number, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...SECURITY_HEADERS, "Content-Type": "application/json; charset=utf-8", ...extra },
  });
}

async function rateLimited(req: Request, env: Env): Promise<boolean> {
  if (!env.RATE_LIMITER) return false;
  const key = req.headers.get("CF-Connecting-IP") ?? "anon";
  const { success } = await env.RATE_LIMITER.limit({ key });
  return !success;
}

const cacheStore = (): Cache | null => (typeof caches !== "undefined" ? (caches as unknown as { default: Cache }).default : null);

/** Scan with a short shared cache, so a viral link doesn't hammer the target. */
async function cachedScan(target: URL, ctx: ExecutionContext | undefined, fetcher: typeof fetch, fresh: boolean): Promise<ScanResponse> {
  const cache = cacheStore();
  const key = new Request(`https://cache.sentinel/scan?u=${encodeURIComponent(target.href)}`);
  if (cache && !fresh) {
    const hit = await cache.match(key);
    if (hit) return { ...(await hit.json<Omit<ScanResponse, "cached">>()), cached: true };
  }
  const out = await scanUrl(target, { fetcher });
  if (cache) {
    const put = cache.put(key, new Response(JSON.stringify(out), { headers: { "Cache-Control": `max-age=${CACHE_TTL}` } }));
    ctx ? ctx.waitUntil(put) : await put;
  }
  return { ...out, cached: false };
}

export async function handle(req: Request, env: Env, ctx?: ExecutionContext, fetcher: typeof fetch = fetch): Promise<Response> {
  const url = new URL(req.url);
  const cors = corsHeaders(req, env);

  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: { ...cors, "Access-Control-Allow-Methods": "GET", "Access-Control-Max-Age": "86400" } });
  }

  if (url.pathname === "/api/scan" || url.pathname === "/badge" || url.pathname === "/badge.svg") {
    if (req.method !== "GET") return json({ error: "Use GET." }, 405, cors);
    const target = normalizeTarget(url.searchParams.get("url") ?? "");
    const isBadge = url.pathname !== "/api/scan";

    if (!target.ok) {
      return isBadge ? svg(badgeSvg("?"), 60) : json({ error: target.error }, 400, cors);
    }
    if (await rateLimited(req, env)) {
      return json({ error: "Too many scans from your network. Wait a minute and try again." }, 429, { ...cors, "Retry-After": "60" });
    }

    try {
      const result = await cachedScan(target.url, ctx, fetcher, url.searchParams.has("fresh"));
      if (isBadge) return svg(badgeSvg(result.report.grade), BADGE_TTL);
      return json(result, 200, { ...cors, "Cache-Control": "no-store" });
    } catch (e) {
      if (isBadge) return svg(badgeSvg("?"), 300);
      const status = e instanceof ScanError ? e.status : 500;
      const message = e instanceof ScanError ? e.message : "The scan failed unexpectedly.";
      return json({ error: message }, status, cors);
    }
  }

  if (url.pathname === "/api/health") return json({ ok: true }, 200, cors);
  if (url.pathname.startsWith("/api/")) return json({ error: "Not found." }, 404, cors);

  return env.ASSETS ? env.ASSETS.fetch(req) : new Response("Not found", { status: 404 });
}

function svg(body: string, ttl: number): Response {
  return new Response(body, {
    headers: {
      ...SECURITY_HEADERS,
      "Content-Type": "image/svg+xml; charset=utf-8",
      "Cache-Control": `public, max-age=${ttl}, s-maxage=${ttl}`,
    },
  });
}

export default {
  fetch: (req: Request, env: Env, ctx: ExecutionContext) => handle(req, env, ctx),
} satisfies ExportedHandler<Env>;
