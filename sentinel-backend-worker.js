/**
 * Sentinel — header-fetch backend (Cloudflare Worker)
 * ---------------------------------------------------
 * Fetches a target URL server-side and returns its HTTP response headers as
 * JSON. This removes Sentinel's dependency on a public CORS proxy: results
 * become authoritative (the server reads every header directly) and no third
 * party ever sees the URL you analyze. This is the "self-hosted backend" item
 * from the roadmap.
 *
 * ── Deploy in ~2 minutes (free) ─────────────────────────────────────────────
 *  Option A — dashboard:
 *    1. dash.cloudflare.com → Workers & Pages → Create → Create Worker
 *    2. Replace the starter code with this file, click Deploy
 *    3. Copy the worker URL, e.g. https://sentinel-proxy.<you>.workers.dev
 *
 *  Option B — CLI:
 *    1. npm i -g wrangler && wrangler login
 *    2. Save this as worker.js, then:  wrangler deploy worker.js --name sentinel-proxy
 *
 * ── Wire it up ──────────────────────────────────────────────────────────────
 *  In index.html, set the BACKEND constant to your worker URL + "?url=" :
 *    const BACKEND = "https://sentinel-proxy.<you>.workers.dev/?url=";
 *  Sentinel will use it automatically and fall back to the public proxy if it
 *  is ever unreachable.
 *
 *  Test it directly in a browser:
 *    https://sentinel-proxy.<you>.workers.dev/?url=https://github.com
 *  → you should see JSON with a "headers" object.
 *
 * Tip: once it works, lock it to your own site by replacing "*" in
 * ALLOW_ORIGIN below with your domain, e.g. "https://sentinel.yoursite.com".
 */

const ALLOW_ORIGIN = "*";

const CORS = {
  "Access-Control-Allow-Origin": ALLOW_ORIGIN,
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "*",
  "Access-Control-Expose-Headers": "*",
};

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "Content-Type": "application/json; charset=utf-8" },
  });
}

export default {
  async fetch(request) {
    // Preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS });
    }
    if (request.method !== "GET") {
      return json({ error: "Use GET" }, 405);
    }

    const target = new URL(request.url).searchParams.get("url");
    if (!target) {
      return json({ error: "Missing ?url= parameter" }, 400);
    }

    let parsed;
    try {
      parsed = new URL(target);
    } catch {
      return json({ error: "That is not a valid URL" }, 400);
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return json({ error: "Only http and https URLs are allowed" }, 400);
    }

    let upstream;
    try {
      upstream = await fetch(parsed.toString(), {
        method: "GET",
        redirect: "follow",
        headers: {
          // A normal-looking UA avoids some bot walls returning stripped headers
          "User-Agent": "Mozilla/5.0 (compatible; SentinelHeaderScanner/1.0)",
          "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        },
      });
    } catch (e) {
      return json({ error: "Could not reach the target: " + (e && e.message) }, 502);
    }

    // Flatten the response headers into a plain object (lowercased keys)
    const headers = {};
    upstream.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    return json({
      url: upstream.url,
      status: upstream.status,
      finalRedirect: upstream.redirected,
      headers,
    });
  },
};
