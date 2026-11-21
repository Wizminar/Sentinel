import { describe, expect, it, vi } from "vitest";
import { handle, type ScanResponse } from "../src/index.js";

type Route = { status?: number; headers?: Record<string, string | string[]> };

/** A fake internet: URL → canned response. */
function fakeFetch(routes: Record<string, Route>) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const href = String(input);
    const r = routes[href];
    if (!r) throw new TypeError(`unexpected fetch ${href}`);
    expect(init?.redirect).toBe("manual");
    const h = new Headers();
    for (const [k, v] of Object.entries(r.headers ?? {})) for (const one of [v].flat()) h.append(k, one);
    return new Response(null, { status: r.status ?? 200, headers: h });
  }) as unknown as typeof fetch & ReturnType<typeof vi.fn>;
}

const req = (path: string, init?: RequestInit) => new Request(`https://sentinel.test${path}`, init);

describe("worker /api/scan", () => {
  it("scans a site and returns a graded report", async () => {
    const f = fakeFetch({
      "https://example.com/": { headers: { "x-frame-options": "DENY", "set-cookie": ["a=1; Secure", "sid=2"] } },
    });
    const res = await handle(req("/api/scan?url=example.com"), {}, undefined, f);
    expect(res.status).toBe(200);
    const body = (await res.json()) as ScanResponse;
    expect(body.report.finalUrl).toBe("https://example.com/");
    expect(body.report.checks.find((c) => c.id === "framing")?.status).toBe("pass");
    expect(body.response.headers["set-cookie"]).toEqual(["a=1; Secure", "sid=2"]);
    expect(res.headers.get("content-security-policy")).toContain("default-src 'none'");
  });

  it("records each redirect hop", async () => {
    const f = fakeFetch({
      "http://example.com/": { status: 301, headers: { location: "https://example.com/" } },
      "https://example.com/": { status: 302, headers: { location: "/home" } },
      "https://example.com/home": { headers: { server: "x" } },
    });
    const body = (await (await handle(req("/api/scan?url=http://example.com"), {}, undefined, f)).json()) as ScanResponse;
    expect(body.report.redirects.map((r) => r.status)).toEqual([301, 302]);
    expect(body.report.finalUrl).toBe("https://example.com/home");
  });

  it("blocks redirects into private networks (SSRF)", async () => {
    const f = fakeFetch({
      "https://evil.example/": { status: 302, headers: { location: "http://169.254.169.254/latest/meta-data/" } },
    });
    const res = await handle(req("/api/scan?url=evil.example"), {}, undefined, f);
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toMatch(/blocked/);
    expect(f).toHaveBeenCalledTimes(1);
  });

  it("rejects private targets before fetching anything", async () => {
    const f = fakeFetch({});
    const res = await handle(req("/api/scan?url=http://127.0.0.1"), {}, undefined, f);
    expect(res.status).toBe(400);
    expect(f).not.toHaveBeenCalled();
  });

  it("detects CORS origin reflection using the probe origin", async () => {
    const f = vi.fn(async (_u: RequestInfo | URL, init?: RequestInit) => {
      const origin = new Headers(init?.headers).get("origin")!;
      return new Response(null, { headers: { "access-control-allow-origin": origin, "access-control-allow-credentials": "true" } });
    }) as unknown as typeof fetch;
    const body = (await (await handle(req("/api/scan?url=example.com"), {}, undefined, f)).json()) as ScanResponse;
    expect(body.report.grade).toBe("F");
  });

  it("stops redirect loops", async () => {
    const f = fakeFetch({
      "https://a.example/": { status: 302, headers: { location: "https://b.example/" } },
      "https://b.example/": { status: 302, headers: { location: "https://a.example/" } },
    });
    const res = await handle(req("/api/scan?url=a.example"), {}, undefined, f);
    expect(res.status).toBe(502);
  });

  it("returns 429 when the rate limiter says no", async () => {
    const env = { RATE_LIMITER: { limit: async () => ({ success: false }) } };
    const res = await handle(req("/api/scan?url=example.com"), env, undefined, fakeFetch({}));
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("60");
  });

  it("only grants CORS to allowed origins", async () => {
    const f = fakeFetch({ "https://example.com/": {} });
    const env = { ALLOWED_ORIGINS: "http://localhost:5173" };
    const ok = await handle(req("/api/scan?url=example.com", { headers: { Origin: "http://localhost:5173" } }), env, undefined, f);
    expect(ok.headers.get("access-control-allow-origin")).toBe("http://localhost:5173");
    const no = await handle(req("/api/scan?url=example.com", { headers: { Origin: "https://other.site" } }), env, undefined, f);
    expect(no.headers.get("access-control-allow-origin")).toBeNull();
  });
});

describe("worker /badge", () => {
  it("renders an SVG badge with the grade", async () => {
    const f = fakeFetch({ "https://example.com/": {} });
    const res = await handle(req("/badge?url=example.com"), {}, undefined, f);
    expect(res.headers.get("content-type")).toContain("image/svg+xml");
    const svg = await res.text();
    expect(svg).toContain("security headers");
    expect(svg).toMatch(/>D-</);
  });

  it("shows ? for invalid targets instead of erroring", async () => {
    const res = await handle(req("/badge?url=localhost"), {}, undefined, fakeFetch({}));
    expect(await res.text()).toContain(">?<");
  });
});
