import { describe, expect, it } from "vitest";
import fn, { config } from "../../../netlify/functions/api";

const call = (path: string) => fn(new Request(`https://sentinel.netlify.app${path}`));

describe("Netlify function", () => {
  it("routes the API and badge paths", () => {
    expect(config.path).toEqual(["/api/*", "/badge", "/badge.svg"]);
    expect(config.rateLimit.windowLimit).toBe(20);
  });

  it("answers health checks", async () => {
    const res = await call("/api/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("keeps the SSRF guard", async () => {
    const res = await call("/api/scan?url=169.254.169.254");
    expect(res.status).toBe(400);
  });
});
