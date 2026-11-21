import { describe, expect, it } from "vitest";
import { fixesFor, gradeFor, parseRawHeaders, renderConfig, toMarkdown, toSarif } from "../src/index.js";
import { scan, STRONG } from "./helpers.js";

describe("grading", () => {
  it("maps scores to grades", () => {
    expect(gradeFor(105)).toBe("A+");
    expect(gradeFor(90)).toBe("A");
    expect(gradeFor(70)).toBe("B");
    expect(gradeFor(24)).toBe("F");
  });

  it("gives a hardened site A+", () => {
    const r = scan(STRONG);
    expect(r.grade).toBe("A+");
    expect(r.score).toBeGreaterThanOrEqual(100);
    expect(r.summary.fail).toBe(0);
  });

  it("gives a bare HTTPS site D-, and F once it also has a broken CSP and leaky cookies", () => {
    expect(scan({}).grade).toBe("D-");
    const r = scan({ "content-security-policy": "script-src *", "set-cookie": "sid=1", server: "nginx/1.18.0" });
    expect(r.grade).toBe("F");
  });

  it("keeps a site without CSP out of the A range, however good the rest is (old 5/6 = A bug)", () => {
    const { "content-security-policy": _csp, ...rest } = STRONG;
    const r = scan(rest);
    expect(r.grade).toBe("B");
    expect(r.score).toBe(75);
  });

  it("only applies bonuses to sites that already score 90+", () => {
    const r = scan({ "strict-transport-security": "max-age=63072000; includeSubDomains; preload" });
    const bonus = r.checks.flatMap((c) => c.findings).filter((f) => f.modifier > 0);
    expect(bonus.length).toBeGreaterThan(0);
    expect(r.score).toBe(100 + r.checks.reduce((n, c) => n + Math.min(0, c.modifier - c.findings.reduce((m, f) => m + Math.max(0, f.modifier), 0)), 0));
  });

  it("caps plain HTTP at D and CORS credential reflection at F", () => {
    expect(scan(STRONG, { url: "http://example.com/" }).grade).toBe("D");
    const r = scan({ ...STRONG, "access-control-allow-origin": "https://probe.invalid", "access-control-allow-credentials": "true" }, { probeOrigin: "https://probe.invalid" });
    expect(r.grade).toBe("F");
  });

  it("is deterministic", () => {
    expect(scan(STRONG)).toEqual(scan(STRONG));
  });
});

describe("remediation and output", () => {
  it("suggests only the headers that are missing", () => {
    const fixes = fixesFor(scan({ "x-content-type-options": "nosniff" }));
    const names = fixes.map((f) => f.header);
    expect(names).toContain("Content-Security-Policy");
    expect(names).not.toContain("X-Content-Type-Options");
  });

  it("renders valid config for each platform", () => {
    const fixes = fixesFor(scan({}));
    expect(renderConfig("nginx", fixes)).toMatch(/add_header Content-Security-Policy ".*" always;/);
    expect(JSON.parse(renderConfig("vercel", fixes)).headers[0].headers.length).toBe(fixes.length);
    expect(renderConfig("express", fixes)).toContain('app.disable("x-powered-by")');
  });

  it("produces markdown and SARIF", () => {
    const r = scan({});
    expect(toMarkdown(r)).toContain("## Sentinel: D- (27/100)");
    const sarif = toSarif(r);
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0]!.results.length).toBeGreaterThan(3);
    expect(sarif.runs[0]!.results.every((x) => sarif.runs[0]!.tool.driver.rules.some((rule) => rule.id === x.ruleId))).toBe(true);
  });

  it("parses raw curl -I output, keeping only the final response", () => {
    const raw = "HTTP/1.1 301 Moved\r\nLocation: https://x/\r\n\r\nHTTP/2 200\r\nX-Frame-Options: DENY\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n";
    expect(parseRawHeaders(raw)).toEqual({ "x-frame-options": ["DENY"], "set-cookie": ["a=1", "b=2"] });
  });
});

describe("METHOD table", () => {
  it("lists every check in report order", async () => {
    const { METHOD, CHECKS } = await import("../src/index.js");
    expect(METHOD).toHaveLength(CHECKS.length);
    expect(METHOD.map((m) => m.id)).toEqual(scan({}).checks.map((c) => c.id));
  });
  it("matches the worst case each check can actually produce", async () => {
    const { METHOD } = await import("../src/index.js");
    const worst = scan(
      { "set-cookie": ["sid=1; SameSite=None", "__Host-x=1"], server: "a/1.0", "x-powered-by": "b", "x-generator": "c", "public-key-pins": "x", "referrer-policy": "unsafe-url", "permissions-policy": "camera=*", "content-security-policy": "script-src * 'unsafe-inline' 'unsafe-eval' data:", "x-content-type-options": "sniff" },
      { url: "https://example.com/", probeOrigin: "https://p.invalid" },
    );
    const byId = Object.fromEntries(worst.checks.map((c) => [c.id, c.modifier]));
    for (const id of ["csp", "content-type-options", "referrer-policy", "permissions-policy", "cookies", "disclosure", "legacy"] as const) {
      expect(byId[id], id).toBe(METHOD.find((m) => m.id === id)!.penalty);
    }
  });
});
