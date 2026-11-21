import { describe, expect, it } from "vitest";
import { analyzeScripts, parseCsp, parsePolicy } from "../src/index.js";
import { check, ids } from "./helpers.js";

describe("CSP parser", () => {
  it("lowercases directive names and keeps the first duplicate", () => {
    const p = parsePolicy("Script-Src 'self'; script-src *; img-src data:");
    expect(p.directives.get("script-src")).toEqual(["'self'"]);
    expect(p.duplicates).toEqual(["script-src"]);
  });

  it("flags unknown directives", () => {
    expect(parsePolicy("scirpt-src 'self'").unknown).toEqual(["scirpt-src"]);
  });

  it("splits multiple policies on commas", () => {
    expect(parseCsp("default-src 'self', script-src 'none'")).toHaveLength(2);
  });

  it("falls back from script-src to default-src", () => {
    const s = analyzeScripts(parsePolicy("default-src 'self' 'unsafe-inline'").directives);
    expect(s?.from).toBe("default-src");
    expect(s?.unsafeInline).toBe(true);
  });

  it("treats unsafe-inline as neutralised when a nonce is present", () => {
    const s = analyzeScripts(parsePolicy("script-src 'nonce-abc123' 'unsafe-inline'").directives);
    expect(s?.unsafeInline).toBe(false);
  });

  it("ignores allowlists and schemes under strict-dynamic", () => {
    const s = analyzeScripts(parsePolicy("script-src 'nonce-abc' 'strict-dynamic' https: *").directives);
    expect(s?.wildcard).toBe(false);
    expect(s?.broadSchemes).toEqual([]);
  });
});

describe("CSP check", () => {
  it("fails when missing", () => {
    const c = check({}, "csp");
    expect(c.status).toBe("fail");
    expect(ids(c)).toEqual(["csp.missing"]);
    expect(c.modifier).toBe(-25);
  });

  it("does not count Report-Only as protection", () => {
    const c = check({ "content-security-policy-report-only": "default-src 'self'" }, "csp");
    expect(c.status).toBe("fail");
    expect(ids(c)).toEqual(["csp.report-only"]);
  });

  it("catches a wildcard at the end of the directive (old regex bug)", () => {
    expect(ids(check({ "content-security-policy": "script-src *" }, "csp"))).toContain("csp.wildcard");
    expect(ids(check({ "content-security-policy": "script-src 'self' *;" }, "csp"))).toContain("csp.wildcard");
  });

  it("fails a policy that never restricts scripts", () => {
    const c = check({ "content-security-policy": "upgrade-insecure-requests" }, "csp");
    expect(ids(c)).toContain("csp.no-script-restriction");
    expect(c.status).toBe("fail");
  });

  it("flags data: and https: script sources", () => {
    const c = check({ "content-security-policy": "script-src 'self' data: https:; object-src 'none'; base-uri 'self'" }, "csp");
    expect(ids(c)).toEqual(["csp.broad-scheme"]);
  });

  it("flags known JSONP / CDN bypass hosts", () => {
    const c = check({ "content-security-policy": "script-src 'self' https://ajax.googleapis.com; object-src 'none'; base-uri 'self'" }, "csp");
    expect(ids(c)).toEqual(["csp.bypassable-host"]);
    expect(c.status).toBe("warn");
  });

  it("requires object-src 'none' and base-uri", () => {
    const c = check({ "content-security-policy": "script-src 'self'" }, "csp");
    expect(ids(c)).toEqual(["csp.object-src", "csp.base-uri"]);
  });

  it("accepts object-src 'none' inherited from default-src", () => {
    const c = check({ "content-security-policy": "default-src 'none'; script-src 'self'; base-uri 'self'" }, "csp");
    expect(c.status).toBe("pass");
    expect(c.findings).toEqual([]);
  });

  it("rewards nonce + strict-dynamic", () => {
    const c = check({ "content-security-policy": "script-src 'nonce-x1' 'strict-dynamic'; object-src 'none'; base-uri 'none'" }, "csp");
    expect(ids(c)).toEqual(["csp.strict"]);
    expect(c.modifier).toBe(5);
  });

  it("never scores a bad policy below a missing one", () => {
    const c = check({ "content-security-policy": "script-src * 'unsafe-inline' 'unsafe-eval' data:" }, "csp");
    expect(c.modifier).toBe(-25);
  });

  it("uses the strictest of several enforced policies", () => {
    const c = check({ "content-security-policy": ["script-src * 'unsafe-inline'", "script-src 'self'; object-src 'none'; base-uri 'self'"] }, "csp");
    expect(ids(c)).not.toContain("csp.unsafe-inline");
    expect(c.status).toBe("pass");
  });
});
