import { describe, expect, it } from "vitest";
import { check, ids } from "./helpers.js";

describe("HSTS", () => {
  it("fails when missing on HTTPS", () => {
    expect(check({}, "hsts").status).toBe("fail");
  });
  it("is not applicable over HTTP", () => {
    expect(check({}, "hsts", { url: "http://example.com/" }).status).toBe("info");
  });
  it("warns on a short max-age", () => {
    const c = check({ "strict-transport-security": "max-age=300" }, "hsts");
    expect(ids(c)).toContain("hsts.short");
    expect(c.status).toBe("warn");
  });
  it("fails max-age=0 and invalid headers", () => {
    expect(ids(check({ "strict-transport-security": "max-age=0" }, "hsts"))).toContain("hsts.zero");
    expect(ids(check({ "strict-transport-security": "includeSubDomains" }, "hsts"))).toEqual(["hsts.invalid"]);
  });
  it("rewards preload-ready policies", () => {
    const c = check({ "strict-transport-security": "max-age=31536000; includeSubDomains; preload" }, "hsts");
    expect(c.modifier).toBe(5);
  });
});

describe("framing", () => {
  it("prefers CSP frame-ancestors over X-Frame-Options", () => {
    const c = check({ "content-security-policy": "frame-ancestors 'self'", "x-frame-options": "garbage" }, "framing");
    expect(c.status).toBe("pass");
  });
  it("fails on obsolete ALLOW-FROM", () => {
    expect(ids(check({ "x-frame-options": "ALLOW-FROM https://a.com" }, "framing"))).toEqual(["framing.allow-from"]);
  });
  it("fails when frame-ancestors is open", () => {
    expect(check({ "content-security-policy": "frame-ancestors *" }, "framing").status).toBe("fail");
  });
  it("passes DENY regardless of case", () => {
    expect(check({ "x-frame-options": "deny" }, "framing").status).toBe("pass");
  });
});

describe("referrer policy", () => {
  it("uses the last recognised token", () => {
    const c = check({ "referrer-policy": "unsafe-url, made-up, strict-origin" }, "referrer-policy");
    expect(c.summary).toBe("strict-origin");
  });
  it("flags unsafe-url", () => {
    expect(check({ "referrer-policy": "unsafe-url" }, "referrer-policy").status).toBe("warn");
  });
  it("treats a missing header as advisory (browser default is safe)", () => {
    const c = check({}, "referrer-policy");
    expect(c.status).toBe("info");
    expect(c.modifier).toBe(0);
  });
});

describe("permissions policy", () => {
  it("flags powerful features open to every origin", () => {
    expect(ids(check({ "permissions-policy": "camera=*, geolocation=()" }, "permissions-policy"))).toEqual(["permissions.wildcard"]);
  });
  it("notices deprecated Feature-Policy", () => {
    expect(ids(check({ "feature-policy": "camera 'none'" }, "permissions-policy"))).toEqual(["permissions.feature-policy"]);
  });
});

describe("cookies", () => {
  it("is quiet when no cookies are set", () => {
    expect(check({}, "cookies").status).toBe("info");
  });
  it("fails session cookies without Secure and HttpOnly", () => {
    const c = check({ "set-cookie": ["PHPSESSID=1; Path=/"] }, "cookies");
    expect(ids(c)).toEqual(["cookies.session-no-secure", "cookies.session-no-httponly", "cookies.no-samesite"]);
    expect(c.status).toBe("fail");
  });
  it("doesn't demand HttpOnly on non-session cookies", () => {
    const c = check({ "set-cookie": ["theme=dark; Secure; SameSite=Lax"] }, "cookies");
    expect(c.status).toBe("pass");
  });
  it("catches broken __Host- prefixes and SameSite=None without Secure", () => {
    const c = check({ "set-cookie": ["__Host-a=1; Secure; Path=/; Domain=example.com; SameSite=Lax", "b=2; SameSite=None"] }, "cookies");
    expect(ids(c)).toEqual(expect.arrayContaining(["cookies.prefix", "cookies.samesite-none-insecure"]));
  });
  it("keeps Expires dates intact (commas inside a cookie)", () => {
    const c = check({ "set-cookie": ["id=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure; HttpOnly; SameSite=Strict"] }, "cookies");
    expect(c.status).toBe("pass");
  });
});

describe("CORS", () => {
  it("catches origin reflection with credentials", () => {
    const c = check(
      { "access-control-allow-origin": "https://evil.example", "access-control-allow-credentials": "true" },
      "cors",
      { probeOrigin: "https://evil.example" },
    );
    expect(ids(c)).toEqual(["cors.reflect-credentials"]);
    expect(c.status).toBe("fail");
  });
  it("flags the null origin", () => {
    expect(ids(check({ "access-control-allow-origin": "null" }, "cors"))).toEqual(["cors.null"]);
  });
  it("treats public * as advisory", () => {
    expect(check({ "access-control-allow-origin": "*" }, "cors").status).toBe("info");
  });
});

describe("disclosure and legacy", () => {
  it("flags versioned Server and X-Powered-By, capped at -5", () => {
    const c = check({ server: "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/7.4.3", "x-aspnet-version": "4.0", "x-generator": "Drupal 9" }, "disclosure");
    expect(c.findings).toHaveLength(4);
    expect(c.modifier).toBe(-5);
  });
  it("leaves a bare Server name alone", () => {
    expect(check({ server: "cloudflare" }, "disclosure").status).toBe("pass");
  });
  it("advises turning off X-XSS-Protection", () => {
    expect(ids(check({ "x-xss-protection": "1; mode=block" }, "legacy"))).toEqual(["legacy.xss-protection"]);
  });
});

describe("transport", () => {
  it("fails plain HTTP", () => {
    expect(check({}, "transport", { url: "http://example.com/" }).status).toBe("fail");
  });
  it("flags HTTPS → HTTP downgrades in the redirect chain", () => {
    const c = check({}, "transport", {
      url: "https://a.example/",
      finalUrl: "https://c.example/",
      redirects: [{ url: "https://a.example/", status: 301 }, { url: "http://b.example/", status: 302 }],
    });
    expect(ids(c)).toContain("transport.downgrade");
  });
  it("notes an initial redirect that changes host", () => {
    const c = check({}, "transport", {
      url: "http://example.com/",
      finalUrl: "https://www.example.com/",
      redirects: [{ url: "http://example.com/", status: 301 }],
    });
    expect(ids(c)).toEqual(["transport.redirect-host"]);
  });
});
