import { describe, expect, it } from "vitest";
import { isBlockedHost, normalizeTarget } from "../src/index.js";

describe("target validation (SSRF guard)", () => {
  it.each([
    "localhost", "127.0.0.1", "10.1.2.3", "172.20.0.1", "192.168.1.1", "169.254.169.254",
    "100.64.0.1", "0.0.0.0", "[::1]", "[fd00::1]", "[fe80::1]", "[::ffff:127.0.0.1]",
    "metadata.google.internal", "printer.local", "api.internal",
  ])("blocks %s", (h) => {
    expect(isBlockedHost(h)).toBe(true);
  });

  it.each(["example.com", "8.8.8.8", "172.32.0.1", "[2606:4700::1111]"])("allows %s", (h) => {
    expect(isBlockedHost(h)).toBe(false);
  });

  it("catches numeric IP tricks after URL normalisation", () => {
    expect(normalizeTarget("http://2130706433/").ok).toBe(false);
    expect(normalizeTarget("http://0x7f.1/").ok).toBe(false);
    expect(normalizeTarget("http://[::ffff:7f00:1]/").ok).toBe(false);
  });

  it("adds https:// and rejects bad input", () => {
    const r = normalizeTarget("example.com/path#frag");
    expect(r.ok && r.url.href).toBe("https://example.com/path");
    expect(normalizeTarget("ftp://example.com").ok).toBe(false);
    expect(normalizeTarget("https://user:pw@example.com").ok).toBe(false);
    expect(normalizeTarget("https://example.com:22").ok).toBe(false);
    expect(normalizeTarget("intranet").ok).toBe(false);
    expect(normalizeTarget("").ok).toBe(false);
  });
});
