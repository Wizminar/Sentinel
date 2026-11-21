import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { meetsGrade, render, run } from "../src/run.js";

const RAW = [
  "HTTP/2 200",
  "content-security-policy: default-src 'self'; object-src 'none'; base-uri 'self'",
  "strict-transport-security: max-age=31536000",
  "x-frame-options: DENY",
  "x-content-type-options: nosniff",
  "",
].join("\r\n");

describe("CLI runner", () => {
  let out: ReturnType<typeof vi.spyOn>;
  let err: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    out = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    err = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    vi.stubEnv("GITHUB_ACTIONS", "");
    vi.stubEnv("GITHUB_STEP_SUMMARY", "");
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
  });

  const base = { targets: ["https://example.com"], format: "json" as const, allowPrivate: false, verbose: false, timeoutMs: 1000 };

  it("compares grades", () => {
    expect(meetsGrade("A", "B")).toBe(true);
    expect(meetsGrade("B-", "B")).toBe(false);
    expect(meetsGrade("A+", "A+")).toBe(true);
  });

  it("grades a header dump from stdin", async () => {
    const r = await run({ ...base, stdin: RAW });
    expect(r.exitCode).toBe(0);
    expect(r.reports[0]!.grade).toMatch(/^A/);
    expect(JSON.parse(String(out.mock.calls[0]![0])).grade).toBe(r.reports[0]!.grade);
  });

  it("exits 1 below --fail-under", async () => {
    const r = await run({ ...base, stdin: "HTTP/1.1 200\r\nserver: x\r\n", failUnder: "B" });
    expect(r.exitCode).toBe(1);
    expect(String(err.mock.calls.at(-1)![0])).toMatch(/below the required B/);
  });

  it("emits GitHub annotations inside Actions", async () => {
    vi.stubEnv("GITHUB_ACTIONS", "true");
    await run({ ...base, stdin: "HTTP/1.1 200\r\n" });
    const lines = err.mock.calls.map((c) => String(c[0]));
    expect(lines.some((l) => l.startsWith("::error title=Content-Security-Policy"))).toBe(true);
  });

  it("writes reports to a file", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sentinel-"));
    const file = join(dir, "r.sarif");
    await run({ ...base, format: "sarif", output: file, stdin: RAW });
    expect(JSON.parse(await readFile(file, "utf8")).version).toBe("2.1.0");
  });

  it("reports unreachable or private targets as errors (exit 2)", async () => {
    const r = await run({ ...base, stdin: undefined, targets: ["http://10.0.0.1"] });
    expect(r.exitCode).toBe(2);
    expect(r.errors[0]!.message).toMatch(/Private/);
  });

  it("renders every format", async () => {
    const { reports } = await run({ ...base, stdin: RAW });
    for (const format of ["pretty", "json", "markdown", "sarif"] as const) {
      expect(render(reports, { format, verbose: true }).length).toBeGreaterThan(100);
    }
  });
});
