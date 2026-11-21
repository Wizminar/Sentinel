import { parseArgs } from "node:util";
import { PLATFORMS, type Grade, type Platform } from "@sentinel/core";
import { FORMATS, GRADES, readStdin, run, type Format } from "./run.js";

const HELP = `
sentinel-scan — grade a site's HTTP security headers

Usage
  sentinel-scan <url> [more urls] [options]
  curl -sI https://example.com | sentinel-scan --stdin

Options
  -f, --format <fmt>      pretty (default), json, markdown, sarif
      --fail-under <g>    exit 1 if any grade is below g (e.g. B, A-)
  -o, --output <file>     write the report to a file instead of stdout
      --fix <platform>    print a config snippet that fixes what failed:
                          ${PLATFORMS.map((p) => p.id).join(", ")}
      --allow-private     allow localhost and private IPs (scan your own dev servers)
      --stdin             read a raw header dump from stdin instead of fetching
      --timeout <sec>     per-request timeout (default 10)
  -v, --verbose           also show advisory findings
  -h, --help              show this help

Exit codes
  0 all scans succeeded (and met --fail-under)
  1 a site scored below --fail-under
  2 a scan couldn't complete
`;

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      format: { type: "string", short: "f", default: "pretty" },
      "fail-under": { type: "string" },
      output: { type: "string", short: "o" },
      fix: { type: "string" },
      "allow-private": { type: "boolean", default: false },
      stdin: { type: "boolean", default: false },
      timeout: { type: "string", default: "10" },
      verbose: { type: "boolean", short: "v", default: false },
      help: { type: "boolean", short: "h", default: false },
      version: { type: "boolean", default: false },
    },
  });

  if (values.version) return void console.log("2.0.0");
  if (values.help || (!positionals.length && !values.stdin)) {
    console.log(HELP);
    process.exitCode = values.help ? 0 : 2;
    return;
  }
  const format = values.format as Format;
  if (!FORMATS.includes(format)) throw new Error(`--format must be one of ${FORMATS.join(", ")}`);
  const failUnder = values["fail-under"]?.toUpperCase() as Grade | undefined;
  if (failUnder && !GRADES.includes(failUnder)) throw new Error(`--fail-under must be a grade like A, B+ or C`);
  const fix = values.fix as Platform | undefined;
  if (fix && !PLATFORMS.some((p) => p.id === fix)) throw new Error(`--fix must be one of ${PLATFORMS.map((p) => p.id).join(", ")}`);

  const { exitCode } = await run({
    targets: positionals,
    format,
    failUnder,
    fix,
    output: values.output,
    allowPrivate: values["allow-private"]!,
    stdin: values.stdin ? await readStdin() : undefined,
    verbose: values.verbose!,
    timeoutMs: Math.max(1, Number(values.timeout) || 10) * 1000,
  });
  process.exitCode = exitCode;
}

main().catch((e) => {
  process.stderr.write(`sentinel-scan: ${e instanceof Error ? e.message : e}\n`);
  process.exitCode = 2;
});
