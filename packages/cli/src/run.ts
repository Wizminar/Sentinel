import { lookup } from "node:dns/promises";
import { appendFile, readFile, writeFile } from "node:fs/promises";
import {
  analyze, fixesFor, isBlockedHost, normalizeTarget, parseRawHeaders, PLATFORMS, renderConfig,
  scanUrl, toMarkdown, toSarif, type Grade, type Platform, type Report,
} from "@sentinel/core";
import { c, pretty } from "./pretty.js";

export const GRADES: Grade[] = ["A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "D-", "F"];
export const FORMATS = ["pretty", "json", "markdown", "sarif"] as const;
export type Format = (typeof FORMATS)[number];

export interface RunOptions {
  targets: string[];
  format: Format;
  failUnder?: Grade;
  allowPrivate: boolean;
  output?: string;
  fix?: Platform;
  stdin?: string;
  verbose: boolean;
  timeoutMs: number;
}

export const meetsGrade = (grade: Grade, min: Grade) => GRADES.indexOf(grade) <= GRADES.indexOf(min);

/**
 * Resolve the hostname and refuse private addresses, so a public name that
 * points at 10.0.0.1 can't be used to probe an internal network.
 */
async function dnsGuard(url: URL) {
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const addrs = await lookup(host, { all: true }).catch(() => {
    throw new Error(`Couldn't resolve ${host}.`);
  });
  const bad = addrs.find((a) => isBlockedHost(a.family === 6 ? `[${a.address}]` : a.address));
  if (bad) throw new Error(`${host} resolves to a private address (${bad.address}). Pass --allow-private to scan your own internal servers.`);
}

export async function scanOne(target: string, o: Pick<RunOptions, "allowPrivate" | "timeoutMs">): Promise<Report> {
  const t = normalizeTarget(target, { allowPrivate: o.allowPrivate });
  if (!t.ok) throw new Error(t.error);
  const { report } = await scanUrl(t.url, {
    allowPrivate: o.allowPrivate,
    timeoutMs: o.timeoutMs,
    beforeHop: o.allowPrivate ? undefined : dnsGuard,
  });
  return report;
}

export function render(reports: Report[], o: Pick<RunOptions, "format" | "verbose">): string {
  switch (o.format) {
    case "json":
      return JSON.stringify(reports.length === 1 ? reports[0] : reports, null, 2);
    case "markdown":
      return reports.map(toMarkdown).join("\n\n---\n\n");
    case "sarif": {
      const runs = reports.flatMap((r) => toSarif(r).runs);
      return JSON.stringify({ ...toSarif(reports[0]!), runs }, null, 2);
    }
    default:
      return reports.map((r) => pretty(r, o.verbose)).join("\n");
  }
}

export interface RunResult {
  exitCode: number;
  reports: Report[];
  errors: { target: string; message: string }[];
}

export async function run(o: RunOptions): Promise<RunResult> {
  const reports: Report[] = [];
  const errors: RunResult["errors"] = [];

  if (o.stdin !== undefined) {
    // Offline mode: grade a header dump. The URL (if given) only sets the scheme for HTTPS-dependent checks.
    const t = o.targets[0] ? normalizeTarget(o.targets[0], { allowPrivate: true }) : null;
    const url = t?.ok ? t.url.href : "https://stdin.invalid/";
    reports.push(analyze({ url, headers: parseRawHeaders(o.stdin) }));
  } else {
    const settled = await Promise.allSettled(o.targets.map((t) => scanOne(t, o)));
    settled.forEach((s, i) => {
      if (s.status === "fulfilled") reports.push(s.value);
      else errors.push({ target: o.targets[i]!, message: s.reason instanceof Error ? s.reason.message : String(s.reason) });
    });
  }

  if (reports.length) {
    const text = render(reports, o);
    if (o.output) await writeFile(o.output, text + "\n");
    else process.stdout.write(text + "\n");
  }
  for (const e of errors) process.stderr.write(`${c.red("error")} ${e.target}: ${e.message}\n`);

  if (o.fix) {
    for (const r of reports) {
      const label = PLATFORMS.find((p) => p.id === o.fix)?.label ?? o.fix;
      process.stderr.write(`\n${c.bold(`Suggested ${label} config for ${r.finalUrl}`)}\n${renderConfig(o.fix, fixesFor(r))}\n`);
    }
  }

  // Inside GitHub Actions: write a job summary and inline annotations.
  if (process.env.GITHUB_STEP_SUMMARY && reports.length) {
    await appendFile(process.env.GITHUB_STEP_SUMMARY, reports.map(toMarkdown).join("\n\n") + "\n").catch(() => {});
  }
  if (process.env.GITHUB_ACTIONS === "true") {
    for (const r of reports) {
      for (const ch of r.checks) for (const f of ch.findings) {
        if (f.modifier >= 0) continue;
        const level = f.severity === "critical" || f.severity === "high" ? "error" : f.severity === "medium" ? "warning" : "notice";
        process.stderr.write(`::${level} title=${ch.title} (${r.finalUrl})::${f.message.replace(/\r?\n/g, " ")}\n`);
      }
    }
  }

  let exitCode = errors.length ? 2 : 0;
  if (o.failUnder) {
    const failing = reports.filter((r) => !meetsGrade(r.grade, o.failUnder!));
    for (const r of failing) process.stderr.write(`${c.red("✗")} ${r.finalUrl} scored ${r.grade}, below the required ${o.failUnder}\n`);
    if (failing.length) exitCode = 1;
  }
  return { exitCode, reports, errors };
}

export async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

export { readFile };
