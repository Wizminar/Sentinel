/**
 * GitHub Action entry point. Maps action inputs (INPUT_* env vars) onto the
 * CLI runner, and exposes the grade and score as step outputs.
 */
import { appendFile, writeFile } from "node:fs/promises";
import type { Grade, Platform } from "@sentinel/core";
import { GRADES, render, run } from "./run.js";

const input = (name: string) => (process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] ?? "").trim();

async function main() {
  const targets = input("urls").split(/[\s,]+/).filter(Boolean);
  if (!targets.length) throw new Error("Set the `urls` input to at least one URL.");
  const failUnder = (input("fail-under").toUpperCase() || undefined) as Grade | undefined;
  if (failUnder && !GRADES.includes(failUnder)) throw new Error(`fail-under must be a grade like A, B+ or C, not "${failUnder}"`);
  const sarif = input("sarif-file");

  const result = await run({
    targets,
    format: "pretty",
    failUnder,
    allowPrivate: input("allow-private") === "true",
    fix: (input("fix") || undefined) as Platform | undefined,
    verbose: false,
    timeoutMs: 15000,
  });
  if (sarif && result.reports.length) {
    await writeFile(sarif, render(result.reports, { format: "sarif", verbose: false }) + "\n");
  }

  const first = result.reports[0];
  if (process.env.GITHUB_OUTPUT && first) {
    const worst = result.reports.reduce((a, b) => (GRADES.indexOf(b.grade) > GRADES.indexOf(a.grade) ? b : a));
    await appendFile(process.env.GITHUB_OUTPUT, `grade=${worst.grade}\nscore=${worst.score}\nreport=${JSON.stringify(result.reports.map((r) => ({ url: r.finalUrl, grade: r.grade, score: r.score })))}\n`);
  }
  process.exitCode = result.exitCode;
}

main().catch((e) => {
  process.stdout.write(`::error::${e instanceof Error ? e.message : e}\n`);
  process.exitCode = 2;
});
