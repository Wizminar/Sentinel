import type { Report, Status } from "@sentinel/core";

const useColor = !process.env.NO_COLOR && (process.stdout.isTTY || !!process.env.FORCE_COLOR);
const paint = (code: string) => (s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
export const c = {
  bold: paint("1"), dim: paint("2"), red: paint("31"), green: paint("32"),
  yellow: paint("33"), blue: paint("34"), gray: paint("90"),
};

const MARK: Record<Status, string> = { pass: c.green("✓"), warn: c.yellow("!"), fail: c.red("✗"), info: c.blue("i") };

function gradeColor(g: string) {
  return g.startsWith("A") ? c.green : g.startsWith("B") ? c.green : g.startsWith("C") ? c.yellow : c.red;
}

function wrap(text: string, width: number, indent: string): string {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let line = "";
  for (const w of words) {
    if ((line + " " + w).trim().length > width) { lines.push(line); line = w; } else line = (line + " " + w).trim();
  }
  if (line) lines.push(line);
  return lines.map((l, i) => (i ? indent : "") + l).join("\n");
}

export function pretty(r: Report, verbose = false): string {
  const width = Math.min(process.stdout.columns || 88, 100);
  const out: string[] = [];
  const g = gradeColor(r.grade);
  out.push("");
  out.push(`  ${g(c.bold(r.grade.padEnd(3)))} ${c.bold(r.finalUrl)}  ${c.gray(`${r.score}/100`)}`);
  if (r.redirects.length) out.push(`      ${c.gray(`via ${r.redirects.map((h) => `${h.status} ${h.url}`).join(" → ")}`)}`);
  if (r.cap) out.push(`      ${c.yellow(`capped at ${r.cap.grade}: ${r.cap.reason}`)}`);
  out.push("");
  for (const ch of r.checks) {
    const pts = ch.modifier === 0 ? "" : ch.modifier > 0 ? c.green(`+${ch.modifier}`) : c.red(String(ch.modifier));
    out.push(`  ${MARK[ch.status]} ${ch.title.padEnd(26)} ${ch.summary.padEnd(Math.max(10, width - 40))} ${pts}`.trimEnd());
    for (const f of ch.findings) {
      if (f.modifier === 0 && !verbose) continue;
      const tone = f.modifier > 0 ? c.green : f.severity === "critical" || f.severity === "high" ? c.red : f.severity === "medium" ? c.yellow : c.gray;
      out.push(`      ${tone("·")} ${c.dim(wrap(f.message, width - 10, "        "))}`);
    }
  }
  out.push("");
  out.push(c.gray(`  ${r.summary.pass} passed · ${r.summary.warn} warning${r.summary.warn === 1 ? "" : "s"} · ${r.summary.fail} failed · ${r.summary.info} advisory`));
  out.push("");
  return out.join("\n");
}
