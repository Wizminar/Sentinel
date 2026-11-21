import type { CheckResult, Grade } from "./types.js";

const SCALE: [number, Grade][] = [
  [100, "A+"], [90, "A"], [85, "A-"], [80, "B+"], [70, "B"], [65, "B-"],
  [60, "C+"], [50, "C"], [45, "C-"], [40, "D+"], [30, "D"], [25, "D-"],
];
const ORDER: Grade[] = ["A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "D-", "F"];

export function gradeFor(score: number): Grade {
  for (const [min, g] of SCALE) if (score >= min) return g;
  return "F";
}

/** Bonuses only count once a site is already strong, so extras can't paper over a missing defence. */
export const BONUS_THRESHOLD = 90;

export function scoreChecks(checks: CheckResult[]): number {
  let penalty = 0, bonus = 0;
  for (const c of checks) {
    // c.modifier is (floored penalties + bonuses); split it back apart.
    const pos = c.findings.reduce((n, f) => n + Math.max(0, f.modifier), 0);
    penalty += c.modifier - pos;
    bonus += pos;
  }
  const base = 100 + penalty;
  return Math.max(0, base >= BONUS_THRESHOLD ? base + bonus : base);
}

/** Hard ceilings: some failures make a high grade misleading whatever the arithmetic says. */
export function applyCaps(grade: Grade, checks: CheckResult[]): { grade: Grade; cap?: { grade: Grade; reason: string } } {
  const has = (id: string) => checks.some((c) => c.findings.some((f) => f.id === id));
  const caps: { grade: Grade; reason: string }[] = [];
  if (has("cors.reflect-credentials")) caps.push({ grade: "F", reason: "Any website can read logged-in users' data through CORS." });
  if (has("transport.plain-http")) caps.push({ grade: "D", reason: "The page isn't served over HTTPS." });

  let out = grade;
  let applied: { grade: Grade; reason: string } | undefined;
  for (const c of caps) {
    if (ORDER.indexOf(c.grade) > ORDER.indexOf(out)) {
      out = c.grade;
      applied = c;
    }
  }
  return applied ? { grade: out, cap: applied } : { grade: out };
}
