import type { HeaderBag } from "../headers.js";
import type { CheckId, CheckResult, Finding, RedirectHop, Status } from "../types.js";

export interface CheckContext {
  headers: HeaderBag;
  /** The URL that produced the final response. */
  url: URL;
  /** The URL the user asked for. */
  requested: URL;
  redirects: RedirectHop[];
  probeOrigin?: string;
}

export type Check = (ctx: CheckContext) => CheckResult;

interface ResultBase {
  id: CheckId;
  title: string;
  headers: string[];
  defends: string;
  summary: string;
  status?: Status;
  value?: string;
  /** Lowest total this check can contribute, so one header can't sink the whole grade. */
  floor?: number;
}

const RANK: Record<Finding["severity"], number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** Status implied by the worst finding when a check doesn't set one explicitly. */
export function statusFrom(findings: Finding[]): Status {
  const worst = Math.max(0, ...findings.filter((f) => f.modifier <= 0).map((f) => RANK[f.severity]));
  if (worst >= 3) return "fail";
  if (worst >= 1) return "warn";
  return "pass";
}

export function result(base: ResultBase, findings: Finding[]): CheckResult {
  // The floor limits penalties only; bonuses are added on top.
  const neg = findings.reduce((n, f) => n + Math.min(0, f.modifier), 0);
  const pos = findings.reduce((n, f) => n + Math.max(0, f.modifier), 0);
  const modifier = Math.max(base.floor ?? -Infinity, neg) + pos;
  const { floor: _floor, ...rest } = base;
  return { ...rest, status: base.status ?? statusFrom(findings), modifier, findings };
}

export const isHttps = (u: URL) => u.protocol === "https:";
