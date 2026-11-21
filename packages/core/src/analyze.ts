import { contentTypeOptions } from "./checks/content-type-options.js";
import type { Check, CheckContext } from "./checks/context.js";
import { cookies } from "./checks/cookies.js";
import { cors } from "./checks/cors.js";
import { crossOriginIsolation } from "./checks/cross-origin-isolation.js";
import { csp } from "./checks/csp.js";
import { disclosure } from "./checks/disclosure.js";
import { framing } from "./checks/framing.js";
import { hsts } from "./checks/hsts.js";
import { legacy } from "./checks/legacy.js";
import { permissionsPolicy } from "./checks/permissions-policy.js";
import { referrerPolicy } from "./checks/referrer-policy.js";
import { transport } from "./checks/transport.js";
import { HeaderBag } from "./headers.js";
import { applyCaps, gradeFor, scoreChecks } from "./score.js";
import type { AnalyzeInput, Report } from "./types.js";

export const ENGINE_VERSION = "2.0.0";

/** Checks in report order: the ones that matter most come first. */
export const CHECKS: Check[] = [
  transport, csp, hsts, framing, contentTypeOptions, referrerPolicy,
  permissionsPolicy, cookies, cors, crossOriginIsolation, disclosure, legacy,
];

export function analyze(input: AnalyzeInput): Report {
  const requested = new URL(input.url);
  const url = new URL(input.finalUrl ?? input.url);
  const ctx: CheckContext = {
    headers: new HeaderBag(input.headers),
    url,
    requested,
    redirects: input.redirects ?? [],
    probeOrigin: input.probeOrigin,
  };
  const checks = CHECKS.map((check) => check(ctx));
  const score = scoreChecks(checks);
  const { grade, cap } = applyCaps(gradeFor(score), checks);
  const summary = { pass: 0, warn: 0, fail: 0, info: 0 };
  for (const c of checks) summary[c.status]++;
  return {
    engine: ENGINE_VERSION,
    url: requested.href,
    finalUrl: url.href,
    status: input.status,
    redirects: ctx.redirects,
    generatedAt: (input.now ?? new Date()).toISOString(),
    score,
    grade,
    ...(cap ? { cap } : {}),
    summary,
    checks,
  };
}


/**
 * Worst penalty and best bonus each check can contribute. Mirrors the
 * modifiers and floors in src/checks; a test keeps the two in sync.
 */
export const METHOD: { id: import("./types.js").CheckId; penalty: number; bonus: number }[] = [
  { id: "transport", penalty: -40, bonus: 0 },
  { id: "csp", penalty: -25, bonus: 5 },
  { id: "hsts", penalty: -20, bonus: 5 },
  { id: "framing", penalty: -20, bonus: 0 },
  { id: "content-type-options", penalty: -5, bonus: 0 },
  { id: "referrer-policy", penalty: -5, bonus: 5 },
  { id: "permissions-policy", penalty: -5, bonus: 0 },
  { id: "cookies", penalty: -40, bonus: 0 },
  { id: "cors", penalty: -40, bonus: 0 },
  { id: "cross-origin-isolation", penalty: 0, bonus: 5 },
  { id: "disclosure", penalty: -5, bonus: 0 },
  { id: "legacy", penalty: -5, bonus: 0 },
];
