/** Raw header input: one value, or several when a header was sent more than once. */
export type HeaderInput = Record<string, string | string[] | undefined>;

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** pass = good, warn = present but risky, fail = missing or broken, info = advisory only. */
export type Status = "pass" | "warn" | "fail" | "info";

export type CheckId =
  | "transport"
  | "csp"
  | "hsts"
  | "framing"
  | "content-type-options"
  | "referrer-policy"
  | "permissions-policy"
  | "cookies"
  | "cross-origin-isolation"
  | "cors"
  | "disclosure"
  | "legacy";

export interface Finding {
  /** Stable identifier, e.g. "csp.unsafe-inline". Used for SARIF rule ids and docs links. */
  id: string;
  severity: Severity;
  /** One sentence in plain English. */
  message: string;
  /** Points added to (positive) or removed from (negative) the score. */
  modifier: number;
  /** The exact header text that triggered the finding, when there is one. */
  evidence?: string;
}

export interface CheckResult {
  id: CheckId;
  title: string;
  /** Header names this check reads. */
  headers: string[];
  status: Status;
  /** What this check protects against, in plain words. */
  defends: string;
  /** One-line verdict shown next to the status. */
  summary: string;
  /** The raw value that was evaluated, if any. */
  value?: string;
  /** Sum of the finding modifiers after the check's own floor is applied. */
  modifier: number;
  findings: Finding[];
}

export interface RedirectHop {
  url: string;
  status: number;
}

export interface AnalyzeInput {
  /** URL that was requested. */
  url: string;
  /** URL that produced the final response after redirects. Defaults to `url`. */
  finalUrl?: string;
  /** Final HTTP status code, if known. */
  status?: number;
  headers: HeaderInput;
  /** Every hop before the final response, in order. */
  redirects?: RedirectHop[];
  /**
   * The Origin header the scanner sent while fetching, if any. Lets the CORS
   * check detect servers that reflect arbitrary origins.
   */
  probeOrigin?: string;
  /** Override the clock (tests). */
  now?: Date;
}

export type Grade = "A+" | "A" | "A-" | "B+" | "B" | "B-" | "C+" | "C" | "C-" | "D+" | "D" | "D-" | "F";

export interface Report {
  engine: string;
  url: string;
  finalUrl: string;
  status?: number;
  redirects: RedirectHop[];
  generatedAt: string;
  score: number;
  grade: Grade;
  /** Why the grade is lower than the score alone would give, if a cap applied. */
  cap?: { grade: Grade; reason: string };
  summary: { pass: number; warn: number; fail: number; info: number };
  checks: CheckResult[];
}
