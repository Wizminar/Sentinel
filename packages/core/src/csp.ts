/**
 * Content-Security-Policy parser and evaluator.
 *
 * Follows CSP Level 3 parsing rules: policies are separated by ",", directives
 * by ";", directive names are case-insensitive, and only the first occurrence
 * of a directive counts. Source evaluation borrows the threat model of Google's
 * CSP Evaluator: what matters most is whether an attacker who can inject markup
 * can get script to execute.
 */

export type Directives = Map<string, string[]>;

export interface ParsedPolicy {
  directives: Directives;
  /** Directive names that appeared more than once (later copies are ignored). */
  duplicates: string[];
  /** Directive names not in the CSP spec (often typos like "scirpt-src"). */
  unknown: string[];
}

const KNOWN_DIRECTIVES = new Set([
  "default-src", "script-src", "script-src-elem", "script-src-attr", "style-src",
  "style-src-elem", "style-src-attr", "img-src", "font-src", "connect-src",
  "media-src", "object-src", "frame-src", "child-src", "worker-src",
  "manifest-src", "prefetch-src", "fenced-frame-src", "base-uri", "form-action",
  "frame-ancestors", "navigate-to", "sandbox", "report-uri", "report-to",
  "upgrade-insecure-requests", "block-all-mixed-content", "require-trusted-types-for",
  "trusted-types", "require-sri-for", "plugin-types", "referrer", "webrtc",
]);

export function parsePolicy(policy: string): ParsedPolicy {
  const directives: Directives = new Map();
  const duplicates: string[] = [];
  const unknown: string[] = [];
  for (const chunk of policy.split(";")) {
    const tokens = chunk.trim().split(/\s+/).filter(Boolean);
    const name = tokens.shift()?.toLowerCase();
    if (!name) continue;
    if (directives.has(name)) {
      duplicates.push(name);
      continue;
    }
    if (!KNOWN_DIRECTIVES.has(name)) unknown.push(name);
    directives.set(name, tokens);
  }
  return { directives, duplicates, unknown };
}

/** A header may carry several policies separated by commas; all are enforced. */
export function parseHeader(value: string): ParsedPolicy[] {
  return value
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean)
    .map(parsePolicy);
}

const FETCH_FALLBACK: Record<string, string[]> = {
  "script-src-elem": ["script-src", "default-src"],
  "script-src": ["default-src"],
  "object-src": ["default-src"],
  "style-src": ["default-src"],
  "frame-src": ["child-src", "default-src"],
  "worker-src": ["child-src", "script-src", "default-src"],
};

/** The source list that actually governs a directive, following CSP fallback rules. */
export function effectiveSources(d: Directives, directive: string): { from: string; sources: string[] } | null {
  const own = d.get(directive);
  if (own) return { from: directive, sources: own };
  for (const fb of FETCH_FALLBACK[directive] ?? []) {
    const s = d.get(fb);
    if (s) return { from: fb, sources: s };
  }
  return null;
}

const lower = (s: string) => s.toLowerCase();

export const isNonce = (s: string) => /^'nonce-[A-Za-z0-9+/_=-]+'$/.test(s);
export const isHash = (s: string) => /^'sha(256|384|512)-[A-Za-z0-9+/_=-]+'$/i.test(s);

export interface ScriptAnalysis {
  from: string;
  sources: string[];
  hasNonceOrHash: boolean;
  strictDynamic: boolean;
  /** 'unsafe-inline' that browsers will actually honour (no nonce/hash to cancel it). */
  unsafeInline: boolean;
  unsafeEval: boolean;
  wildcard: boolean;
  /** Scheme-only sources that allow scripts from anywhere on that scheme. */
  broadSchemes: string[];
  /** Hosts known to serve JSONP or user-controlled script, which bypass allowlists. */
  bypassHosts: string[];
}

/**
 * Hosts that serve JSONP endpoints, old AngularJS, or arbitrary user files.
 * An allowlist containing any of them can be bypassed to run attacker script.
 * A short, well-known subset of the list used by CSP Evaluator.
 */
const BYPASS_HOSTS = [
  "*.googleapis.com", "ajax.googleapis.com", "www.google.com", "*.google.com",
  "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "raw.githubusercontent.com",
  "*.githubusercontent.com", "*.cloudfront.net", "*.amazonaws.com", "*.firebaseapp.com",
  "*.appspot.com", "*.herokuapp.com", "accounts.google.com", "*.yandex.ru",
];

function hostOf(source: string): string {
  return source.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/[/:].*$/, "").toLowerCase();
}

export function analyzeScripts(d: Directives): ScriptAnalysis | null {
  const eff = effectiveSources(d, "script-src");
  if (!eff) return null;
  const s = eff.sources;
  const ls = s.map(lower);
  const hasNonceOrHash = s.some((x) => isNonce(x) || isHash(x));
  const strictDynamic = ls.includes("'strict-dynamic'");
  // With strict-dynamic, host allowlists and scheme sources are ignored by CSP3 browsers.
  const allowlistIgnored = strictDynamic && hasNonceOrHash;
  const broadSchemes = allowlistIgnored ? [] : ls.filter((x) => /^(https?|data|blob|filesystem):$/.test(x));
  const bypassHosts = allowlistIgnored ? [] : ls.filter((x) => BYPASS_HOSTS.includes(hostOf(x)));
  return {
    from: eff.from,
    sources: s,
    hasNonceOrHash,
    strictDynamic,
    unsafeInline: ls.includes("'unsafe-inline'") && !hasNonceOrHash,
    unsafeEval: ls.includes("'unsafe-eval'"),
    wildcard: !allowlistIgnored && ls.includes("*"),
    broadSchemes,
    bypassHosts: [...new Set(bypassHosts)],
  };
}
