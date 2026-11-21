// src/action.ts
import { appendFile as appendFile2, writeFile as writeFile2 } from "node:fs/promises";

// src/run.ts
import { lookup } from "node:dns/promises";
import { appendFile, readFile, writeFile } from "node:fs/promises";

// ../core/src/checks/context.ts
var RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
function statusFrom(findings) {
  const worst = Math.max(0, ...findings.filter((f) => f.modifier <= 0).map((f) => RANK[f.severity]));
  if (worst >= 3) return "fail";
  if (worst >= 1) return "warn";
  return "pass";
}
function result(base, findings) {
  const neg = findings.reduce((n, f) => n + Math.min(0, f.modifier), 0);
  const pos = findings.reduce((n, f) => n + Math.max(0, f.modifier), 0);
  const modifier = Math.max(base.floor ?? -Infinity, neg) + pos;
  const { floor: _floor, ...rest } = base;
  return { ...rest, status: base.status ?? statusFrom(findings), modifier, findings };
}
var isHttps = (u) => u.protocol === "https:";

// ../core/src/checks/content-type-options.ts
var contentTypeOptions = ({ headers }) => {
  const base = {
    id: "content-type-options",
    title: "X-Content-Type-Options",
    headers: ["x-content-type-options"],
    defends: "MIME sniffing that turns uploads into scripts"
  };
  const value = headers.first("x-content-type-options");
  if (!value) {
    return result({ ...base, summary: "Missing" }, [
      { id: "xcto.missing", severity: "medium", message: "Browsers may guess a file's type, so an uploaded text file can end up executed as script.", modifier: -5 }
    ]);
  }
  if (value.trim().toLowerCase() !== "nosniff") {
    return result({ ...base, summary: "Invalid value", value }, [
      { id: "xcto.invalid", severity: "medium", message: `The only valid value is "nosniff"; "${value}" is ignored.`, modifier: -5, evidence: value }
    ]);
  }
  return result({ ...base, summary: "nosniff", value }, []);
};

// ../core/src/checks/cookies.ts
function parseSetCookie(raw) {
  const [pair, ...attrs] = raw.split(";");
  const eq = pair?.indexOf("=") ?? -1;
  const name = (eq > 0 ? pair.slice(0, eq) : pair ?? "").trim();
  if (!name) return null;
  const c2 = { name, secure: false, httpOnly: false, raw };
  for (const a of attrs) {
    const [k = "", ...rest] = a.split("=");
    const key = k.trim().toLowerCase();
    const val = rest.join("=").trim();
    if (key === "secure") c2.secure = true;
    else if (key === "httponly") c2.httpOnly = true;
    else if (key === "samesite") c2.sameSite = val.toLowerCase();
    else if (key === "domain") c2.domain = val;
    else if (key === "path") c2.path = val;
  }
  return c2;
}
var SESSION = /(^|[_.-])(sess(ion)?|sid|auth|token|jwt|login|remember)([_.-]|$)|^(phpsessid|jsessionid|asp\.net_sessionid|connect\.sid|laravel_session|_session_id|session)$/i;
var looksLikeSession = (name) => SESSION.test(name);
var list = (names) => names.length > 3 ? `${names.slice(0, 3).join(", ")} and ${names.length - 3} more` : names.join(", ");
var cookies = ({ headers, url }) => {
  const base = {
    id: "cookies",
    title: "Cookies",
    headers: ["set-cookie"],
    defends: "Session theft and cross-site request forgery",
    floor: -40
  };
  const parsed = headers.all("set-cookie").map(parseSetCookie).filter((c2) => c2 !== null);
  if (!parsed.length) {
    return result({ ...base, summary: "No cookies set on this response", status: "info" }, []);
  }
  const f = [];
  const https = isHttps(url);
  const noSecure = parsed.filter((c2) => !c2.secure);
  const sessionNoSecure = noSecure.filter((c2) => looksLikeSession(c2.name));
  if (https && sessionNoSecure.length) {
    f.push({ id: "cookies.session-no-secure", severity: "high", message: `${list(sessionNoSecure.map((c2) => c2.name))} look${sessionNoSecure.length === 1 ? "s" : ""} like session cookies but lack Secure, so they can leak over any HTTP request.`, modifier: -20 });
  } else if (https && noSecure.length) {
    f.push({ id: "cookies.no-secure", severity: "medium", message: `${list(noSecure.map((c2) => c2.name))} lack${noSecure.length === 1 ? "s" : ""} the Secure flag and can be sent over plain HTTP.`, modifier: -10 });
  }
  const sessionNoHttpOnly = parsed.filter((c2) => looksLikeSession(c2.name) && !c2.httpOnly);
  if (sessionNoHttpOnly.length) {
    f.push({ id: "cookies.session-no-httponly", severity: "high", message: `${list(sessionNoHttpOnly.map((c2) => c2.name))} can be read by JavaScript, so a single XSS bug can steal the session. Add HttpOnly.`, modifier: -10 });
  }
  const noneNoSecure = parsed.filter((c2) => c2.sameSite === "none" && !c2.secure);
  if (noneNoSecure.length) {
    f.push({ id: "cookies.samesite-none-insecure", severity: "medium", message: `${list(noneNoSecure.map((c2) => c2.name))} use SameSite=None without Secure, so browsers reject them.`, modifier: -5 });
  }
  const prefixBad = parsed.filter((c2) => c2.name.startsWith("__Host-") && (!c2.secure || c2.domain !== void 0 || c2.path !== "/") || c2.name.startsWith("__Secure-") && !c2.secure);
  if (prefixBad.length) {
    f.push({ id: "cookies.prefix", severity: "medium", message: `${list(prefixBad.map((c2) => c2.name))} break the rules of their __Host-/__Secure- prefix, so browsers drop them.`, modifier: -5 });
  }
  const noSameSite = parsed.filter((c2) => c2.sameSite === void 0);
  if (noSameSite.length) {
    f.push({ id: "cookies.no-samesite", severity: "info", message: `${list(noSameSite.map((c2) => c2.name))} rely on the browser default (Lax). Set SameSite explicitly.`, modifier: 0 });
  }
  const bad = f.filter((x) => x.modifier < 0).length;
  const summary = bad ? `${parsed.length} cookie${parsed.length === 1 ? "" : "s"}, ${bad} issue${bad === 1 ? "" : "s"}` : `${parsed.length} cookie${parsed.length === 1 ? "" : "s"}, all flagged correctly`;
  return result({ ...base, summary, value: parsed.map((c2) => c2.raw).join("\n") }, f);
};

// ../core/src/checks/cors.ts
var cors = ({ headers, probeOrigin }) => {
  const base = {
    id: "cors",
    title: "CORS",
    headers: ["access-control-allow-origin", "access-control-allow-credentials"],
    defends: "Other sites reading your users' data"
  };
  const acao = headers.first("access-control-allow-origin")?.trim();
  const creds = headers.first("access-control-allow-credentials")?.trim().toLowerCase() === "true";
  if (!acao) {
    return result({ ...base, summary: "No cross-origin reads allowed" }, []);
  }
  const value = `${acao}${creds ? " (with credentials)" : ""}`;
  const f = [];
  if (probeOrigin && acao === probeOrigin) {
    f.push(creds ? { id: "cors.reflect-credentials", severity: "critical", message: "The server echoes back any Origin and allows credentials, so any website can read logged-in users' responses.", modifier: -40, evidence: value } : { id: "cors.reflect", severity: "high", message: "The server echoes back whatever Origin it receives, so every website is allowed to read this response.", modifier: -15, evidence: value });
  } else if (acao === "null") {
    f.push({ id: "cors.null", severity: "high", message: 'Allowing the "null" origin lets sandboxed iframes and data: URLs \u2014 which attackers control \u2014 read the response.', modifier: -15, evidence: value });
  } else if (acao === "*") {
    f.push(creds ? { id: "cors.wildcard-credentials", severity: "low", message: "* combined with credentials is rejected by browsers; this often means origin handling is broken elsewhere.", modifier: -2, evidence: value } : { id: "cors.wildcard", severity: "info", message: "Any site can read this response. Fine for public content; never for pages that show user data.", modifier: 0, evidence: value });
  }
  const summary = f[0]?.severity === "critical" || f[0]?.severity === "high" ? "Any origin can read responses" : acao === "*" ? "Public (*)" : `Allows ${acao}`;
  return result({ ...base, summary, value, status: f.length && f[0].severity === "info" ? "info" : void 0 }, f);
};

// ../core/src/checks/cross-origin-isolation.ts
var crossOriginIsolation = ({ headers }) => {
  const base = {
    id: "cross-origin-isolation",
    title: "Cross-origin isolation",
    headers: ["cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy"],
    defends: "Cross-site leaks and Spectre-style side channels"
  };
  const coop = headers.first("cross-origin-opener-policy")?.toLowerCase().split(";")[0]?.trim();
  const coep = headers.first("cross-origin-embedder-policy")?.toLowerCase().split(";")[0]?.trim();
  const corp = headers.first("cross-origin-resource-policy")?.toLowerCase().trim();
  const value = [
    coop && `COOP: ${coop}`,
    coep && `COEP: ${coep}`,
    corp && `CORP: ${corp}`
  ].filter(Boolean).join("\n") || void 0;
  const f = [];
  if (coop === "same-origin" || coop === "same-origin-allow-popups" || coop === "noopener-allow-popups") {
    f.push({ id: "isolation.coop", severity: "info", message: `COOP ${coop} cuts the link between this page and windows it didn't open.`, modifier: 5 });
  } else {
    f.push({ id: "isolation.no-coop", severity: "info", message: "Without Cross-Origin-Opener-Policy, a site that opens yours in a popup keeps a handle to it (cross-site leaks, tab-nabbing).", modifier: 0 });
  }
  const isolated = coop === "same-origin" && (coep === "require-corp" || coep === "credentialless");
  if (isolated) {
    f.push({ id: "isolation.full", severity: "info", message: "The page is cross-origin isolated, which also unlocks SharedArrayBuffer and precise timers.", modifier: 0 });
  }
  const summary = isolated ? "Fully cross-origin isolated" : coop && coop !== "unsafe-none" ? `COOP ${coop}` : "Not configured";
  return result({ ...base, summary, value, status: coop && coop !== "unsafe-none" ? "pass" : "info" }, f);
};

// ../core/src/csp.ts
var KNOWN_DIRECTIVES = /* @__PURE__ */ new Set([
  "default-src",
  "script-src",
  "script-src-elem",
  "script-src-attr",
  "style-src",
  "style-src-elem",
  "style-src-attr",
  "img-src",
  "font-src",
  "connect-src",
  "media-src",
  "object-src",
  "frame-src",
  "child-src",
  "worker-src",
  "manifest-src",
  "prefetch-src",
  "fenced-frame-src",
  "base-uri",
  "form-action",
  "frame-ancestors",
  "navigate-to",
  "sandbox",
  "report-uri",
  "report-to",
  "upgrade-insecure-requests",
  "block-all-mixed-content",
  "require-trusted-types-for",
  "trusted-types",
  "require-sri-for",
  "plugin-types",
  "referrer",
  "webrtc"
]);
function parsePolicy(policy) {
  const directives = /* @__PURE__ */ new Map();
  const duplicates = [];
  const unknown = [];
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
function parseHeader(value) {
  return value.split(",").map((p) => p.trim()).filter(Boolean).map(parsePolicy);
}
var FETCH_FALLBACK = {
  "script-src-elem": ["script-src", "default-src"],
  "script-src": ["default-src"],
  "object-src": ["default-src"],
  "style-src": ["default-src"],
  "frame-src": ["child-src", "default-src"],
  "worker-src": ["child-src", "script-src", "default-src"]
};
function effectiveSources(d, directive) {
  const own = d.get(directive);
  if (own) return { from: directive, sources: own };
  for (const fb of FETCH_FALLBACK[directive] ?? []) {
    const s = d.get(fb);
    if (s) return { from: fb, sources: s };
  }
  return null;
}
var lower = (s) => s.toLowerCase();
var isNonce = (s) => /^'nonce-[A-Za-z0-9+/_=-]+'$/.test(s);
var isHash = (s) => /^'sha(256|384|512)-[A-Za-z0-9+/_=-]+'$/i.test(s);
var BYPASS_HOSTS = [
  "*.googleapis.com",
  "ajax.googleapis.com",
  "www.google.com",
  "*.google.com",
  "cdnjs.cloudflare.com",
  "cdn.jsdelivr.net",
  "unpkg.com",
  "raw.githubusercontent.com",
  "*.githubusercontent.com",
  "*.cloudfront.net",
  "*.amazonaws.com",
  "*.firebaseapp.com",
  "*.appspot.com",
  "*.herokuapp.com",
  "accounts.google.com",
  "*.yandex.ru"
];
function hostOf(source) {
  return source.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/[/:].*$/, "").toLowerCase();
}
function analyzeScripts(d) {
  const eff = effectiveSources(d, "script-src");
  if (!eff) return null;
  const s = eff.sources;
  const ls = s.map(lower);
  const hasNonceOrHash = s.some((x) => isNonce(x) || isHash(x));
  const strictDynamic = ls.includes("'strict-dynamic'");
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
    bypassHosts: [...new Set(bypassHosts)]
  };
}

// ../core/src/checks/csp.ts
function scriptFindings(p) {
  const f = [];
  const s = analyzeScripts(p.directives);
  if (!s) {
    f.push({
      id: "csp.no-script-restriction",
      severity: "high",
      message: "The policy has no script-src or default-src, so it doesn't restrict where scripts load from.",
      modifier: -20
    });
    return f;
  }
  const ev = `${s.from} ${s.sources.join(" ")}`;
  if (s.unsafeInline) {
    f.push({
      id: "csp.unsafe-inline",
      severity: "high",
      message: "'unsafe-inline' lets injected <script> tags and event handlers run, which cancels most of CSP's XSS protection.",
      modifier: -20,
      evidence: ev
    });
  }
  if (s.wildcard) {
    f.push({
      id: "csp.wildcard",
      severity: "high",
      message: "A bare * allows scripts from any host on the internet.",
      modifier: -20,
      evidence: ev
    });
  }
  if (s.broadSchemes.length) {
    f.push({
      id: "csp.broad-scheme",
      severity: "high",
      message: `${s.broadSchemes.join(", ")} allows scripts from any URL with that scheme${s.broadSchemes.includes("data:") ? " \u2014 data: lets an attacker inline a whole script" : ""}.`,
      modifier: -15,
      evidence: ev
    });
  }
  if (s.unsafeEval) {
    f.push({
      id: "csp.unsafe-eval",
      severity: "medium",
      message: "'unsafe-eval' allows eval() and new Function(), turning string injection into code execution.",
      modifier: -10,
      evidence: ev
    });
  }
  if (s.bypassHosts.length) {
    f.push({
      id: "csp.bypassable-host",
      severity: "medium",
      message: `${s.bypassHosts.join(", ")} hosts JSONP or user-uploaded files that can be used to run attacker script past the allowlist.`,
      modifier: -5,
      evidence: ev
    });
  }
  if (s.hasNonceOrHash && s.strictDynamic && !s.unsafeEval) {
    f.push({
      id: "csp.strict",
      severity: "info",
      message: "Uses nonces or hashes with 'strict-dynamic' \u2014 the setup Google and OWASP recommend.",
      modifier: 5
    });
  }
  return f;
}
var penalty = (fs) => fs.reduce((n, x) => n + Math.min(0, x.modifier), 0);
var csp = ({ headers }) => {
  const base = {
    id: "csp",
    title: "Content-Security-Policy",
    headers: ["content-security-policy", "content-security-policy-report-only"],
    defends: "Cross-site scripting (XSS) and data injection",
    floor: -25
  };
  const enforced = headers.all("content-security-policy");
  const reportOnly = headers.joined("content-security-policy-report-only");
  if (!enforced.length) {
    const f2 = [reportOnly ? {
      id: "csp.report-only",
      severity: "high",
      message: "Only a Report-Only policy is set: violations are logged but nothing is blocked.",
      modifier: -25,
      evidence: reportOnly
    } : {
      id: "csp.missing",
      severity: "high",
      message: "No Content-Security-Policy, so any script an attacker manages to inject will run.",
      modifier: -25
    }];
    return result({ ...base, summary: reportOnly ? "Report-only \u2014 nothing is enforced" : "Missing", status: "fail", value: reportOnly }, f2);
  }
  const value = enforced.join(", ");
  const policies = enforced.flatMap(parseHeader);
  const f = [];
  const perPolicy = policies.map(scriptFindings);
  const best = perPolicy.reduce((a, b) => penalty(b) > penalty(a) ? b : a, perPolicy[0] ?? []);
  f.push(...best);
  const objectOk = policies.some((p) => {
    const o = effectiveSources(p.directives, "object-src");
    return o !== null && o.sources.length === 1 && o.sources[0].toLowerCase() === "'none'";
  });
  if (!objectOk) {
    f.push({
      id: "csp.object-src",
      severity: "medium",
      message: "object-src isn't 'none', so plugin content (<object>, <embed>) can be used to run script.",
      modifier: -5
    });
  }
  if (!policies.some((p) => p.directives.has("base-uri"))) {
    f.push({
      id: "csp.base-uri",
      severity: "low",
      message: "No base-uri, so an injected <base> tag can point relative script URLs at an attacker's server.",
      modifier: -2
    });
  }
  for (const p of policies) {
    for (const name of p.unknown) {
      f.push({ id: "csp.unknown-directive", severity: "info", message: `"${name}" isn't a CSP directive \u2014 browsers ignore it. Typo?`, modifier: 0, evidence: name });
    }
    for (const name of p.duplicates) {
      f.push({ id: "csp.duplicate-directive", severity: "info", message: `"${name}" appears twice; browsers ignore every copy after the first.`, modifier: 0, evidence: name });
    }
  }
  const blocking = f.filter((x) => x.modifier < 0 && (x.severity === "high" || x.severity === "critical"));
  const summary = blocking.length ? "Set, but scripts can still be injected" : f.some((x) => x.id === "csp.strict") ? "Strict, nonce-based policy" : f.some((x) => x.modifier < 0) ? "Set, with gaps" : "Restricts script sources";
  return result({ ...base, summary, value }, f);
};

// ../core/src/checks/disclosure.ts
var LEAKY = ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-runtime", "x-drupal-cache", "x-varnish-version"];
var disclosure = ({ headers }) => {
  const base = {
    id: "disclosure",
    title: "Information disclosure",
    headers: ["server", ...LEAKY],
    defends: "Attackers matching your stack to known CVEs",
    floor: -5
  };
  const f = [];
  const server = headers.first("server");
  if (server && /\d+(\.\d+)+/.test(server)) {
    f.push({ id: "disclosure.server-version", severity: "low", message: `The Server header reveals an exact version (${server}), which makes it easy to look up known vulnerabilities.`, modifier: -2, evidence: `server: ${server}` });
  }
  for (const h of LEAKY) {
    const v = headers.first(h);
    if (v) f.push({ id: `disclosure.${h}`, severity: "low", message: `${h} announces the software behind the site (${v}). Remove it.`, modifier: -2, evidence: `${h}: ${v}` });
  }
  const value = f.map((x) => x.evidence).join("\n") || void 0;
  return result({ ...base, summary: f.length ? `${f.length} header${f.length === 1 ? "" : "s"} reveal the stack` : "No software versions exposed", value }, f);
};

// ../core/src/checks/framing.ts
var framing = ({ headers }) => {
  const base = {
    id: "framing",
    title: "Frame protection",
    headers: ["x-frame-options", "content-security-policy"],
    defends: "Clickjacking through hidden iframes"
  };
  const xfo = headers.first("x-frame-options");
  const csp2 = headers.joined("content-security-policy");
  const ancestors = csp2 ? parseHeader(csp2).map((p) => p.directives.get("frame-ancestors")).find((d) => d !== void 0) : void 0;
  if (ancestors) {
    const value = `frame-ancestors ${ancestors.join(" ")}`;
    const open = ancestors.some((s) => s === "*" || /^https?:$/i.test(s));
    const f2 = open ? [{ id: "framing.ancestors-open", severity: "high", message: "frame-ancestors allows any site to embed this page.", modifier: -20, evidence: value }] : [];
    if (xfo && !open) {
      f2.push({ id: "framing.both", severity: "info", message: "X-Frame-Options is also set. Modern browsers use frame-ancestors and ignore it; keeping both covers old browsers.", modifier: 0 });
    }
    return result({ ...base, summary: open ? "Any site can frame this page" : "Restricted by CSP frame-ancestors", value }, f2);
  }
  if (!xfo) {
    return result({ ...base, summary: "Missing", status: "fail" }, [
      { id: "framing.missing", severity: "high", message: "Any site can load this page in an invisible iframe and trick users into clicking it.", modifier: -20 }
    ]);
  }
  const v = xfo.trim().toLowerCase();
  if (v === "deny" || v === "sameorigin") {
    return result({ ...base, summary: v === "deny" ? "Framing denied" : "Same-origin framing only", value: xfo }, []);
  }
  const f = v.startsWith("allow-from") ? { id: "framing.allow-from", severity: "high", message: "ALLOW-FROM is obsolete and every current browser ignores it, so the page can be framed anywhere. Use CSP frame-ancestors.", modifier: -20, evidence: xfo } : { id: "framing.invalid", severity: "high", message: `"${xfo}" isn't a valid X-Frame-Options value, so browsers ignore it.`, modifier: -20, evidence: xfo };
  return result({ ...base, summary: "Set, but ignored by browsers", value: xfo }, [f]);
};

// ../core/src/checks/hsts.ts
var SIX_MONTHS = 15552e3;
var ONE_YEAR = 31536e3;
var hsts = ({ headers, url }) => {
  const base = {
    id: "hsts",
    title: "Strict-Transport-Security",
    headers: ["strict-transport-security"],
    defends: "HTTPS downgrade and SSL-stripping attacks"
  };
  if (!isHttps(url)) {
    return result({ ...base, summary: "Not applicable over plain HTTP", status: "info" }, [
      { id: "hsts.not-applicable", severity: "info", message: "Browsers ignore HSTS on plain-HTTP responses. Serve the site over HTTPS first.", modifier: 0 }
    ]);
  }
  const all = headers.all("strict-transport-security");
  const value = all[0];
  if (!value) {
    return result({ ...base, summary: "Missing", status: "fail" }, [
      { id: "hsts.missing", severity: "high", message: "Without HSTS, a first visit over http:// can be intercepted and kept on plain HTTP by an attacker.", modifier: -20 }
    ]);
  }
  const parts = value.split(";").map((p) => p.trim().toLowerCase()).filter(Boolean);
  const maxAgePart = parts.find((p) => p.startsWith("max-age"));
  const m = maxAgePart ? /^max-age\s*=\s*"?(\d+)"?$/.exec(maxAgePart) : null;
  const subdomains = parts.includes("includesubdomains");
  const preload = parts.includes("preload");
  const f = [];
  if (!m) {
    f.push({ id: "hsts.invalid", severity: "high", message: "The header has no valid max-age, so browsers ignore it.", modifier: -20, evidence: value });
    return result({ ...base, summary: "Invalid", value }, f);
  }
  const age = Number(m[1]);
  const days = Math.round(age / 86400);
  if (age === 0) {
    f.push({ id: "hsts.zero", severity: "high", message: "max-age=0 tells browsers to forget the HSTS policy.", modifier: -20, evidence: value });
  } else if (age < SIX_MONTHS) {
    f.push({ id: "hsts.short", severity: "medium", message: `max-age is ${days} day${days === 1 ? "" : "s"}. Use at least 180 days; one year is the norm.`, modifier: -10, evidence: value });
  }
  if (!subdomains) {
    f.push({ id: "hsts.no-subdomains", severity: "info", message: "Subdomains aren't covered. Add includeSubDomains once every subdomain serves HTTPS.", modifier: 0 });
  }
  if (preload && subdomains && age >= ONE_YEAR) {
    f.push({ id: "hsts.preload-ready", severity: "info", message: "Meets the requirements for the browser HSTS preload list.", modifier: 5 });
  }
  if (all.length > 1) {
    f.push({ id: "hsts.duplicate", severity: "info", message: `Sent ${all.length} times; browsers only use the first.`, modifier: 0 });
  }
  const summary = age === 0 ? "Disabled (max-age=0)" : age < SIX_MONTHS ? `Set, but only ${days} days` : preload && subdomains ? "Long-lived and preload-ready" : `Enforced for ${days} days`;
  return result({ ...base, summary, value }, f);
};

// ../core/src/checks/legacy.ts
var legacy = ({ headers }) => {
  const base = {
    id: "legacy",
    title: "Deprecated headers",
    headers: ["x-xss-protection", "public-key-pins", "expect-ct"],
    defends: "Configuration drift from retired browser features"
  };
  const f = [];
  const xxp = headers.first("x-xss-protection");
  if (xxp && xxp.trim().startsWith("1")) {
    f.push({ id: "legacy.xss-protection", severity: "low", message: "X-XSS-Protection turned on a filter no current browser ships; in old ones it could be abused to leak data. Set it to 0 or remove it.", modifier: 0, evidence: xxp });
  }
  const hpkp = headers.first("public-key-pins");
  if (hpkp) {
    f.push({ id: "legacy.hpkp", severity: "medium", message: "Public-Key-Pins was removed from browsers after it locked sites out when certificates changed. Remove it.", modifier: -5, evidence: hpkp });
  }
  const ect = headers.first("expect-ct");
  if (ect) {
    f.push({ id: "legacy.expect-ct", severity: "info", message: "Expect-CT is obsolete now that Certificate Transparency is always enforced. Safe to remove.", modifier: 0, evidence: ect });
  }
  const value = f.map((x) => x.evidence).join("\n") || void 0;
  return result({ ...base, summary: f.length ? `${f.length} retired header${f.length === 1 ? "" : "s"} still sent` : "None in use", value }, f);
};

// ../core/src/checks/permissions-policy.ts
var POWERFUL = ["camera", "microphone", "geolocation", "payment", "usb", "serial", "bluetooth", "hid", "display-capture", "midi"];
function parsePermissionsPolicy(value) {
  const out = /* @__PURE__ */ new Map();
  const re = /([a-z0-9-]+)\s*=\s*(\([^)]*\)|\*|[^,\s]+)/gi;
  let m;
  while (m = re.exec(value)) {
    const feature = m[1].toLowerCase();
    const raw = m[2].replace(/^\(|\)$/g, "").trim();
    out.set(feature, raw ? raw.split(/\s+/) : []);
  }
  return out;
}
var permissionsPolicy = ({ headers }) => {
  const base = {
    id: "permissions-policy",
    title: "Permissions-Policy",
    headers: ["permissions-policy", "feature-policy"],
    defends: "Embedded content using camera, mic, location"
  };
  const value = headers.joined("permissions-policy");
  const legacy2 = headers.joined("feature-policy");
  if (!value) {
    const f2 = legacy2 ? [{ id: "permissions.feature-policy", severity: "low", message: "Only the deprecated Feature-Policy header is set. Browsers now read Permissions-Policy, which uses a different syntax.", modifier: -3, evidence: legacy2 }] : [{ id: "permissions.missing", severity: "low", message: "Embedded iframes can ask for powerful features like the camera or location. Turn off the ones you don't use.", modifier: -3 }];
    return result({ ...base, summary: legacy2 ? "Deprecated Feature-Policy only" : "Missing", value: legacy2 }, f2);
  }
  const parsed = parsePermissionsPolicy(value);
  if (!parsed.size) {
    return result({ ...base, summary: "Unparseable", value }, [
      { id: "permissions.invalid", severity: "low", message: "The value doesn't follow the structured-header syntax (feature=(allowlist)), so browsers ignore it.", modifier: -3, evidence: value }
    ]);
  }
  const open = POWERFUL.filter((p) => parsed.get(p)?.includes("*"));
  const f = open.length ? [{ id: "permissions.wildcard", severity: "medium", message: `${open.join(", ")} ${open.length === 1 ? "is" : "are"} allowed for every origin, including third-party iframes.`, modifier: -5, evidence: value }] : [];
  const disabled = [...parsed.values()].filter((v) => v.length === 0).length;
  return result({ ...base, summary: `${parsed.size} feature${parsed.size === 1 ? "" : "s"} configured, ${disabled} disabled`, value }, f);
};

// ../core/src/checks/referrer-policy.ts
var VALID = /* @__PURE__ */ new Set([
  "no-referrer",
  "no-referrer-when-downgrade",
  "origin",
  "origin-when-cross-origin",
  "same-origin",
  "strict-origin",
  "strict-origin-when-cross-origin",
  "unsafe-url"
]);
var STRICT = /* @__PURE__ */ new Set(["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"]);
var referrerPolicy = ({ headers }) => {
  const base = {
    id: "referrer-policy",
    title: "Referrer-Policy",
    headers: ["referrer-policy"],
    defends: "Leaking private URLs to other sites"
  };
  const value = headers.joined("referrer-policy");
  const effective = value?.split(",").map((t) => t.trim().toLowerCase()).filter((t) => VALID.has(t)).pop();
  if (!effective) {
    return result({ ...base, summary: value ? "Unrecognised value" : "Not set \u2014 browser default applies", status: "info", value }, [
      { id: "referrer.missing", severity: "info", message: "Modern browsers default to strict-origin-when-cross-origin, which is safe. Set it explicitly so older browsers behave the same.", modifier: 0 }
    ]);
  }
  const f = [];
  if (effective === "unsafe-url") {
    f.push({ id: "referrer.unsafe-url", severity: "medium", message: "unsafe-url sends the full URL \u2014 path and query string included \u2014 to every site you link to, even over HTTP.", modifier: -5, evidence: effective });
  } else if (effective === "no-referrer-when-downgrade") {
    f.push({ id: "referrer.downgrade", severity: "low", message: "Full URLs, including any tokens in the query string, are sent to every other HTTPS site.", modifier: -3, evidence: effective });
  } else if (STRICT.has(effective)) {
    f.push({ id: "referrer.strict", severity: "info", message: `${effective} keeps paths and query strings private.`, modifier: 5 });
  }
  return result({ ...base, summary: effective, value }, f);
};

// ../core/src/checks/transport.ts
var transport = ({ url, requested, redirects }) => {
  const f = [];
  const base = {
    id: "transport",
    title: "HTTPS",
    headers: ["location"],
    defends: "Eavesdropping and tampering in transit"
  };
  if (!isHttps(url)) {
    f.push({
      id: "transport.plain-http",
      severity: "critical",
      message: "The page is served over plain HTTP, so anyone on the network can read or change it.",
      modifier: -40
    });
    return result({ ...base, summary: "Served over plain HTTP", status: "fail" }, f);
  }
  const hops = redirects.map((r) => {
    try {
      return new URL(r.url);
    } catch {
      return null;
    }
  }).filter((u) => u !== null);
  const chain = [...hops, url];
  for (let i = 1; i < chain.length; i++) {
    const prev = chain[i - 1], next = chain[i];
    if (isHttps(prev) && !isHttps(next)) {
      f.push({
        id: "transport.downgrade",
        severity: "high",
        message: `A redirect drops from HTTPS to HTTP (${prev.host} \u2192 ${next.host}).`,
        modifier: -20,
        evidence: next.href
      });
      break;
    }
  }
  if (!isHttps(requested)) {
    const first = chain[1] ?? url;
    if (first.host !== requested.host) {
      f.push({
        id: "transport.redirect-host",
        severity: "low",
        message: `The first redirect from http://${requested.host} goes to a different host, so that host never receives an HSTS header over HTTPS.`,
        modifier: -5,
        evidence: first.href
      });
    }
  }
  const summary = !isHttps(requested) ? "Redirects HTTP to HTTPS" : "Served over HTTPS";
  return result({ ...base, summary }, f);
};

// ../core/src/headers.ts
var HeaderBag = class {
  map = /* @__PURE__ */ new Map();
  constructor(input2 = {}) {
    for (const [rawKey, rawValue] of Object.entries(input2)) {
      if (rawValue === void 0) continue;
      const key = rawKey.trim().toLowerCase();
      if (!key) continue;
      const values = Array.isArray(rawValue) ? rawValue : [rawValue];
      const list2 = this.map.get(key) ?? [];
      for (const v of values) list2.push(String(v).trim());
      this.map.set(key, list2);
    }
  }
  has(name) {
    return this.map.has(name.toLowerCase());
  }
  /** Every value sent for this header, in order. */
  all(name) {
    return this.map.get(name.toLowerCase()) ?? [];
  }
  /** The first value, which is what browsers honour for most single-value headers. */
  first(name) {
    return this.all(name)[0];
  }
  /** All values joined the way a browser would combine repeated headers. */
  joined(name) {
    const v = this.all(name);
    return v.length ? v.join(", ") : void 0;
  }
  names() {
    return [...this.map.keys()];
  }
  get size() {
    return this.map.size;
  }
};
function parseRawHeaders(text) {
  const blocks = text.split(/\r?\n\s*\r?\n/).filter((b) => b.trim());
  const last = blocks[blocks.length - 1] ?? "";
  const out = {};
  for (const rawLine of last.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || /^HTTP\//i.test(line)) continue;
    const i = line.indexOf(":");
    if (i < 1) continue;
    const key = line.slice(0, i).trim().toLowerCase();
    const val = line.slice(i + 1).trim();
    (out[key] ??= []).push(val);
  }
  return out;
}

// ../core/src/score.ts
var SCALE = [
  [100, "A+"],
  [90, "A"],
  [85, "A-"],
  [80, "B+"],
  [70, "B"],
  [65, "B-"],
  [60, "C+"],
  [50, "C"],
  [45, "C-"],
  [40, "D+"],
  [30, "D"],
  [25, "D-"]
];
var ORDER = ["A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "D-", "F"];
function gradeFor(score) {
  for (const [min, g] of SCALE) if (score >= min) return g;
  return "F";
}
var BONUS_THRESHOLD = 90;
function scoreChecks(checks) {
  let penalty2 = 0, bonus = 0;
  for (const c2 of checks) {
    const pos = c2.findings.reduce((n, f) => n + Math.max(0, f.modifier), 0);
    penalty2 += c2.modifier - pos;
    bonus += pos;
  }
  const base = 100 + penalty2;
  return Math.max(0, base >= BONUS_THRESHOLD ? base + bonus : base);
}
function applyCaps(grade, checks) {
  const has = (id) => checks.some((c2) => c2.findings.some((f) => f.id === id));
  const caps = [];
  if (has("cors.reflect-credentials")) caps.push({ grade: "F", reason: "Any website can read logged-in users' data through CORS." });
  if (has("transport.plain-http")) caps.push({ grade: "D", reason: "The page isn't served over HTTPS." });
  let out = grade;
  let applied;
  for (const c2 of caps) {
    if (ORDER.indexOf(c2.grade) > ORDER.indexOf(out)) {
      out = c2.grade;
      applied = c2;
    }
  }
  return applied ? { grade: out, cap: applied } : { grade: out };
}

// ../core/src/analyze.ts
var ENGINE_VERSION = "2.0.0";
var CHECKS = [
  transport,
  csp,
  hsts,
  framing,
  contentTypeOptions,
  referrerPolicy,
  permissionsPolicy,
  cookies,
  cors,
  crossOriginIsolation,
  disclosure,
  legacy
];
function analyze(input2) {
  const requested = new URL(input2.url);
  const url = new URL(input2.finalUrl ?? input2.url);
  const ctx = {
    headers: new HeaderBag(input2.headers),
    url,
    requested,
    redirects: input2.redirects ?? [],
    probeOrigin: input2.probeOrigin
  };
  const checks = CHECKS.map((check) => check(ctx));
  const score = scoreChecks(checks);
  const { grade, cap } = applyCaps(gradeFor(score), checks);
  const summary = { pass: 0, warn: 0, fail: 0, info: 0 };
  for (const c2 of checks) summary[c2.status]++;
  return {
    engine: ENGINE_VERSION,
    url: requested.href,
    finalUrl: url.href,
    status: input2.status,
    redirects: ctx.redirects,
    generatedAt: (input2.now ?? /* @__PURE__ */ new Date()).toISOString(),
    score,
    grade,
    ...cap ? { cap } : {},
    summary,
    checks
  };
}

// ../core/src/remediation.ts
var PLATFORMS = [
  { id: "nginx", label: "nginx" },
  { id: "apache", label: "Apache" },
  { id: "caddy", label: "Caddy" },
  { id: "express", label: "Express" },
  { id: "vercel", label: "Vercel" },
  { id: "netlify", label: "Netlify" },
  { id: "cloudflare", label: "Cloudflare Pages" }
];
var RECOMMENDED = {
  csp: [{
    header: "Content-Security-Policy",
    value: "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'; upgrade-insecure-requests",
    note: "Start in Content-Security-Policy-Report-Only, watch for violations, then enforce. For inline scripts, switch to nonces with 'strict-dynamic'."
  }],
  hsts: [{ header: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains", note: "Add '; preload' and submit to hstspreload.org once every subdomain is on HTTPS." }],
  framing: [{ header: "X-Frame-Options", value: "DENY", note: "Also covered by CSP frame-ancestors, which modern browsers prefer." }],
  "content-type-options": [{ header: "X-Content-Type-Options", value: "nosniff" }],
  "referrer-policy": [{ header: "Referrer-Policy", value: "strict-origin-when-cross-origin" }],
  "permissions-policy": [{ header: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()" }],
  "cross-origin-isolation": [{ header: "Cross-Origin-Opener-Policy", value: "same-origin", note: "Use same-origin-allow-popups if you rely on OAuth or payment popups." }],
  legacy: [{ header: "X-XSS-Protection", value: "0" }]
};
function fixesFor(report) {
  const out = [];
  for (const c2 of report.checks) {
    if (c2.status === "pass") continue;
    if (c2.id === "cross-origin-isolation" && c2.status !== "info") continue;
    if (c2.id === "legacy" && !c2.findings.some((f) => f.id === "legacy.xss-protection")) continue;
    out.push(...RECOMMENDED[c2.id] ?? []);
  }
  return out;
}
var q = (s) => s.replace(/"/g, '\\"');
function renderConfig(platform, fixes) {
  if (!fixes.length) return "# Nothing to add \u2014 every header check passed.";
  switch (platform) {
    case "nginx":
      return ["# inside your server { } block", ...fixes.map((f) => `add_header ${f.header} "${q(f.value)}" always;`)].join("\n");
    case "apache":
      return ["# .htaccess or <VirtualHost> (needs mod_headers)", ...fixes.map((f) => `Header always set ${f.header} "${q(f.value)}"`)].join("\n");
    case "caddy":
      return ["header {", ...fixes.map((f) => `	${f.header} "${q(f.value)}"`), "}"].join("\n");
    case "express":
      return [
        "app.use((req, res, next) => {",
        ...fixes.map((f) => `  res.setHeader("${f.header}", "${q(f.value)}");`),
        "  next();",
        "});",
        'app.disable("x-powered-by");'
      ].join("\n");
    case "netlify":
    case "cloudflare":
      return ["# _headers", "/*", ...fixes.map((f) => `  ${f.header}: ${f.value}`)].join("\n");
    case "vercel":
      return JSON.stringify({
        headers: [{ source: "/(.*)", headers: fixes.map((f) => ({ key: f.header, value: f.value })) }]
      }, null, 2);
  }
}

// ../core/src/format.ts
var ICON = { pass: "\u2705", warn: "\u26A0\uFE0F", fail: "\u274C", info: "\u2139\uFE0F" };
function toMarkdown(r) {
  const out = [];
  out.push(`## Sentinel: ${r.grade} (${r.score}/100) \u2014 ${r.finalUrl}`, "");
  if (r.cap) out.push(`> Grade capped at **${r.cap.grade}**: ${r.cap.reason}`, "");
  out.push("| | Check | Result | Points |", "|---|---|---|---:|");
  for (const c2 of r.checks) {
    out.push(`| ${ICON[c2.status]} | ${c2.title} | ${c2.summary.replace(/\|/g, "\\|")} | ${c2.modifier > 0 ? "+" : ""}${c2.modifier} |`);
  }
  const issues = r.checks.flatMap((c2) => c2.findings.filter((f) => f.modifier < 0).map((f) => `- **${c2.title}:** ${f.message}`));
  if (issues.length) out.push("", "### What to fix", "", ...issues);
  const fixes = fixesFor(r);
  if (fixes.length) out.push("", "<details><summary>nginx config</summary>", "", "```nginx", renderConfig("nginx", fixes), "```", "", "</details>");
  out.push("", `<sub>Generated by Sentinel ${r.engine} at ${r.generatedAt}</sub>`);
  return out.join("\n");
}
var SARIF_LEVEL = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note"
};
function toSarif(r) {
  const findings = r.checks.flatMap((c2) => c2.findings.filter((f) => f.modifier < 0).map((f) => ({ c: c2, f })));
  const rules = [...new Map(findings.map(({ c: c2, f }) => [f.id, {
    id: f.id,
    name: f.id.replace(/[^a-z0-9]+/gi, "_"),
    shortDescription: { text: `${c2.title}: ${f.message}` },
    helpUri: "https://github.com/Wizminar/Sentinel#checks",
    properties: { tags: ["security", "http-headers"], "security-severity": { critical: "9.5", high: "7.5", medium: "5.0", low: "3.0", info: "0.0" }[f.severity] }
  }])).values()];
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "Sentinel", version: r.engine, informationUri: "https://github.com/Wizminar/Sentinel", rules } },
      results: findings.map(({ f }) => ({
        ruleId: f.id,
        level: SARIF_LEVEL[f.severity],
        message: { text: f.message + (f.evidence ? ` Evidence: ${f.evidence}` : "") },
        locations: [{ physicalLocation: { artifactLocation: { uri: r.finalUrl } } }]
      }))
    }]
  };
}

// ../core/src/target.ts
var ALLOWED_PORTS = /* @__PURE__ */ new Set(["", "80", "443", "8080", "8443"]);
function normalizeTarget(raw, opts = {}) {
  let s = (raw ?? "").trim();
  if (!s) return { ok: false, error: "Enter a URL to scan." };
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = "https://" + s;
  let url;
  try {
    url = new URL(s);
  } catch {
    return { ok: false, error: "That isn't a valid URL. Try something like example.com." };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return { ok: false, error: "Only http and https URLs can be scanned." };
  if (url.username || url.password) return { ok: false, error: "Remove the username and password from the URL." };
  if (opts.allowPrivate) {
    url.hash = "";
    return { ok: true, url };
  }
  if (!ALLOWED_PORTS.has(url.port)) return { ok: false, error: "Only ports 80, 443, 8080 and 8443 can be scanned." };
  if (!url.hostname.includes(".") && !url.hostname.startsWith("[")) return { ok: false, error: "Use a full domain name, like example.com." };
  if (isBlockedHost(url.hostname)) return { ok: false, error: "Private, local and internal addresses can't be scanned." };
  url.hash = "";
  return { ok: true, url };
}
function ipv4(host) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  return parts.every((n) => n <= 255) ? parts : null;
}
function blockedV4([a, b]) {
  if (a === void 0 || b === void 0) return true;
  return a === 0 || a === 10 || a === 127 || a >= 224 || a === 100 && b >= 64 && b <= 127 || // carrier-grade NAT
  a === 169 && b === 254 || // link-local, cloud metadata
  a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168 || a === 192 && b === 0 || a === 198 && (b === 18 || b === 19);
}
function isBlockedHost(hostname) {
  const h = hostname.toLowerCase().replace(/\.$/, "");
  if (h === "localhost" || /\.(localhost|local|internal|intranet|lan|home\.arpa)$/.test(h)) return true;
  if (h === "metadata.google.internal" || h === "metadata") return true;
  const v4 = ipv4(h);
  if (v4) return blockedV4(v4);
  if (h.startsWith("[") || h.includes(":")) {
    const v6 = h.replace(/^\[|\]$/g, "");
    if (v6 === "::" || v6 === "::1") return true;
    if (/^f[cd]/.test(v6) || /^fe[89ab]/.test(v6)) return true;
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(v6);
    if (mapped) return blockedV4(ipv4(mapped[1]) ?? []);
    if (/^::ffff:[0-9a-f]{1,4}:[0-9a-f]{1,4}$/.test(v6)) {
      const [hi, lo] = v6.slice(7).split(":").map((x) => parseInt(x, 16));
      return blockedV4([hi >> 8, hi & 255, lo >> 8, lo & 255]);
    }
  }
  return false;
}

// ../core/src/fetch-chain.ts
var PROBE_ORIGIN = "https://sentinel-cors-probe.invalid";
var MAX_HOPS = 6;
var HOP_TIMEOUT_MS = 8e3;
var ScanError = class extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
};
async function fetchChain(start, opts = {}) {
  const fetcher = opts.fetcher ?? fetch;
  const timeout = opts.timeoutMs ?? HOP_TIMEOUT_MS;
  const t0 = Date.now();
  const redirects = [];
  let url = start;
  for (let hop = 0; hop <= MAX_HOPS; hop++) {
    await opts.beforeHop?.(url);
    let res;
    try {
      res = await fetcher(url.href, {
        method: "GET",
        redirect: "manual",
        signal: AbortSignal.timeout(timeout),
        headers: {
          "User-Agent": opts.userAgent ?? "Mozilla/5.0 (compatible; SentinelScanner/2.0; +https://github.com/Wizminar/Sentinel)",
          Accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
          Origin: PROBE_ORIGIN
        }
      });
    } catch (e) {
      const msg = e instanceof Error && e.name === "TimeoutError" ? `${url.host} didn't respond within ${timeout / 1e3} seconds.` : `Couldn't connect to ${url.host}.`;
      throw new ScanError(msg, 502);
    }
    await res.body?.cancel().catch(() => {
    });
    const location = res.headers.get("location");
    if (res.status >= 300 && res.status < 400 && location) {
      redirects.push({ url: url.href, status: res.status });
      let next;
      try {
        next = new URL(location, url);
      } catch {
        throw new ScanError(`${url.host} redirected to an invalid URL.`, 502);
      }
      const checked = normalizeTarget(next.href, opts);
      if (!checked.ok) throw new ScanError(`Redirect to ${next.host} was blocked: ${checked.error}`, 400);
      url = checked.url;
      continue;
    }
    const headers = {};
    res.headers.forEach((value, key) => {
      if (key !== "set-cookie") headers[key] = value;
    });
    const h = res.headers;
    const cookies2 = typeof h.getSetCookie === "function" ? h.getSetCookie() : [];
    if (cookies2.length) headers["set-cookie"] = cookies2;
    return { finalUrl: url.href, status: res.status, headers, redirects, timingMs: Date.now() - t0 };
  }
  throw new ScanError(`More than ${MAX_HOPS} redirects.`, 502);
}
async function scanUrl(target, opts = {}) {
  const chain = await fetchChain(target, opts);
  const report = analyze({
    url: target.href,
    finalUrl: chain.finalUrl,
    status: chain.status,
    headers: chain.headers,
    redirects: chain.redirects,
    probeOrigin: PROBE_ORIGIN
  });
  const { finalUrl: _f, ...response } = chain;
  return { report, response };
}

// src/pretty.ts
var useColor = !process.env.NO_COLOR && (process.stdout.isTTY || !!process.env.FORCE_COLOR);
var paint = (code) => (s) => useColor ? `\x1B[${code}m${s}\x1B[0m` : s;
var c = {
  bold: paint("1"),
  dim: paint("2"),
  red: paint("31"),
  green: paint("32"),
  yellow: paint("33"),
  blue: paint("34"),
  gray: paint("90")
};
var MARK = { pass: c.green("\u2713"), warn: c.yellow("!"), fail: c.red("\u2717"), info: c.blue("i") };
function gradeColor(g) {
  return g.startsWith("A") ? c.green : g.startsWith("B") ? c.green : g.startsWith("C") ? c.yellow : c.red;
}
function wrap(text, width, indent) {
  const words = text.split(/\s+/);
  const lines = [];
  let line = "";
  for (const w of words) {
    if ((line + " " + w).trim().length > width) {
      lines.push(line);
      line = w;
    } else line = (line + " " + w).trim();
  }
  if (line) lines.push(line);
  return lines.map((l, i) => (i ? indent : "") + l).join("\n");
}
function pretty(r, verbose = false) {
  const width = Math.min(process.stdout.columns || 88, 100);
  const out = [];
  const g = gradeColor(r.grade);
  out.push("");
  out.push(`  ${g(c.bold(r.grade.padEnd(3)))} ${c.bold(r.finalUrl)}  ${c.gray(`${r.score}/100`)}`);
  if (r.redirects.length) out.push(`      ${c.gray(`via ${r.redirects.map((h) => `${h.status} ${h.url}`).join(" \u2192 ")}`)}`);
  if (r.cap) out.push(`      ${c.yellow(`capped at ${r.cap.grade}: ${r.cap.reason}`)}`);
  out.push("");
  for (const ch of r.checks) {
    const pts = ch.modifier === 0 ? "" : ch.modifier > 0 ? c.green(`+${ch.modifier}`) : c.red(String(ch.modifier));
    out.push(`  ${MARK[ch.status]} ${ch.title.padEnd(26)} ${ch.summary.padEnd(Math.max(10, width - 40))} ${pts}`.trimEnd());
    for (const f of ch.findings) {
      if (f.modifier === 0 && !verbose) continue;
      const tone = f.modifier > 0 ? c.green : f.severity === "critical" || f.severity === "high" ? c.red : f.severity === "medium" ? c.yellow : c.gray;
      out.push(`      ${tone("\xB7")} ${c.dim(wrap(f.message, width - 10, "        "))}`);
    }
  }
  out.push("");
  out.push(c.gray(`  ${r.summary.pass} passed \xB7 ${r.summary.warn} warning${r.summary.warn === 1 ? "" : "s"} \xB7 ${r.summary.fail} failed \xB7 ${r.summary.info} advisory`));
  out.push("");
  return out.join("\n");
}

// src/run.ts
var GRADES = ["A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "D-", "F"];
var meetsGrade = (grade, min) => GRADES.indexOf(grade) <= GRADES.indexOf(min);
async function dnsGuard(url) {
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const addrs = await lookup(host, { all: true }).catch(() => {
    throw new Error(`Couldn't resolve ${host}.`);
  });
  const bad = addrs.find((a) => isBlockedHost(a.family === 6 ? `[${a.address}]` : a.address));
  if (bad) throw new Error(`${host} resolves to a private address (${bad.address}). Pass --allow-private to scan your own internal servers.`);
}
async function scanOne(target, o) {
  const t = normalizeTarget(target, { allowPrivate: o.allowPrivate });
  if (!t.ok) throw new Error(t.error);
  const { report } = await scanUrl(t.url, {
    allowPrivate: o.allowPrivate,
    timeoutMs: o.timeoutMs,
    beforeHop: o.allowPrivate ? void 0 : dnsGuard
  });
  return report;
}
function render(reports, o) {
  switch (o.format) {
    case "json":
      return JSON.stringify(reports.length === 1 ? reports[0] : reports, null, 2);
    case "markdown":
      return reports.map(toMarkdown).join("\n\n---\n\n");
    case "sarif": {
      const runs = reports.flatMap((r) => toSarif(r).runs);
      return JSON.stringify({ ...toSarif(reports[0]), runs }, null, 2);
    }
    default:
      return reports.map((r) => pretty(r, o.verbose)).join("\n");
  }
}
async function run(o) {
  const reports = [];
  const errors = [];
  if (o.stdin !== void 0) {
    const t = o.targets[0] ? normalizeTarget(o.targets[0], { allowPrivate: true }) : null;
    const url = t?.ok ? t.url.href : "https://stdin.invalid/";
    reports.push(analyze({ url, headers: parseRawHeaders(o.stdin) }));
  } else {
    const settled = await Promise.allSettled(o.targets.map((t) => scanOne(t, o)));
    settled.forEach((s, i) => {
      if (s.status === "fulfilled") reports.push(s.value);
      else errors.push({ target: o.targets[i], message: s.reason instanceof Error ? s.reason.message : String(s.reason) });
    });
  }
  if (reports.length) {
    const text = render(reports, o);
    if (o.output) await writeFile(o.output, text + "\n");
    else process.stdout.write(text + "\n");
  }
  for (const e of errors) process.stderr.write(`${c.red("error")} ${e.target}: ${e.message}
`);
  if (o.fix) {
    for (const r of reports) {
      const label = PLATFORMS.find((p) => p.id === o.fix)?.label ?? o.fix;
      process.stderr.write(`
${c.bold(`Suggested ${label} config for ${r.finalUrl}`)}
${renderConfig(o.fix, fixesFor(r))}
`);
    }
  }
  if (process.env.GITHUB_STEP_SUMMARY && reports.length) {
    await appendFile(process.env.GITHUB_STEP_SUMMARY, reports.map(toMarkdown).join("\n\n") + "\n").catch(() => {
    });
  }
  if (process.env.GITHUB_ACTIONS === "true") {
    for (const r of reports) {
      for (const ch of r.checks) for (const f of ch.findings) {
        if (f.modifier >= 0) continue;
        const level = f.severity === "critical" || f.severity === "high" ? "error" : f.severity === "medium" ? "warning" : "notice";
        process.stderr.write(`::${level} title=${ch.title} (${r.finalUrl})::${f.message.replace(/\r?\n/g, " ")}
`);
      }
    }
  }
  let exitCode = errors.length ? 2 : 0;
  if (o.failUnder) {
    const failing = reports.filter((r) => !meetsGrade(r.grade, o.failUnder));
    for (const r of failing) process.stderr.write(`${c.red("\u2717")} ${r.finalUrl} scored ${r.grade}, below the required ${o.failUnder}
`);
    if (failing.length) exitCode = 1;
  }
  return { exitCode, reports, errors };
}

// src/action.ts
var input = (name) => (process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] ?? "").trim();
async function main() {
  const targets = input("urls").split(/[\s,]+/).filter(Boolean);
  if (!targets.length) throw new Error("Set the `urls` input to at least one URL.");
  const failUnder = input("fail-under").toUpperCase() || void 0;
  if (failUnder && !GRADES.includes(failUnder)) throw new Error(`fail-under must be a grade like A, B+ or C, not "${failUnder}"`);
  const sarif = input("sarif-file");
  const result2 = await run({
    targets,
    format: "pretty",
    failUnder,
    allowPrivate: input("allow-private") === "true",
    fix: input("fix") || void 0,
    verbose: false,
    timeoutMs: 15e3
  });
  if (sarif && result2.reports.length) {
    await writeFile2(sarif, render(result2.reports, { format: "sarif", verbose: false }) + "\n");
  }
  const first = result2.reports[0];
  if (process.env.GITHUB_OUTPUT && first) {
    const worst = result2.reports.reduce((a, b) => GRADES.indexOf(b.grade) > GRADES.indexOf(a.grade) ? b : a);
    await appendFile2(process.env.GITHUB_OUTPUT, `grade=${worst.grade}
score=${worst.score}
report=${JSON.stringify(result2.reports.map((r) => ({ url: r.finalUrl, grade: r.grade, score: r.score })))}
`);
  }
  process.exitCode = result2.exitCode;
}
main().catch((e) => {
  process.stdout.write(`::error::${e instanceof Error ? e.message : e}
`);
  process.exitCode = 2;
});
