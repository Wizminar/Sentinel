import "@fontsource-variable/martian-mono/standard.css";
import "@fontsource-variable/schibsted-grotesk/wght.css";
import "@fontsource-variable/schibsted-grotesk/wght-italic.css";
import "./styles.css";
import {
  analyze, fixesFor, gradeFor, METHOD, PLATFORMS, renderConfig, toMarkdown, toSarif,
  type CheckResult, type HeaderInput, type Platform, type Report,
} from "@sentinel/core";
import { scan, ScanFailure, type ScanResult } from "./api";
import { renderSheet } from "./sheet";

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

const form = $<HTMLFormElement>("scan-form");
const input = $<HTMLInputElement>("url");
const button = $<HTMLButtonElement>("scan-btn");
const errorEl = $("scan-error");
const sheet = $("sheet");
const caption = $("proof-caption");
const reportEl = $("report");

let current: ScanResult | null = null;
let platform: Platform = "nginx";

/* ---------- sample shown before the first scan ---------- */
const SAMPLE_HEADERS: HeaderInput = {
  "content-type": "text/html; charset=utf-8",
  "x-powered-by": "Express",
  "strict-transport-security": "max-age=300",
  "set-cookie": ["connect.sid=s%3A9f2c1; Path=/; HttpOnly"],
  "x-xss-protection": "1; mode=block",
  etag: 'W/"5a2-Qm3n"',
};
const sample = analyze({ url: "https://shop.example/", headers: SAMPLE_HEADERS, status: 200 });
renderSheet(sheet, sample, SAMPLE_HEADERS, 200);

/* ---------- scanning ---------- */
function setBusy(on: boolean, host = "") {
  button.disabled = on;
  button.textContent = on ? "Scanning…" : "Scan headers";
  sheet.classList.toggle("busy", on);
  if (on) caption.textContent = `Fetching headers from ${host}…`;
}

function showError(msg: string) {
  errorEl.textContent = msg;
  errorEl.hidden = false;
  input.setAttribute("aria-invalid", "true");
}

async function run(raw: string, pushState = true) {
  errorEl.hidden = true;
  input.removeAttribute("aria-invalid");
  const host = raw.replace(/^https?:\/\//, "").split("/")[0] || raw;
  setBusy(true, host);
  try {
    const result = await scan(raw);
    current = result;
    const r = result.report;
    renderSheet(sheet, r, result.headers, result.status);
    const shown = new URL(r.finalUrl).host;
    caption.textContent = `${shown}, scanned just now${result.via === "public" ? " through the public lookup" : result.cached ? " (cached for 10 minutes)" : ""}`;
    renderReport(result);
    if (pushState) {
      const u = new URL(location.href);
      u.searchParams.set("url", shown + (new URL(r.url).pathname !== "/" ? new URL(r.url).pathname : ""));
      history.pushState(null, "", u);
    }
    document.title = `${r.grade} for ${shown} — Sentinel`;
  } catch (e) {
    caption.textContent = current ? caption.textContent : "Sample: a typical Express app, proofread";
    showError(e instanceof ScanFailure ? e.message : "Something went wrong while scanning. Try again.");
  } finally {
    setBusy(false);
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  if (!input.value.trim()) return showError("Enter a website address to scan.");
  void run(input.value);
});
document.querySelectorAll<HTMLButtonElement>(".example").forEach((b) =>
  b.addEventListener("click", () => {
    input.value = b.dataset.url!;
    void run(b.dataset.url!);
  }),
);

function fromQuery(push: boolean) {
  const q = new URL(location.href).searchParams.get("url");
  if (q) {
    input.value = q;
    void run(q, push);
  }
}
window.addEventListener("popstate", () => fromQuery(false));
fromQuery(false);

/* ---------- report ---------- */
const STATUS_WORD = { pass: "Passes", warn: "Needs attention", fail: "Fails", info: "Advisory" } as const;

function verdict(r: Report): string {
  const { fail, warn } = r.summary;
  if (!fail && !warn) return "Every check passes. Nothing to fix.";
  const parts = [fail && `${fail} check${fail === 1 ? "" : "s"} failed`, warn && `${warn} need${warn === 1 ? "s" : ""} attention`].filter(Boolean);
  return `${parts.join(", ")}.`.replace(/^./, (c) => c.toUpperCase());
}

function checkItem(c: CheckResult): string {
  const pts = c.modifier === 0 ? "" : `<span class="pts ${c.modifier > 0 ? "plus" : "minus"}">${c.modifier > 0 ? "+" : "−"}${Math.abs(c.modifier)}</span>`;
  const findings = c.findings.map((f) => `
    <li class="finding sev-${f.severity}${f.modifier > 0 ? " good" : ""}">
      <p>${esc(f.message)}</p>
      ${f.evidence && f.evidence !== c.value ? `<code>${esc(f.evidence)}</code>` : ""}
    </li>`).join("");
  return `<li class="check st-${c.status}">
    <details${c.status === "fail" ? " open" : ""}>
      <summary>
        <span class="dot" aria-hidden="true"></span>
        <span class="check-title">${esc(c.title)}</span>
        <span class="check-sum"><span class="visually-hidden">${STATUS_WORD[c.status]}: </span>${esc(c.summary)}</span>
        ${pts}
      </summary>
      <div class="check-body">
        <p class="defends">Protects against: ${esc(c.defends)}.</p>
        ${findings ? `<ul class="findings">${findings}</ul>` : ""}
        ${c.value ? `<pre class="code small">${esc(c.value)}</pre>` : ""}
      </div>
    </details>
  </li>`;
}

function renderFix(r: Report) {
  const fixes = fixesFor(r);
  $("fix-code").textContent = renderConfig(platform, fixes);
  const notes = fixes.map((f) => f.note).filter(Boolean);
  $("fix-note").textContent = notes.length ? notes.join(" ") : "";
  document.querySelectorAll<HTMLButtonElement>("#fix-tabs [role=tab]").forEach((t) => {
    const on = t.dataset.platform === platform;
    t.setAttribute("aria-selected", String(on));
    t.tabIndex = on ? 0 : -1;
  });
}

const tabs = $("fix-tabs");
tabs.innerHTML = PLATFORMS.map((p) => `<button type="button" role="tab" data-platform="${p.id}" aria-controls="fix-code">${esc(p.label)}</button>`).join("");
tabs.addEventListener("click", (e) => {
  const t = (e.target as HTMLElement).closest<HTMLButtonElement>("[role=tab]");
  if (!t || !current) return;
  platform = t.dataset.platform as Platform;
  renderFix(current.report);
});
tabs.addEventListener("keydown", (e) => {
  if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
  const all = [...tabs.querySelectorAll<HTMLButtonElement>("[role=tab]")];
  const i = all.findIndex((t) => t.dataset.platform === platform);
  const next = all[(i + (e.key === "ArrowRight" ? 1 : all.length - 1)) % all.length]!;
  next.click();
  next.focus();
});

function renderReport(result: ScanResult) {
  const r = result.report;
  const host = new URL(r.finalUrl).host;
  $("report-title").textContent = `${host} scored ${r.grade}`;
  $("report-sub").innerHTML = `${esc(verdict(r))} ${r.cap ? `Capped at ${esc(r.cap.grade)}: ${esc(r.cap.reason)}` : ""} <span class="score-note">Score ${r.score} of 100.</span>`;
  $("checks").innerHTML = r.checks.map(checkItem).join("");
  renderFix(r);

  const badgeBlock = $("badge-block");
  badgeBlock.hidden = result.via !== "api";
  if (result.via === "api") {
    const badgeUrl = `${location.origin}/badge?url=${encodeURIComponent(host)}`;
    $<HTMLImageElement>("badge-img").src = badgeUrl;
    $<HTMLImageElement>("badge-img").alt = `security headers: ${r.grade}`;
    $("badge-code").textContent = `[![security headers](${badgeUrl})](${location.origin}/?url=${encodeURIComponent(host)})`;
  }
  reportEl.hidden = false;
}

/* ---------- copy & export ---------- */
async function copy(text: string, btn: HTMLButtonElement, done: string) {
  const label = btn.textContent;
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = done;
  } catch {
    btn.textContent = "Couldn't copy — select the text instead";
  }
  setTimeout(() => (btn.textContent = label), 1600);
}
$<HTMLButtonElement>("copy-fix").addEventListener("click", (e) => copy($("fix-code").textContent ?? "", e.currentTarget as HTMLButtonElement, "Copied config"));
$<HTMLButtonElement>("copy-badge").addEventListener("click", (e) => copy($("badge-code").textContent ?? "", e.currentTarget as HTMLButtonElement, "Copied Markdown"));
$<HTMLButtonElement>("copy-link").addEventListener("click", (e) => copy(location.href, e.currentTarget as HTMLButtonElement, "Copied link"));

document.querySelectorAll<HTMLButtonElement>("[data-export]").forEach((b) =>
  b.addEventListener("click", () => {
    if (!current) return;
    const r = current.report;
    const host = new URL(r.finalUrl).host;
    const kind = b.dataset.export!;
    const [body, type, ext] =
      kind === "md" ? [toMarkdown(r), "text/markdown", "md"]
      : kind === "sarif" ? [JSON.stringify(toSarif(r), null, 2), "application/sarif+json", "sarif"]
      : [JSON.stringify(r, null, 2), "application/json", "json"];
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([body], { type }));
    a.download = `sentinel-${host}.${ext}`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }),
);

/* ---------- method table & grade scale (from the engine itself) ---------- */
const meta = new Map(analyze({ url: "https://x.example/", headers: {} }).checks.map((c) => [c.id, c]));
$("weights").innerHTML = METHOD.map((m) => {
  const c = meta.get(m.id)!;
  return `<tr><th scope="row">${esc(c.title)}</th><td>${esc(c.defends)}</td><td class="num">${m.penalty ? `−${-m.penalty}` : "—"}</td><td class="num">${m.bonus ? `+${m.bonus}` : "—"}</td></tr>`;
}).join("");

const SCALE = [100, 90, 85, 80, 70, 65, 60, 50, 45, 40, 30, 25, 0];
$("scale").innerHTML = SCALE.map((min) => {
  const g = gradeFor(min);
  return `<li class="scale-${g[0]!.toLowerCase()}"><span class="g">${g}</span><span class="t">${min === 0 ? "below 25" : `${min}+`}</span></li>`;
}).join("");
