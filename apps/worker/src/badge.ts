import type { Grade } from "@sentinel/core";

const COLOR: Record<string, string> = { A: "#1f7a4d", B: "#5b7a1f", C: "#a8730b", D: "#b4501a", F: "#b3261e" };

/** Approximate Verdana 11px advance widths, enough to size a badge without a font engine. */
function textWidth(s: string): number {
  let w = 0;
  for (const ch of s) w += /[ilI.:|]/.test(ch) ? 3.5 : /[mwMW]/.test(ch) ? 10 : /[A-Z+]/.test(ch) ? 8 : 6.6;
  return Math.ceil(w);
}

const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);

/** A shields.io-style flat badge: "security headers | A+". */
export function badgeSvg(grade: Grade | "?", label = "security headers"): string {
  const color = COLOR[grade[0] ?? ""] ?? "#6b7280";
  const lw = textWidth(label) + 12;
  const vw = textWidth(grade) + 14;
  const w = lw + vw;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${esc(label)}: ${esc(grade)}">
<title>${esc(label)}: ${esc(grade)}</title>
<clipPath id="r"><rect width="${w}" height="20" rx="3"/></clipPath>
<g clip-path="url(#r)"><rect width="${lw}" height="20" fill="#1c2340"/><rect x="${lw}" width="${vw}" height="20" fill="${color}"/></g>
<g fill="#fff" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">
<text x="${lw / 2}" y="14">${esc(label)}</text><text x="${lw + vw / 2}" y="14" font-weight="bold">${esc(grade)}</text>
</g></svg>`;
}
