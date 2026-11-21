import type { HeaderInput } from "./types.js";

/**
 * Case-insensitive, multi-value view of response headers.
 *
 * Headers can arrive several ways: a fetch Headers object flattened to a record,
 * a raw dump where repeated headers were joined with ", ", or an explicit array.
 * Set-Cookie is the awkward one: it may legally contain commas (in Expires), so
 * it must never be split on ", ".
 */
export class HeaderBag {
  private readonly map = new Map<string, string[]>();

  constructor(input: HeaderInput = {}) {
    for (const [rawKey, rawValue] of Object.entries(input)) {
      if (rawValue === undefined) continue;
      const key = rawKey.trim().toLowerCase();
      if (!key) continue;
      const values = Array.isArray(rawValue) ? rawValue : [rawValue];
      const list = this.map.get(key) ?? [];
      for (const v of values) list.push(String(v).trim());
      this.map.set(key, list);
    }
  }

  has(name: string): boolean {
    return this.map.has(name.toLowerCase());
  }

  /** Every value sent for this header, in order. */
  all(name: string): string[] {
    return this.map.get(name.toLowerCase()) ?? [];
  }

  /** The first value, which is what browsers honour for most single-value headers. */
  first(name: string): string | undefined {
    return this.all(name)[0];
  }

  /** All values joined the way a browser would combine repeated headers. */
  joined(name: string): string | undefined {
    const v = this.all(name);
    return v.length ? v.join(", ") : undefined;
  }

  names(): string[] {
    return [...this.map.keys()];
  }

  get size(): number {
    return this.map.size;
  }
}

/**
 * Parse a raw HTTP header dump ("Name: value" per line) into a HeaderInput.
 * Status lines are skipped. When the dump contains several responses (a
 * redirect chain from `curl -IL`), only the last block is kept.
 */
export function parseRawHeaders(text: string): HeaderInput {
  const blocks = text.split(/\r?\n\s*\r?\n/).filter((b) => b.trim());
  const last = blocks[blocks.length - 1] ?? "";
  const out: Record<string, string[]> = {};
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
