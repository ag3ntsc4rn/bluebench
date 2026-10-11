/**
 * Cached values never contain the indicator or domain they're about: occurrences are replaced by a
 * placeholder before writing to KV and restored on read (the key is already a hash).
 */
const PLACEHOLDER = "⟦indicator⟧";

/** Swap `from` for `to` inside the JSON text, matching the JSON-escaped forms. */
function swapJson<T>(value: T, from: string, to: string): T {
  const esc = (s: string) => JSON.stringify(s).slice(1, -1);
  return JSON.parse(JSON.stringify(value).split(esc(from)).join(esc(to))) as T;
}

export const redact = <T>(value: T, subject: string): T => swapJson(value, subject, PLACEHOLDER);
export const restore = <T>(value: T, subject: string): T => swapJson(value, PLACEHOLDER, subject);
