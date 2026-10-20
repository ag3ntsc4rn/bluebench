import {
  ANON_DAILY_LIMIT,
  BULK_LOOKUP_MAX,
  classifyIp,
  exportVerdict,
  extractedKey,
  isLookupKind,
  parseIp,
  toCsv,
  toStixBundle,
  type BatchLookupResponse,
  type Extracted,
  type ExtractedKind,
  type LookupKind,
  USER_DAILY_LIMIT,
} from "@bluebench/shared";
import { useEffect, useRef, useState } from "react";
import { lookupBatch } from "../../lib/api";
import { runBulkLookup } from "../../lib/bulk";
import { downloadText, stampedName } from "../../lib/download";
import { defangExtracted } from "../../lib/summaries";
import { runTurnstile } from "../../lib/turnstile";
import { Badge, CopyButton, Panel, type Tone } from "../ui";
import { SafeBrowsingNotice } from "./Reputation";

export { defangExtracted };

const PLURAL: Record<ExtractedKind, string> = {
  url: "URLs",
  domain: "Domains",
  ipv4: "IPv4 addresses",
  ipv6: "IPv6 addresses",
  email: "Email addresses",
  sha256: "SHA-256 hashes",
  sha1: "SHA-1 hashes",
  md5: "MD5 hashes",
};

/** Shown per kind before "Show all". */
const PREVIEW = 50;

type Result = BatchLookupResponse["results"][number];
export type BulkResult = Result;

const isInternalIp = (i: Extracted) => {
  const ip = i.kind === "ipv4" || i.kind === "ipv6" ? parseIp(i.value) : null;
  return ip !== null && !classifyIp(ip).global;
};

/** Items our sources can answer for: not email addresses, not private or reserved IPs. */
export const checkable = (i: Extracted): i is Extracted & { kind: LookupKind } => isLookupKind(i.kind) && !isInternalIp(i);

/** Row badge. Safe Browsing alone gets hedged wording, as on single lookups. */
export function resultBadge(r: Result): { tone: Tone; label: string } {
  if (!r.ok) return { tone: "neutral", label: r.error === "daily-limit" ? "Not checked" : "Can't check" };
  if (r.verdict === "listed") {
    const listers = r.sources.filter((s) => s.status === "listed");
    return { tone: "critical", label: listers.every((s) => s.source === "safebrowsing") ? "Suspected" : "Listed" };
  }
  return r.verdict === "not-listed" ? { tone: "ok", label: "Not listed" } : { tone: "warn", label: "Incomplete" };
}

function Group({
  kind,
  items,
  results,
  onUseAsInput,
}: {
  kind: ExtractedKind;
  items: Extracted[];
  results: ReadonlyMap<string, Result>;
  onUseAsInput: (text: string) => void;
}) {
  const [all, setAll] = useState(false);
  const shown = all ? items : items.slice(0, PREVIEW);
  return (
    <section className="space-y-2">
      <h3 className="text-sm font-medium">
        {PLURAL[kind]} <span className="text-muted">({items.length})</span>
      </h3>
      <ul className="divide-y divide-border rounded-md border border-border">
        {shown.map((i) => {
          const r = results.get(extractedKey(i));
          const badge = r && resultBadge(r);
          return (
            <li key={i.value} className="flex flex-wrap items-center gap-x-2 pl-3">
              <span className="min-w-0 flex-1 basis-48 py-2 font-mono text-sm break-all">{i.value}</span>
              {isInternalIp(i) && <Badge tone="neutral">Not public</Badge>}
              {badge && <Badge tone={badge.tone}>{badge.label}</Badge>}
              <button
                type="button"
                onClick={() => onUseAsInput(i.value)}
                aria-label={`Analyse ${i.value}`}
                className="min-h-11 shrink-0 px-3 text-sm text-muted underline hover:text-fg"
              >
                Analyse
              </button>
            </li>
          );
        })}
      </ul>
      {items.length > PREVIEW && !all && (
        <button type="button" onClick={() => setAll(true)} className="min-h-11 rounded-md border border-border px-3 text-sm text-muted hover:text-fg">
          Show all {items.length}
        </button>
      )}
    </section>
  );
}

type Run = { phase: "idle" } | { phase: "running"; done: number; total: number; pausedFor?: number } | { phase: "stopped"; message: string };

/** Every indicator in a paste: refanged, de-duplicated, grouped, checkable in bulk and exportable. */
export function BulkTool({
  items,
  onUseAsInput,
  onResults,
}: {
  items: Extracted[];
  onUseAsInput: (text: string) => void;
  /** Called whenever reputation results come in (the triage tool puts them in its ticket note). */
  onResults?: (results: ReadonlyMap<string, Result>) => void;
}) {
  const [results, setResults] = useState<ReadonlyMap<string, Result>>(new Map());
  useEffect(() => {
    if (results.size > 0) onResults?.(results);
  }, [results, onResults]);
  const [run, setRun] = useState<Run>({ phase: "idle" });
  const [listedOnly, setListedOnly] = useState(false);
  const challengeRef = useRef<HTMLDivElement>(null);

  const toCheck = items.filter(checkable).filter((i) => !results.has(extractedKey(i))).slice(0, BULK_LOOKUP_MAX);
  const skipped = items.filter((i) => !checkable(i)).length;
  const listedCount = [...results.values()].filter((r) => r.ok && r.verdict === "listed").length;
  const shownItems = listedOnly ? items.filter((i) => { const r = results.get(extractedKey(i)); return r?.ok && r.verdict === "listed"; }) : items;
  const kinds = [...new Set(shownItems.map((i) => i.kind))];
  const running = run.phase === "running";

  const verdicts = new Map([...results].flatMap(([k, r]) => (r.ok ? [[k, exportVerdict(r)] as const] : [])));
  const name = stampedName("bluebench-iocs");

  const checkAll = async () => {
    const batch = toCheck.map((i) => ({ kind: i.kind, value: i.value }));
    setRun({ phase: "running", done: 0, total: batch.length });
    let done = 0;
    const stop = await runBulkLookup(batch, {
      send: (b) => lookupBatch(b, (siteKey) => runTurnstile(challengeRef.current!, siteKey)),
      onResult: (index, r) => {
        done++;
        const key = extractedKey(toCheck[index]!);
        setResults((prev) => new Map(prev).set(key, r));
        setRun({ phase: "running", done, total: batch.length });
      },
      onPause: (seconds) => setRun({ phase: "running", done, total: batch.length, pausedFor: seconds }),
    });
    setRun(stop ? { phase: "stopped", message: stop.message } : { phase: "idle" });
  };

  return (
    <Panel title="Indicators found" aside={<span className="text-sm text-muted">{items.length}</span>}>
      <p className="text-sm text-muted">
        Extracted in your browser: refanged, de-duplicated, grouped by type. File names like invoice.pdf are skipped. Tap
        Analyse to look at one on its own.
      </p>

      <div className="space-y-2 rounded-md border border-border p-3">
        {toCheck.length > 0 ? (
          <>
            <button
              type="button"
              disabled={running}
              onClick={() => void checkAll()}
              className="min-h-11 rounded-md bg-accent px-4 text-sm font-medium text-on-accent disabled:opacity-50"
            >
              {running ? "Checking…" : `Check reputation for ${toCheck.length}`}
            </button>
            <p className="text-sm text-muted">
              Sends these {toCheck.length} to our server, and each counts toward today's lookups ({ANON_DAILY_LIMIT} a day, or {USER_DAILY_LIMIT} signed in).
              {skipped > 0 && ` ${skipped} can't be checked (email addresses and private IPs).`} Your own API keys aren't
              used in bulk: open one with Analyse to include them.
            </p>
          </>
        ) : (
          results.size > 0 && <p className="text-sm text-muted">Every indicator that can be checked has been.</p>
        )}
        <div aria-live="polite" className="text-sm">
          {running && (
            <p>
              Checked {run.done} of {run.total}
              {run.pausedFor ? `. Pausing ${run.pausedFor} seconds for the per-minute limit…` : "…"}
            </p>
          )}
          {run.phase === "stopped" && (
            <p className="flex items-start gap-2">
              <Badge tone="warn">Stopped</Badge>
              <span>{run.message}</span>
            </p>
          )}
          {results.size > 0 && !running && (
            <p className="text-muted">
              {listedCount} listed out of {results.size} checked.
            </p>
          )}
        </div>
        {/* Turnstile renders here, and only becomes visible if Cloudflare needs an interaction. */}
        <div ref={challengeRef} />
      </div>

      <div className="flex flex-wrap gap-2">
        <CopyButton value={items.map(defangExtracted).join("\n")} label="Copy defanged list" />
        <button
          type="button"
          onClick={() => downloadText(`${name}.csv`, toCsv(items, defangExtracted, verdicts), "text/csv")}
          className="min-h-11 rounded-md border border-border px-3 text-sm text-muted hover:text-fg"
        >
          Download CSV
        </button>
        <button
          type="button"
          onClick={() => downloadText(`${name}.stix.json`, toStixBundle(items, undefined, undefined, verdicts), "application/stix+json")}
          className="min-h-11 rounded-md border border-border px-3 text-sm text-muted hover:text-fg"
        >
          Download STIX 2.1
        </button>
        {listedCount > 0 && (
          <label className="flex min-h-11 cursor-pointer items-center gap-2 px-1 text-sm">
            <input type="checkbox" checked={listedOnly} onChange={(e) => setListedOnly(e.target.checked)} className="size-5 accent-accent" />
            Listed only
          </label>
        )}
      </div>

      {kinds.map((k) => (
        <Group key={k} kind={k} items={shownItems.filter((i) => i.kind === k)} results={results} onUseAsInput={onUseAsInput} />
      ))}

      <p className="text-xs text-muted">
        The copied list and the CSV's "defanged" column are safe to paste into chat and tickets. Exported verdicts leave out
        Google Safe Browsing, as Google's terms require; STIX marks only listed items as malicious activity.
      </p>
      {[...results.values()].some((r) => r.ok && r.sources.some((s) => s.source === "safebrowsing" && s.status !== "skipped")) && <SafeBrowsingNotice />}
    </Panel>
  );
}
