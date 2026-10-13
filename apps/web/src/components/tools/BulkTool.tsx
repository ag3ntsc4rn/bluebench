import { classifyIp, parseIp, toCsv, toStixBundle, type Extracted, type ExtractedKind } from "@bluebench/shared";
import { useState } from "react";
import { downloadText, stampedName } from "../../lib/download";
import { defangEmail, defangHost, defangUrl } from "../../lib/summaries";
import { Badge, CopyButton, Panel } from "../ui";

/** Share-safe form: links and hosts stop being clickable when pasted into chat or tickets. */
export function defangExtracted(i: Extracted): string {
  if (i.kind === "url") return defangUrl(i.value);
  if (i.kind === "email") return defangEmail(i.value);
  if (i.kind === "domain" || i.kind === "ipv4") return defangHost(i.value);
  return i.value;
}

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

function Group({ kind, items, onUseAsInput }: { kind: ExtractedKind; items: Extracted[]; onUseAsInput: (text: string) => void }) {
  const [all, setAll] = useState(false);
  const shown = all ? items : items.slice(0, PREVIEW);
  return (
    <section className="space-y-2">
      <h3 className="text-sm font-medium">
        {PLURAL[kind]} <span className="text-muted">({items.length})</span>
      </h3>
      <ul className="divide-y divide-border rounded-md border border-border">
        {shown.map((i) => {
          const ip = i.kind === "ipv4" || i.kind === "ipv6" ? parseIp(i.value) : null;
          const internal = ip !== null && !classifyIp(ip).global;
          return (
            <li key={i.value} className="flex items-center gap-2 pl-3">
              <span className="min-w-0 flex-1 font-mono text-sm break-all">{i.value}</span>
              {internal && <Badge tone="neutral">Not public</Badge>}
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

/** Every indicator in a paste: refanged, de-duplicated, grouped, and exportable. Nothing leaves the browser. */
export function BulkTool({ items, onUseAsInput }: { items: Extracted[]; onUseAsInput: (text: string) => void }) {
  const kinds = [...new Set(items.map((i) => i.kind))];
  const defangedList = items.map(defangExtracted).join("\n");
  const name = stampedName("bluebench-iocs");

  return (
    <Panel title="Indicators found" aside={<span className="text-sm text-muted">{items.length}</span>}>
      <p className="text-sm text-muted">
        Extracted in your browser: refanged, de-duplicated, grouped by type. Nothing is sent. File names like invoice.pdf
        are skipped. Tap Analyse to look at one on its own, including its reputation.
      </p>
      <div className="flex flex-wrap gap-2">
        <CopyButton value={defangedList} label="Copy defanged list" />
        <button
          type="button"
          onClick={() => downloadText(`${name}.csv`, toCsv(items, defangExtracted), "text/csv")}
          className="min-h-11 rounded-md border border-border px-3 text-sm text-muted hover:text-fg"
        >
          Download CSV
        </button>
        <button
          type="button"
          onClick={() => downloadText(`${name}.stix.json`, toStixBundle(items), "application/stix+json")}
          className="min-h-11 rounded-md border border-border px-3 text-sm text-muted hover:text-fg"
        >
          Download STIX 2.1
        </button>
      </div>
      {kinds.map((k) => (
        <Group key={k} kind={k} items={items.filter((i) => i.kind === k)} onUseAsInput={onUseAsInput} />
      ))}
      <p className="text-xs text-muted">
        The copied list and the CSV's "defanged" column are safe to paste into chat and tickets: links won't be clickable.
        STIX lists each item as an indicator without a verdict.
      </p>
    </Panel>
  );
}
