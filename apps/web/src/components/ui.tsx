import { useState, type ReactNode } from "react";
import type { Finding, Severity } from "../lib/findings";

export function Panel({ title, children, aside }: { title: string; children: ReactNode; aside?: ReactNode }) {
  return (
    <section className="rounded-lg border border-border bg-surface p-4" aria-label={title}>
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="text-base font-semibold">{title}</h2>
        {aside}
      </div>
      <div className="space-y-4">{children}</div>
    </section>
  );
}

export type Tone = "ok" | "warn" | "critical" | "neutral";

const TONE_CLASSES: Record<Tone, string> = {
  ok: "border-ok/50 text-ok",
  warn: "border-warn/50 text-warn",
  critical: "border-critical/50 text-critical",
  neutral: "border-border text-muted",
};

/** Coloured label. The text always carries the meaning; colour only reinforces it. */
export function Badge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span className={`inline-flex shrink-0 items-center rounded border px-1.5 py-0.5 text-xs font-medium ${TONE_CLASSES[tone]}`}>
      {children}
    </span>
  );
}

const SEVERITY: Record<Severity, { tone: Tone; label: string }> = {
  critical: { tone: "critical", label: "Red flag" },
  warning: { tone: "warn", label: "Warning" },
  info: { tone: "neutral", label: "Note" },
};

export function FindingList({ findings, empty }: { findings: Finding[]; empty?: string }) {
  if (findings.length === 0) {
    return empty ? (
      <p className="flex items-start gap-2 text-sm">
        <Badge tone="ok">OK</Badge>
        <span>{empty}</span>
      </p>
    ) : null;
  }
  return (
    <ul className="space-y-2">
      {findings.map((f, i) => (
        <li key={i} className="flex items-start gap-2 text-sm">
          <Badge tone={SEVERITY[f.severity].tone}>{SEVERITY[f.severity].label}</Badge>
          <span>
            <span className="font-medium">{f.title}</span>
            {f.detail && <span className="text-muted"> — {f.detail}</span>}
          </span>
        </li>
      ))}
    </ul>
  );
}

/** A collapsed "What's this?" explanation next to a term in a result. */
export function WhatsThis({ children }: { children: ReactNode }) {
  return (
    <details className="text-sm">
      <summary className="inline-flex min-h-11 cursor-pointer items-center text-muted underline hover:text-fg">What's this?</summary>
      <p className="text-muted">{children}</p>
    </details>
  );
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
      className="min-h-11 shrink-0 rounded-md border border-border px-3 text-sm text-muted hover:text-fg"
    >
      <span aria-live="polite">{copied ? "Copied" : label}</span>
    </button>
  );
}

export function CodeBlock({ children, label }: { children: string; label?: string }) {
  return (
    <div>
      {label && (
        <div className="mb-1 flex items-center justify-between gap-2">
          <h3 className="text-sm font-medium text-muted">{label}</h3>
          <CopyButton value={children} />
        </div>
      )}
      <pre className="max-h-96 overflow-auto rounded-md border border-border bg-ground p-3 font-mono text-sm break-all whitespace-pre-wrap">
        {children}
      </pre>
    </div>
  );
}

/** Two-column facts list. Values render in mono unless `plain` is set. */
export function Facts({ rows }: { rows: [label: string, value: ReactNode, plain?: boolean][] }) {
  return (
    // The label column is capped at 40% so a long label can't squeeze values down to one letter per line.
    <dl className="grid grid-cols-[minmax(6rem,40%)_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
      {rows.map(([label, value, plain]) => (
        <div key={label} className="contents">
          <dt className="min-w-0 break-words text-muted">{label}</dt>
          <dd className={plain ? "min-w-0 break-words" : "min-w-0 font-mono break-all"}>{value}</dd>
        </div>
      ))}
    </dl>
  );
}
