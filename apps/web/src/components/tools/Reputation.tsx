import {
  SOURCE_LABELS,
  SOURCES_FOR_KIND,
  type ApiError,
  type LookupKind,
  type LookupResponse,
  type SourceResult,
  type SourceStatus,
  type Verdict,
} from "@bluebench/shared";
import { useRef, useState } from "react";
import { lookupReputation } from "../../lib/api";
import { runTurnstile } from "../../lib/turnstile";
import { summarizeLookup } from "../../lib/summaries";
import { Badge, CopyButton, Facts, type Tone } from "../ui";

const VERDICT: Record<Verdict, { tone: Tone; label: string; text: string }> = {
  listed: { tone: "critical", label: "Listed", text: "At least one source lists this. Treat it as suspicious." },
  "not-listed": {
    tone: "ok",
    label: "Not listed",
    text: "No source lists this. That isn't proof it's safe: new threats take time to be reported.",
  },
  incomplete: {
    tone: "warn",
    label: "Incomplete",
    text: "No source that answered lists this, but some couldn't be checked.",
  },
};

const STATUS: Record<SourceStatus, { tone: Tone; label: string }> = {
  listed: { tone: "critical", label: "Listed" },
  "not-listed": { tone: "ok", label: "Not listed" },
  skipped: { tone: "neutral", label: "Skipped" },
  error: { tone: "warn", label: "Error" },
};

function SourceRow({ result }: { result: SourceResult }) {
  // Google's terms: hedge the wording of a match.
  const status = result.source === "safebrowsing" && result.status === "listed" ? { tone: "critical" as const, label: "Suspected" } : STATUS[result.status];
  const note = result.stale ? "Older result: a live check wasn't possible." : result.cached ? "Recent cached result." : null;
  return (
    <li className="space-y-2 border-t border-border pt-3 first:border-t-0 first:pt-0">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{SOURCE_LABELS[result.source]}</span>
        <Badge tone={status.tone}>{status.label}</Badge>
      </div>
      <p className="text-sm">{result.summary}</p>
      {result.facts.length > 0 && <Facts rows={result.facts.map((f) => [f.label, f.value])} />}
      {(note || result.link) && (
        <p className="flex flex-wrap gap-x-4 gap-y-1 text-sm text-muted">
          {note && <span>{note}</span>}
          {result.link && result.source !== "safebrowsing" && (
            <a href={result.link} target="_blank" rel="noopener noreferrer" className="inline-flex min-h-11 items-center underline hover:text-fg">
              Details on {SOURCE_LABELS[result.source]}
            </a>
          )}
        </p>
      )}
    </li>
  );
}

/** Required attribution whenever Safe Browsing results are shown. */
function SafeBrowsingNotice() {
  return (
    <p className="text-sm text-muted">
      <a
        href="https://developers.google.com/safe-browsing/v4/advisory"
        target="_blank"
        rel="noopener noreferrer"
        className="underline hover:text-fg"
      >
        Advisory provided by Google
      </a>
      . Google works to provide accurate and up-to-date information on unsafe web resources, but can't guarantee it's
      comprehensive and error-free: some risky sites may not be identified, and some safe sites may be flagged in error.
    </p>
  );
}

export function ReputationResult({ result }: { result: LookupResponse }) {
  const verdict = VERDICT[result.verdict];
  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-2">
          <Badge tone={verdict.tone}>{verdict.label}</Badge>
          <p className="text-sm">{verdict.text}</p>
        </div>
        <CopyButton value={summarizeLookup(result)} label="Copy result" />
      </div>
      <ul className="space-y-3">
        {result.sources.map((s) => (
          <SourceRow key={s.source} result={s} />
        ))}
      </ul>
      {result.sources.some((s) => s.source === "safebrowsing" && s.status !== "skipped") && <SafeBrowsingNotice />}
    </div>
  );
}

type State = { phase: "idle" } | { phase: "loading" } | { phase: "done"; result: LookupResponse } | { phase: "error"; error: ApiError };

/** Opt-in reputation lookup: nothing leaves the browser until the button is pressed. */
export function Reputation({ kind, value }: { kind: LookupKind; value: string }) {
  const [state, setState] = useState<State>({ phase: "idle" });
  const challengeRef = useRef<HTMLDivElement>(null);
  const sources = SOURCES_FOR_KIND[kind].map((s) => SOURCE_LABELS[s]).join(", ");

  const run = async () => {
    setState({ phase: "loading" });
    const res = await lookupReputation(kind, value, (siteKey) => runTurnstile(challengeRef.current!, siteKey));
    setState(res.ok ? { phase: "done", result: res } : { phase: "error", error: res });
  };

  return (
    <div className="space-y-3 border-t border-border pt-4">
      <h3 className="text-sm font-medium">Reputation</h3>
      {state.phase === "done" ? (
        <ReputationResult result={state.result} />
      ) : (
        <>
          <p className="text-sm text-muted">
            Checks {sources}. Only this indicator is sent to our server, and it isn't logged.
          </p>
          <button
            type="button"
            onClick={() => void run()}
            disabled={state.phase === "loading"}
            className="min-h-11 rounded-md bg-accent px-4 text-sm font-medium text-on-accent disabled:opacity-50"
          >
            {state.phase === "loading" ? "Checking…" : "Check reputation"}
          </button>
        </>
      )}
      {/* Turnstile renders here, and only becomes visible if Cloudflare needs an interaction. */}
      <div ref={challengeRef} />
      <div aria-live="polite">
        {state.phase === "error" && (
          <p className="flex items-start gap-2 text-sm">
            <Badge tone="warn">{state.error.error === "daily-limit" || state.error.error === "rate-limited" ? "Limit" : "Error"}</Badge>
            <span>{state.error.message}</span>
          </p>
        )}
      </div>
    </div>
  );
}
