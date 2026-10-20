import { detect, extractIndicators, KIND_LABELS, MAX_PASTE_LENGTH, type Detection, type IndicatorKind } from "@bluebench/shared";
import { useDeferredValue, useMemo, useRef, useState, type ReactNode } from "react";
import { Base64Tool } from "../components/tools/Base64Tool";
import { BulkTool } from "../components/tools/BulkTool";
import { HeaderTool } from "../components/tools/HeaderTool";
import { IndicatorTool } from "../components/tools/IndicatorTool";
import { JwtTool } from "../components/tools/JwtTool";
import { UrlDecodeTool, UrlTool } from "../components/tools/UrlTool";
import { navigate } from "../components/AppLink";
import { looksLikeFullMessage } from "../lib/mime";
import { handOffMessage } from "../lib/triage";

const TRIAGE_PATH = "/phishing-triage";

/** Shown above the header analysis when the paste is a whole message: triage also checks its links and attachments. */
function TriageOffer({ message }: { message: string }) {
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-lg border border-border bg-surface p-4 text-sm">
      <span className="min-w-0 flex-1 basis-60">This is a whole email, not just its headers. Phishing triage also checks its links and attachments.</span>
      <a
        href={TRIAGE_PATH}
        onClick={(e) => {
          if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
          e.preventDefault();
          handOffMessage(message);
          navigate(TRIAGE_PATH);
        }}
        className="inline-flex min-h-11 items-center rounded-md bg-accent px-4 font-medium text-on-accent"
      >
        Open in phishing triage
      </a>
    </div>
  );
}

/** Short chip labels; KIND_LABELS has the long form. */
const CHIP_LABELS: Partial<Record<IndicatorKind, string>> = {
  ipv4: "IPv4",
  ipv6: "IPv6",
  md5: "MD5",
  sha1: "SHA-1",
  sha256: "SHA-256",
  email: "Email address",
  "url-encoded": "URL decode",
};

function Chip({ pressed, onClick, children }: { pressed: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button
      type="button"
      aria-pressed={pressed}
      onClick={onClick}
      className={[
        "min-h-11 rounded-full border px-4 text-sm font-medium",
        pressed ? "border-accent bg-accent text-on-accent" : "border-border text-muted hover:text-fg",
      ].join(" ")}
    >
      {children}
    </button>
  );
}

function Tool({ detection, onUseAsInput }: { detection: Detection; onUseAsInput: (text: string) => void }) {
  switch (detection.kind) {
    case "jwt":
      return <JwtTool token={detection.value} />;
    case "base64":
      return <Base64Tool value={detection.value} onUseAsInput={onUseAsInput} />;
    case "url":
      return <UrlTool href={detection.value} />;
    case "url-encoded":
      return <UrlDecodeTool text={detection.value} />;
    case "email-headers":
      return <HeaderTool raw={detection.value} />;
    default:
      return <IndicatorTool detection={detection} />;
  }
}

interface LookupPageProps {
  initialValue?: string;
  heading?: string;
  lead?: string;
  /** Offered via "Try an example" while the box is empty. */
  example?: string;
  placeholder?: string;
  /** Show "All indicators" first when a paste has any (the IOC extractor page). */
  preferBulk?: boolean;
}

/** The "All indicators" chip: every indicator in the paste, extracted in bulk. */
const BULK = "bulk" as const;

export function LookupPage({
  initialValue = "",
  heading = "Lookup",
  lead = "Paste an IP, domain, URL, hash, email address, JWT, base64 or raw email headers.",
  example,
  placeholder = "e.g. 203.0.113.7, example.com, a JWT or email headers",
  preferBulk = false,
}: LookupPageProps) {
  const [input, setInput] = useState(initialValue);
  const [chosen, setChosen] = useState<IndicatorKind | typeof BULK | null>(null);
  // Keep typing responsive on big pastes; analysis catches up a frame later.
  const deferred = useDeferredValue(input);
  const detections = useMemo(() => detect(deferred), [deferred]);
  const extracted = useMemo(() => extractIndicators(deferred), [deferred]);
  // Offer the bulk view when there's more than one indicator, or one that the single-item detector missed.
  const bulkAvailable = extracted.length >= 2 || (extracted.length === 1 && detections.length === 0);
  const bulk = bulkAvailable && (chosen === BULK || ((preferBulk || detections.length === 0) && chosen === null));
  const active = bulk ? undefined : (detections.find((d) => d.kind === chosen) ?? detections[0]);
  const atLimit = input.length >= MAX_PASTE_LENGTH;

  const resultsRef = useRef<HTMLDivElement>(null);
  const multiline = input.includes("\n");

  const replaceInput = (text: string) => {
    setInput(text.slice(0, MAX_PASTE_LENGTH));
    setChosen(null);
  };

  // Detection is already live; this closes the phone keyboard and brings the results into view.
  const showResults = () => {
    const results = resultsRef.current;
    if (!results) return;
    results.focus({ preventScroll: true });
    const smooth = !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    requestAnimationFrame(() => results.scrollIntoView({ behavior: smooth ? "smooth" : "auto", block: "start" }));
  };

  return (
    <section aria-labelledby="lookup-heading" className="space-y-4">
      <div>
        <h1 id="lookup-heading" className="text-2xl font-semibold tracking-tight">
          {heading}
        </h1>
        <p className="mt-1 text-muted">{lead}</p>
      </div>
      <div className="rounded-lg border border-border bg-surface p-4">
        <label htmlFor="paste" className="block text-sm font-medium">
          Indicator or text
        </label>
        <textarea
          id="paste"
          rows={6}
          maxLength={MAX_PASTE_LENGTH}
          spellCheck={false}
          autoComplete="off"
          autoCapitalize="off"
          placeholder={placeholder}
          // One-line indicators: the return key reads "Go" and shows results. Multi-line text (headers) keeps newlines.
          enterKeyHint={multiline ? "enter" : "go"}
          value={input}
          onChange={(e) => replaceInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing && !multiline && input.trim()) {
              e.preventDefault();
              showResults();
            }
          }}
          className="mt-2 w-full resize-y rounded-md border border-border bg-ground p-3 font-mono text-sm text-fg placeholder:text-muted focus:border-accent focus:outline-none"
        />
        <p className="mt-2 text-sm text-muted">
          {atLimit
            ? "Limit reached: only the first 64 KB is analysed."
            : "Runs in your browser. Nothing is sent unless you choose Check reputation, and nothing is stored."}
        </p>
        <div className="mt-3 flex gap-2">
          <button
            type="button"
            onClick={showResults}
            disabled={!input.trim()}
            className="min-h-11 flex-1 rounded-md bg-accent px-4 text-sm font-medium text-on-accent disabled:opacity-50 sm:flex-none"
          >
            Analyse
          </button>
          {!input && example && (
            <button
              type="button"
              onClick={() => replaceInput(example)}
              className="min-h-11 rounded-md border border-border px-4 text-sm text-muted hover:text-fg"
            >
              Try an example
            </button>
          )}
          {input && (
            <button
              type="button"
              onClick={() => replaceInput("")}
              className="min-h-11 rounded-md border border-border px-4 text-sm text-muted hover:text-fg"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      <div ref={resultsRef} tabIndex={-1} aria-label="Results" className="scroll-mt-4 space-y-4 focus:outline-none">
        {(active || bulk) && (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Detected type">
              <span className="text-sm text-muted">Detected:</span>
              {detections.map((d) => (
                <Chip key={d.kind} pressed={d.kind === active?.kind} onClick={() => setChosen(d.kind)}>
                  {CHIP_LABELS[d.kind] ?? KIND_LABELS[d.kind]}
                </Chip>
              ))}
              {bulkAvailable && (
                <Chip pressed={bulk} onClick={() => setChosen(BULK)}>
                  All indicators ({extracted.length})
                </Chip>
              )}
            </div>
            {active?.refanged && <p className="text-sm text-muted">Defanged input was refanged for analysis.</p>}
          </div>
        )}

        {deferred.trim() && !active && !bulk && (
          <p className="rounded-lg border border-border bg-surface p-4 text-sm text-muted">
            Couldn't find anything to analyse. Paste an indicator, a JWT, base64, the full headers of an email, or any text
            containing IPs, domains, URLs or hashes.
          </p>
        )}

        {active?.kind === "email-headers" && looksLikeFullMessage(deferred) && <TriageOffer message={deferred} />}
        {active && <Tool key={`${active.kind}:${active.value}`} detection={active} onUseAsInput={replaceInput} />}
        {bulk && <BulkTool items={extracted} onUseAsInput={replaceInput} />}
      </div>
    </section>
  );
}
