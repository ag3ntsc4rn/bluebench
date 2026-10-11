import { detect, KIND_LABELS, MAX_PASTE_LENGTH, type Detection, type IndicatorKind } from "@bluebench/shared";
import { useDeferredValue, useMemo, useRef, useState } from "react";
import { Base64Tool } from "../components/tools/Base64Tool";
import { HeaderTool } from "../components/tools/HeaderTool";
import { IndicatorTool } from "../components/tools/IndicatorTool";
import { JwtTool } from "../components/tools/JwtTool";
import { UrlDecodeTool, UrlTool } from "../components/tools/UrlTool";

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

export function LookupPage({ initialValue = "" }: { initialValue?: string }) {
  const [input, setInput] = useState(initialValue);
  const [chosen, setChosen] = useState<IndicatorKind | null>(null);
  // Keep typing responsive on big pastes; analysis catches up a frame later.
  const deferred = useDeferredValue(input);
  const detections = useMemo(() => detect(deferred), [deferred]);
  const active = detections.find((d) => d.kind === chosen) ?? detections[0];
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
          Lookup
        </h1>
        <p className="mt-1 text-muted">
          Paste an IP, domain, URL, hash, email address, JWT, base64 or raw email headers.
        </p>
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
          placeholder="e.g. 203.0.113.7 or example.com"
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
        {active && (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Detected type">
              <span className="text-sm text-muted">Detected:</span>
              {detections.map((d) => (
                <button
                  key={d.kind}
                  type="button"
                  aria-pressed={d.kind === active.kind}
                  onClick={() => setChosen(d.kind)}
                  className={[
                    "min-h-11 rounded-full border px-4 text-sm font-medium",
                    d.kind === active.kind ? "border-accent bg-accent text-on-accent" : "border-border text-muted hover:text-fg",
                  ].join(" ")}
                >
                  {CHIP_LABELS[d.kind] ?? KIND_LABELS[d.kind]}
                </button>
              ))}
            </div>
            {active.refanged && <p className="text-sm text-muted">Defanged input was refanged for analysis.</p>}
          </div>
        )}

        {deferred.trim() && !active && (
          <p className="rounded-lg border border-border bg-surface p-4 text-sm text-muted">
            Couldn't recognise this. Paste one indicator at a time, or the full headers of an email.
          </p>
        )}

        {active && <Tool key={`${active.kind}:${active.value}`} detection={active} onUseAsInput={replaceInput} />}
      </div>
    </section>
  );
}
