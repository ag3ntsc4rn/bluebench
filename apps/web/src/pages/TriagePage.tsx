import { exportVerdict, MAX_PASTE_LENGTH, type ExportVerdicts, type Extracted } from "@bluebench/shared";
import { useCallback, useDeferredValue, useEffect, useMemo, useRef, useState, type DragEvent } from "react";
import { BulkTool, type BulkResult } from "../components/tools/BulkTool";
import { HeaderTool } from "../components/tools/HeaderTool";
import { IndicatorTool } from "../components/tools/IndicatorTool";
import { UrlTool } from "../components/tools/UrlTool";
import { AppLink } from "../components/AppLink";
import { Badge, CopyButton, FindingList, Panel } from "../components/ui";
import { analyzeHeaders } from "../lib/email-headers";
import { MAX_EML_BYTES, parseMime, type ParsedMessage } from "../lib/mime";
import {
  clearHandOff,
  collectLinks,
  formatSize,
  NO_FLAGS,
  peekHandOff,
  readHtml,
  reportAttachment,
  sha256Hex,
  ticketNote,
  triageFlags,
  triageIndicators,
  type TriageLink,
} from "../lib/triage";
import { RUNBOOKS } from "../runbooks";

const PHISHING_RUNBOOK = RUNBOOKS.find((r) => r.slug === "phishing-link-clicked")!;

interface LoadedFile {
  name: string;
  bytes: Uint8Array<ArrayBuffer>;
}

function LinkRow({ link }: { link: TriageLink }) {
  const worst = link.findings[0];
  return (
    <li className="space-y-1 py-3">
      <div className="flex flex-wrap items-start gap-2">
        <span className="min-w-0 flex-1 basis-48 font-mono text-sm break-all">{link.href}</span>
        {worst ? (
          <Badge tone={worst.severity === "critical" ? "critical" : "warn"}>{worst.severity === "critical" ? "Red flag" : "Warning"}</Badge>
        ) : null}
      </div>
      {link.text !== undefined && (
        <p className="text-sm text-muted">
          Shown as: <span className="break-all text-fg">{link.text || "(no text, e.g. an image)"}</span>
        </p>
      )}
      {link.source === "text" && <p className="text-sm text-muted">Written in the plain-text body.</p>}
      {link.findings.length > 0 && <FindingList findings={link.findings} />}
    </li>
  );
}

/** One indicator picked from the list, analysed on its own below it. */
function SingleIndicator({ item }: { item: Extracted }) {
  const detection = { kind: item.kind, value: item.value, refanged: false };
  return item.kind === "url" ? <UrlTool href={item.value} /> : <IndicatorTool detection={detection} />;
}

function TriageResults({ msg, onOpenMessage }: { msg: ParsedMessage; onOpenMessage: (name: string, bytes: Uint8Array<ArrayBuffer>) => void }) {
  const html = useMemo(() => msg.html.map(readHtml), [msg]);
  const headers = useMemo(() => (msg.headers.trim() ? analyzeHeaders(msg.headers) : null), [msg]);
  const links = useMemo(() => collectLinks(msg, html), [msg, html]);
  const attachments = useMemo(() => msg.attachments.map(reportAttachment), [msg]);

  const [hashes, setHashes] = useState<(string | undefined)[]>([]);
  useEffect(() => {
    let live = true;
    setHashes([]);
    void Promise.all(msg.attachments.map((a) => sha256Hex(a.bytes).catch(() => undefined))).then((h) => {
      if (live) setHashes(h);
    });
    return () => {
      live = false;
    };
  }, [msg]);

  const indicators = useMemo(
    () => triageIndicators(msg, html, links, headers, hashes.filter((h): h is string => Boolean(h))),
    [msg, html, links, headers, hashes],
  );
  const flags = useMemo(() => triageFlags(headers, links, attachments), [headers, links, attachments]);

  const [verdicts, setVerdicts] = useState<ExportVerdicts>(new Map());
  const onResults = useCallback((results: ReadonlyMap<string, BulkResult>) => {
    setVerdicts(new Map([...results].flatMap(([k, r]) => (r.ok ? [[k, exportVerdict(r)] as const] : []))));
  }, []);

  const [single, setSingle] = useState<Extracted | null>(null);
  const singleRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (single) singleRef.current?.scrollIntoView({ block: "start" });
  }, [single]);

  const note = ticketNote({ headers, flags, attachments, hashes, indicators, verdicts });
  const flaggedLinks = links.filter((l) => l.findings.length > 0).length;

  return (
    <div className="space-y-4">
      <Panel title="Summary" aside={<CopyButton value={note} label="Copy as ticket note" />}>
        {flags.length > 0 ? (
          <FindingList findings={flags} />
        ) : (
          <p className="flex items-start gap-2 text-sm">
            <Badge tone="neutral">Note</Badge>
            <span>{NO_FLAGS}</span>
          </p>
        )}
        <p className="text-sm text-muted">
          {links.length} link{links.length === 1 ? "" : "s"}, {attachments.length} attachment{attachments.length === 1 ? "" : "s"},{" "}
          {indicators.length} indicator{indicators.length === 1 ? "" : "s"}. Nothing was opened or visited, and nothing leaves your
          browser unless you press Check reputation.
        </p>
        {msg.warnings.length > 0 && (
          <ul className="space-y-2">
            {msg.warnings.map((w) => (
              <li key={w} className="flex items-start gap-2 text-sm">
                <Badge tone="neutral">Note</Badge>
                <span>{w}</span>
              </li>
            ))}
          </ul>
        )}
        <p className="rounded-md border border-border bg-ground p-3 text-sm">
          If someone clicked a link or opened an attachment:{" "}
          <AppLink href={PHISHING_RUNBOOK.path} className="inline-flex min-h-11 items-center text-accent underline">
            follow the phishing response checklist
          </AppLink>
        </p>
      </Panel>

      {headers ? (
        <HeaderTool raw={msg.headers} />
      ) : (
        <Panel title="Email headers">
          <p className="text-sm text-muted">
            No headers found, so the sender can't be checked. Paste the whole message source (Show original, or View source),
            starting with the headers.
          </p>
        </Panel>
      )}

      <Panel title="Links" aside={<span className="text-sm text-muted">{links.length}</span>}>
        {links.length === 0 ? (
          <p className="text-sm text-muted">No links found.</p>
        ) : (
          <>
            <p className="text-sm text-muted">
              {flaggedLinks > 0 ? `${flaggedLinks} of ${links.length} need a closer look. ` : ""}Read from the message without
              loading it: links aren't visited and images aren't fetched.
            </p>
            <ul className="divide-y divide-border">
              {links.map((l, i) => (
                <LinkRow key={i} link={l} />
              ))}
            </ul>
          </>
        )}
      </Panel>

      <Panel title="Attachments" aside={<span className="text-sm text-muted">{attachments.length}</span>}>
        {attachments.length === 0 ? (
          <p className="text-sm text-muted">No attachments.</p>
        ) : (
          <ul className="space-y-3">
            {attachments.map((a, i) => (
              <li key={i} className="space-y-2 rounded-md border border-border bg-ground p-3 text-sm">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <span className="min-w-0 font-medium break-all">{a.filename}</span>
                  {a.findings[0] ? (
                    <Badge tone={a.findings[0].severity === "critical" ? "critical" : "warn"}>{a.findings[0].severity === "critical" ? "Red flag" : "Warning"}</Badge>
                  ) : (
                    <Badge tone="neutral">Nothing obvious</Badge>
                  )}
                </div>
                <dl className="grid grid-cols-[minmax(6rem,40%)_minmax(0,1fr)] gap-x-4 gap-y-1">
                  <dt className="text-muted">Declared type</dt>
                  <dd className="min-w-0 font-mono break-all">{a.contentType}</dd>
                  <dt className="text-muted">Size</dt>
                  <dd>{formatSize(a.size)}</dd>
                  <dt className="text-muted">Content looks like</dt>
                  <dd>{a.sniffed ?? "Not recognised"}</dd>
                  <dt className="text-muted">SHA-256</dt>
                  <dd className="min-w-0 font-mono break-all">{hashes[i] ?? "Calculating…"}</dd>
                </dl>
                {a.findings.length > 0 && <FindingList findings={a.findings} />}
                {a.contentType === "message/rfc822" && (
                  <button
                    type="button"
                    onClick={() => onOpenMessage(a.filename, msg.attachments[i]!.bytes)}
                    className="min-h-11 rounded-md border border-border px-3 text-sm text-muted hover:text-fg"
                  >
                    Triage the attached message
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
        {attachments.length > 0 && (
          <p className="text-xs text-muted">
            Attachments are never opened. Hashes are calculated in your browser; check them below with Check reputation.
          </p>
        )}
      </Panel>

      {indicators.length > 0 ? (
        <BulkTool
          items={indicators}
          onResults={onResults}
          onUseAsInput={(value) => setSingle(indicators.find((i) => i.value === value) ?? null)}
        />
      ) : (
        <Panel title="Indicators found">
          <p className="text-sm text-muted">No URLs, domains, IP addresses, email addresses or hashes found.</p>
        </Panel>
      )}

      {single && (
        <div ref={singleRef} className="scroll-mt-4 space-y-2">
          <button type="button" onClick={() => setSingle(null)} className="min-h-11 rounded-md border border-border px-3 text-sm text-muted hover:text-fg">
            Close {single.value.length > 40 ? "indicator" : single.value}
          </button>
          <SingleIndicator key={`${single.kind}:${single.value}`} item={single} />
        </div>
      )}
    </div>
  );
}

export function TriagePage({ heading, lead, example, placeholder }: { heading: string; lead: string; example: string; placeholder: string }) {
  // A message handed over from the Lookup paste box (memory only). Cleared once mounted.
  const [paste, setPaste] = useState(() => peekHandOff() ?? "");
  useEffect(() => clearHandOff(), []);
  const [file, setFile] = useState<LoadedFile | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const [run, setRun] = useState(0);

  // Keep typing responsive on big pastes; analysis catches up a frame later.
  const deferred = useDeferredValue(paste);
  const fileBytes = file?.bytes;
  const msg = useMemo(() => (fileBytes ? parseMime(fileBytes) : deferred.trim() ? parseMime(deferred) : null), [fileBytes, deferred]);
  const loaded = Boolean(file) || paste.trim() !== "";

  const resultsRef = useRef<HTMLDivElement>(null);

  const loadFile = async (f: File) => {
    setError(null);
    if (f.size > MAX_EML_BYTES) {
      setError(`${f.name} is ${formatSize(f.size)}. The limit is 10 MB: forward the message without large attachments, or paste its source instead.`);
      return;
    }
    try {
      const bytes = new Uint8Array(await f.arrayBuffer());
      if (bytes[0] === 0xd0 && bytes[1] === 0xcf && bytes[2] === 0x11 && bytes[3] === 0xe0) {
        setError(`${f.name} is an Outlook .msg file, which can't be read here. In Outlook, save it as .eml, or copy the message source and paste it.`);
        return;
      }
      openBytes(f.name, bytes);
    } catch {
      setError(`Couldn't read ${f.name}.`);
    }
  };

  const openBytes = (name: string, bytes: Uint8Array<ArrayBuffer>) => {
    setPaste("");
    setFile({ name, bytes });
    setRun((n) => n + 1);
    requestAnimationFrame(() => resultsRef.current?.scrollIntoView({ block: "start" }));
  };

  const clear = () => {
    setPaste("");
    setFile(null);
    setError(null);
    setRun((n) => n + 1);
  };

  const onDrop = (e: DragEvent<HTMLDivElement>) => {
    setDragging(false);
    const f = e.dataTransfer.files[0];
    if (!f) return; // dropped text goes into the box as usual
    e.preventDefault();
    void loadFile(f);
  };

  return (
    <section aria-labelledby="triage-heading" className="space-y-4">
      <div>
        <h1 id="triage-heading" className="text-2xl font-semibold tracking-tight">
          {heading}
        </h1>
        <p className="mt-1 text-muted">{lead}</p>
      </div>

      <div
        data-triage-loaded={loaded ? "" : undefined}
        onDragOver={(e) => {
          if (![...e.dataTransfer.types].includes("Files")) return;
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        className={["rounded-lg border bg-surface p-4", dragging ? "border-accent" : "border-border"].join(" ")}
      >
        {file ? (
          <p className="block text-sm font-medium">Message file</p>
        ) : (
          <label htmlFor="triage-paste" className="block text-sm font-medium">
            Raw message (headers and body)
          </label>
        )}
        {file ? (
          <p className="mt-2 flex flex-wrap items-center gap-2 rounded-md border border-border bg-ground p-3 text-sm">
            <Badge tone="neutral">File</Badge>
            <span className="min-w-0 font-mono break-all">{file.name}</span>
            <span className="text-muted">{formatSize(file.bytes.length)}</span>
          </p>
        ) : (
          <textarea
            id="triage-paste"
            rows={8}
            maxLength={MAX_PASTE_LENGTH}
            spellCheck={false}
            autoComplete="off"
            autoCapitalize="off"
            placeholder={placeholder}
            value={paste}
            onChange={(e) => {
              setPaste(e.target.value.slice(0, MAX_PASTE_LENGTH));
              setError(null);
            }}
            className="mt-2 w-full resize-y rounded-md border border-border bg-ground p-3 font-mono text-sm text-fg placeholder:text-muted focus:border-accent focus:outline-none"
          />
        )}
        <p className="mt-2 text-sm text-muted">
          {paste.length >= MAX_PASTE_LENGTH
            ? "Limit reached: only the first 64 KB is analysed. For longer messages, choose the .eml file instead."
            : "Or drop an .eml file here (up to 10 MB). Read in your browser: nothing is sent unless you choose Check reputation."}
        </p>
        {error && (
          <p role="alert" className="mt-2 flex items-start gap-2 text-sm">
            <Badge tone="warn">Can't read</Badge>
            <span>{error}</span>
          </p>
        )}
        <div className="mt-3 flex flex-wrap gap-2">
          <label className="inline-flex min-h-11 cursor-pointer items-center rounded-md bg-accent px-4 text-sm font-medium text-on-accent has-focus-visible:outline-2 has-focus-visible:outline-offset-2 has-focus-visible:outline-accent">
            Choose .eml file
            <input
              type="file"
              accept=".eml,message/rfc822,text/plain"
              className="sr-only"
              onChange={(e) => {
                const f = e.target.files?.[0];
                e.target.value = "";
                if (f) void loadFile(f);
              }}
            />
          </label>
          {!loaded && (
            <button
              type="button"
              onClick={() => {
                setPaste(example);
                setRun((n) => n + 1);
              }}
              className="min-h-11 rounded-md border border-border px-4 text-sm text-muted hover:text-fg"
            >
              Try an example
            </button>
          )}
          {loaded && (
            <button type="button" onClick={clear} className="min-h-11 rounded-md border border-border px-4 text-sm text-muted hover:text-fg">
              Clear
            </button>
          )}
        </div>
      </div>

      <div ref={resultsRef} aria-label="Results" className="scroll-mt-4">
        {msg && <TriageResults key={run + (file ? `f:${file.name}` : "p")} msg={msg} onOpenMessage={openBytes} />}
      </div>
    </section>
  );
}
