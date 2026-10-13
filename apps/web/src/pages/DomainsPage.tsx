import { CHECK_LABELS, type ApiError, type CheckStatus, type DomainCheck, type DomainReport, type Grade } from "@bluebench/shared";
import { useRef, useState, type FormEvent } from "react";
import { MyDomains } from "../components/MyDomains";
import { Badge, CopyButton, Facts, WhatsThis, type Tone } from "../components/ui";
import { checkDomain } from "../lib/api";
import { CHECK_EXPLAINERS } from "../lib/explainers";
import { domainFromInput } from "../lib/domain-input";
import { summarizeDomain } from "../lib/summaries";
import { runTurnstile } from "../lib/turnstile";

const GRADE: Record<Grade, { tone: Tone; text: string }> = {
  A: { tone: "ok", text: "Strong. Nothing important missing." },
  B: { tone: "ok", text: "Good, with a few things to tighten." },
  C: { tone: "warn", text: "Fair. Some real gaps worth fixing." },
  D: { tone: "warn", text: "Weak. Several important protections missing." },
  F: { tone: "critical", text: "Poor. Easy to spoof or intercept." },
};

const GRADE_CLASSES: Record<Tone, string> = {
  ok: "border-ok text-ok",
  warn: "border-warn text-warn",
  critical: "border-critical text-critical",
  neutral: "border-border text-muted",
};

const STATUS: Record<CheckStatus, { tone: Tone; label: string }> = {
  pass: { tone: "ok", label: "Pass" },
  warn: { tone: "warn", label: "Warning" },
  fail: { tone: "critical", label: "Fail" },
  info: { tone: "neutral", label: "Info" },
  skipped: { tone: "neutral", label: "Skipped" },
};

function CheckRow({ check }: { check: DomainCheck }) {
  const status = STATUS[check.status];
  return (
    <li className="space-y-2 border-t border-border pt-3 first:border-t-0 first:pt-0">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{CHECK_LABELS[check.id]}</span>
        <Badge tone={status.tone}>{status.label}</Badge>
      </div>
      <p className="text-sm">{check.summary}</p>
      {check.fix && (
        <p className="rounded-md border border-border bg-ground p-2 text-sm">
          <span className="font-medium">Fix: </span>
          {check.fix}
        </p>
      )}
      {check.facts.length > 0 && <Facts rows={check.facts.map((f) => [f.label, f.value])} />}
      <WhatsThis>{CHECK_EXPLAINERS[check.id]}</WhatsThis>
    </li>
  );
}

const ORDER: Record<CheckStatus, number> = { fail: 0, warn: 1, pass: 2, info: 3, skipped: 4 };

export function DomainReportView({ report }: { report: DomainReport }) {
  const grade = GRADE[report.grade];
  const checks = [...report.checks].sort((a, b) => ORDER[a.status] - ORDER[b.status]);
  const when = new Date(report.checkedAt).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  return (
    <section aria-label={`Report for ${report.domain}`} className="space-y-4 rounded-lg border border-border bg-surface p-4">
      <div className="flex items-center gap-4">
        <p
          className={`flex size-16 shrink-0 items-center justify-center rounded-lg border-2 text-3xl font-semibold ${GRADE_CLASSES[grade.tone]}`}
          aria-label={`Grade ${report.grade}`}
        >
          {report.grade}
        </p>
        <div className="min-w-0 flex-1">
          <h2 className="font-mono text-base break-all">{report.domain}</h2>
          <p className="text-sm">
            Grade {report.grade} ({report.score}/100). {grade.text}
          </p>
          <p className="text-xs text-muted">
            Checked {when}
            {report.cached ? " (cached; results refresh hourly)" : ""}
          </p>
        </div>
        <CopyButton value={summarizeDomain(report)} label="Copy result" />
      </div>
      <ul className="space-y-3">
        {checks.map((c) => (
          <CheckRow key={c.id} check={c} />
        ))}
      </ul>
    </section>
  );
}

type State = { phase: "idle" } | { phase: "loading" } | { phase: "done"; report: DomainReport } | { phase: "error"; error: ApiError };

interface DomainsPageProps {
  heading?: string;
  lead?: string;
}

export function DomainsPage({
  heading = "Domains",
  lead = "Get a report card for a domain's email and web security: SPF, DMARC, DKIM, DNSSEC, HTTPS, HSTS, headers and certificate expiry.",
}: DomainsPageProps) {
  const [input, setInput] = useState("");
  const [state, setState] = useState<State>({ phase: "idle" });
  const challengeRef = useRef<HTMLDivElement>(null);
  const formRef = useRef<HTMLFormElement>(null);
  const domain = domainFromInput(input);

  const check = async (target: string) => {
    setState({ phase: "loading" });
    const res = await checkDomain(target, (siteKey) => runTurnstile(challengeRef.current!, siteKey));
    setState(res.ok ? { phase: "done", report: res } : { phase: "error", error: res });
  };

  const run = (e: FormEvent) => {
    e.preventDefault();
    if (domain) void check(domain);
  };

  /** "Check now" on a saved domain: fill in the checker, run it and bring it into view. */
  const checkSaved = (target: string) => {
    setInput(target);
    formRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    void check(target);
  };

  return (
    <section aria-labelledby="domains-heading" className="space-y-4">
      <div>
        <h1 id="domains-heading" className="text-2xl font-semibold tracking-tight">
          {heading}
        </h1>
        <p className="mt-1 text-muted">{lead}</p>
      </div>
      <form ref={formRef} onSubmit={run} className="scroll-mt-4 space-y-3 rounded-lg border border-border bg-surface p-4">
        <label htmlFor="domain" className="block text-sm font-medium">
          Domain
        </label>
        <input
          id="domain"
          type="text"
          inputMode="url"
          enterKeyHint="go"
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          placeholder="example.com"
          value={input}
          onChange={(e) => setInput(e.target.value.slice(0, 2048))}
          className="min-h-11 w-full rounded-md border border-border bg-ground px-3 font-mono text-sm text-fg placeholder:text-muted focus:border-accent focus:outline-none"
        />
        <p className="text-sm text-muted">
          {input.trim() && !domain
            ? "That doesn't look like a domain. Try something like example.com."
            : input.trim() && domain && domain !== input.trim().toLowerCase()
              ? `Will check ${domain}.`
              : "A URL or email address works too. We check public DNS, the site's home page and certificate logs."}
        </p>
        <button
          type="submit"
          disabled={!domain || state.phase === "loading"}
          className="min-h-11 rounded-md bg-accent px-4 text-sm font-medium text-on-accent disabled:opacity-50"
        >
          {state.phase === "loading" ? "Checking… (up to 15 s)" : "Check domain"}
        </button>
        {/* Turnstile renders here, and only becomes visible if Cloudflare needs an interaction. */}
        <div ref={challengeRef} />
      </form>
      <div aria-live="polite" className="space-y-4">
        {state.phase === "error" && (
          <p className="flex items-start gap-2 text-sm">
            <Badge tone="warn">{state.error.error === "daily-limit" || state.error.error === "rate-limited" ? "Limit" : "Error"}</Badge>
            <span>{state.error.message}</span>
          </p>
        )}
        {state.phase === "done" && <DomainReportView report={state.report} />}
      </div>
      <MyDomains onCheck={checkSaved} />
    </section>
  );
}
