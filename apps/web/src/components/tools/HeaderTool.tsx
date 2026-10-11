import { analyzeHeaders, type AuthMethod, type AuthResult } from "../../lib/email-headers";
import { summarizeHeaders } from "../../lib/summaries";
import { Badge, CopyButton, Facts, FindingList, Panel, type Tone } from "../ui";

const METHOD_LABELS: Record<AuthMethod, string> = { spf: "SPF", dkim: "DKIM", dmarc: "DMARC" };

function authTone(result?: string): Tone {
  if (result === "pass") return "ok";
  if (result === "fail" || result === "permerror") return "critical";
  return "warn";
}

function AuthRow({ method, results }: { method: AuthMethod; results: AuthResult[] }) {
  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2 text-sm">
      <span className="w-14 font-medium">{METHOD_LABELS[method]}</span>
      {results.length === 0 ? (
        <Badge tone="warn">Not found</Badge>
      ) : (
        results.map((r, i) => (
          <span key={i} className="flex flex-wrap items-center gap-2">
            <Badge tone={authTone(r.result)}>{r.result.charAt(0).toUpperCase() + r.result.slice(1)}</Badge>
            {r.domain && <span className="font-mono break-all">{r.domain}</span>}
            {r.selector && <span className="text-muted">selector {r.selector}</span>}
          </span>
        ))
      )}
    </li>
  );
}

export function HeaderTool({ raw }: { raw: string }) {
  const a = analyzeHeaders(raw);
  const methods: AuthMethod[] = ["spf", "dkim", "dmarc"];

  return (
    <>
      <Panel title="Email headers" aside={<CopyButton value={summarizeHeaders(a)} label="Copy result" />}>
        <FindingList
          findings={a.findings}
          empty="No red flags found. That isn't proof the message is safe: check links and attachments too."
        />
        <Facts
          rows={[
            ["From", a.from ? `${a.from.display ? `${a.from.display} ` : ""}<${a.from.address}>` : "—"],
            ...(a.replyTo ? [["Reply-To", a.replyTo.address] as [string, string]] : []),
            ...(a.returnPath ? [["Return-Path", a.returnPath.address] as [string, string]] : []),
            ["Subject", a.subject ?? "—", true],
            ["Date", a.date ?? "—", true],
            ...(a.messageId ? [["Message-ID", a.messageId] as [string, string]] : []),
          ]}
        />
      </Panel>

      <Panel title="Authentication">
        <ul className="divide-y divide-border">
          {methods.map((m) => (
            <AuthRow key={m} method={m} results={a.auth.filter((r) => r.method === m)} />
          ))}
        </ul>
        {a.auth[0] && <p className="text-xs text-muted">From the {a.auth[0].source} header added by the receiving server.</p>}
        {a.dkimSignatures.length > 0 && (
          <Facts rows={a.dkimSignatures.map((s, i) => [`DKIM signature ${i + 1}`, `d=${s.domain}${s.selector ? ` s=${s.selector}` : ""}`])} />
        )}
      </Panel>

      <Panel
        title="Hop path"
        aside={a.totalDelay && <span className="text-sm text-muted">Total {a.totalDelay}</span>}
      >
        {a.hops.length === 0 ? (
          <p className="text-sm text-muted">No Received headers found.</p>
        ) : (
          <ol className="space-y-3">
            {a.hops.map((hop, i) => (
              <li key={i} className="rounded-md border border-border bg-ground p-3 text-sm">
                <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
                  <span className="font-medium">Hop {i + 1}</span>
                  {hop.delayDisplay !== undefined && (
                    <Badge tone={hop.delay! < -60 ? "critical" : hop.delay! > 3600 ? "warn" : "neutral"}>
                      {hop.delay! < -60 ? "Time went backwards" : hop.delay! > 3600 ? "Slow" : "Delay"} {hop.delayDisplay}
                    </Badge>
                  )}
                </div>
                <Facts
                  rows={[
                    ["From", hop.from ?? "—"],
                    ...(hop.ip ? [["IP", hop.ip] as [string, string]] : []),
                    ["By", hop.by ?? "—"],
                    ...(hop.with ? [["With", hop.with] as [string, string]] : []),
                    ["Time", hop.atDisplay ?? "Unknown", true],
                  ]}
                />
              </li>
            ))}
          </ol>
        )}
        <p className="text-xs text-muted">Oldest first. Hops added before the message reached your provider can be forged.</p>
      </Panel>
    </>
  );
}
