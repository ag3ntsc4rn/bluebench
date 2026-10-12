import { MAX_SAVED_DOMAINS, type ApiError, type Grade, type SavedDomain } from "@bluebench/shared";
import { useEffect, useState, type FormEvent } from "react";
import { listDomains, removeDomain, saveDomain, useAccount, verifyDomain } from "../lib/account";
import { domainFromInput } from "../lib/domain-input";
import { SignInForm } from "./SignInForm";
import { Badge, CopyButton, type Tone } from "./ui";

const GRADE_TONE: Record<Grade, Tone> = { A: "ok", B: "ok", C: "warn", D: "warn", F: "critical" };

const date = (iso: string) => new Date(iso).toLocaleDateString(undefined, { dateStyle: "medium" });

const USES = (h: SavedDomain["lookalikes"][number]) => [h.web && "website", h.mail && "mail"].filter(Boolean).join(" + ");

/** Lookalike domains that resolve, from the daily watcher. */
function Lookalikes({ d }: { d: SavedDomain }) {
  if (!d.lookalikesScannedAt && d.lookalikes.length === 0) {
    return <p className="text-sm text-muted">The first lookalike scan runs within the day.</p>;
  }
  if (d.lookalikes.length === 0) {
    return <p className="text-sm text-muted">No lookalike domains with a website or mail found. Checked daily.</p>;
  }
  const n = d.lookalikes.length;
  return (
    <details className="rounded-md border border-border">
      <summary className="flex min-h-11 cursor-pointer items-center gap-2 px-3 text-sm">
        <Badge tone="warn">{`${n} lookalike${n === 1 ? "" : "s"}`}</Badge>
        <span>Domains that look like this one and resolve</span>
      </summary>
      <div className="space-y-2 border-t border-border p-3">
        <ul className="space-y-1">
          {d.lookalikes.map((h) => (
            <li key={h.domain} className="flex flex-wrap items-baseline justify-between gap-x-3 text-sm">
              <span className="font-mono break-all">{h.domain}</span>
              <span className="text-muted">
                {USES(h)} · since {date(h.firstSeenAt)}
              </span>
            </li>
          ))}
        </ul>
        <p className="text-sm text-muted">
          Some may be yours or harmless. Ones you don't recognise could be used for phishing: warn your users, and report abuse to the registrar or host.
        </p>
      </div>
    </details>
  );
}

function DomainRow({ d, onChange, onRemoved, onCheck }: { d: SavedDomain; onChange: (d: SavedDomain) => void; onRemoved: () => void; onCheck: () => void }) {
  const [message, setMessage] = useState<{ tone: "ok" | "warn"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmRemove, setConfirmRemove] = useState(false);

  const verify = async () => {
    setBusy(true);
    const res = await verifyDomain(d.id);
    setBusy(false);
    if (res.ok) {
      onChange(res.domain);
      setMessage({ tone: "ok", text: "Verified. The first daily check runs within a few minutes." });
    } else setMessage({ tone: "warn", text: res.message });
  };

  const remove = async () => {
    if (!confirmRemove) return setConfirmRemove(true);
    setBusy(true);
    const res = await removeDomain(d.id);
    setBusy(false);
    if (res.ok) onRemoved();
    else setMessage({ tone: "warn", text: res.message });
  };

  return (
    <li className="space-y-3 border-t border-border pt-3 first:border-t-0 first:pt-0">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono break-all">{d.domain}</span>
        {d.verified ? <Badge tone="ok">Monitoring</Badge> : <Badge tone="warn">Not verified</Badge>}
        {d.grade && <Badge tone={GRADE_TONE[d.grade]}>{`Grade ${d.grade}`}</Badge>}
      </div>
      {d.verified && (
        <p className="text-sm text-muted">
          {d.lastCheckedAt && d.grade ? `Last daily check ${date(d.lastCheckedAt)}.` : "The first daily check runs within a few minutes."}
          {d.certExpiresAt && ` Certificate expires ${date(d.certExpiresAt)}.`}
        </p>
      )}
      {d.verified && <Lookalikes d={d} />}
      {!d.verified && (
        <div className="space-y-2">
          <p className="text-sm">
            To turn on daily monitoring and alerts, prove you control this domain: add this TXT record at{" "}
            <span className="font-mono break-all">{d.domain}</span>, then press Verify.
          </p>
          <div className="flex items-center gap-2 rounded-md border border-border bg-ground p-2">
            <code className="min-w-0 flex-1 font-mono text-sm break-all">{d.verifyRecord}</code>
            <CopyButton value={d.verifyRecord} />
          </div>
        </div>
      )}
      <div className="flex flex-wrap gap-2">
        {!d.verified && (
          <button
            type="button"
            onClick={() => void verify()}
            disabled={busy}
            className="min-h-11 rounded-md bg-accent px-4 text-sm font-medium text-on-accent disabled:opacity-50"
          >
            Verify
          </button>
        )}
        <button type="button" onClick={onCheck} className="min-h-11 rounded-md border border-border px-3 text-sm text-muted hover:text-fg">
          Check now
        </button>
        <button
          type="button"
          onClick={() => void remove()}
          onBlur={() => setConfirmRemove(false)}
          disabled={busy}
          className="min-h-11 rounded-md border border-border px-3 text-sm text-muted hover:text-fg disabled:opacity-50"
        >
          {confirmRemove ? "Tap again to remove" : "Remove"}
        </button>
      </div>
      {message && (
        <p aria-live="polite" className="flex items-start gap-2 text-sm">
          <Badge tone={message.tone}>{message.tone === "ok" ? "Done" : "Not yet"}</Badge>
          <span>{message.text}</span>
        </p>
      )}
    </li>
  );
}

function DomainList({ onCheck }: { onCheck: (domain: string) => void }) {
  const [domains, setDomains] = useState<SavedDomain[] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [input, setInput] = useState("");
  const [saving, setSaving] = useState(false);
  const domain = domainFromInput(input);

  useEffect(() => {
    void listDomains().then((res) => (res.ok ? setDomains(res.domains) : setError(res)));
  }, []);

  const add = async (e: FormEvent) => {
    e.preventDefault();
    if (!domain) return;
    setSaving(true);
    const res = await saveDomain(domain);
    setSaving(false);
    if (res.ok) {
      setDomains((ds) => [...(ds ?? []), res.domain]);
      setInput("");
      setError(null);
    } else setError(res);
  };

  const full = (domains?.length ?? 0) >= MAX_SAVED_DOMAINS;
  return (
    <div className="space-y-4 rounded-lg border border-border bg-surface p-4">
      {domains === null && !error && <p className="text-sm text-muted">Loading…</p>}
      {domains?.length === 0 && <p className="text-sm text-muted">No saved domains yet. Add one you run to get alerts when its grade drops, its certificate is about to expire or a lookalike domain appears.</p>}
      {domains && domains.length > 0 && (
        <ul className="space-y-3">
          {domains.map((d) => (
            <DomainRow
              key={d.id}
              d={d}
              onChange={(next) => setDomains((ds) => ds!.map((x) => (x.id === next.id ? next : x)))}
              onRemoved={() => setDomains((ds) => ds!.filter((x) => x.id !== d.id))}
              onCheck={() => onCheck(d.domain)}
            />
          ))}
        </ul>
      )}
      {domains && !full && (
        <form onSubmit={(e) => void add(e)} className="flex flex-wrap items-end gap-2 border-t border-border pt-3">
          <div className="min-w-0 flex-1">
            <label htmlFor="save-domain" className="block text-sm font-medium">
              Add a domain ({domains.length} of {MAX_SAVED_DOMAINS})
            </label>
            <input
              id="save-domain"
              type="text"
              inputMode="url"
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              placeholder="example.com"
              value={input}
              onChange={(e) => setInput(e.target.value.slice(0, 2048))}
              className="mt-1 min-h-11 w-full rounded-md border border-border bg-ground px-3 font-mono text-sm text-fg placeholder:text-muted focus:border-accent focus:outline-none"
            />
          </div>
          <button type="submit" disabled={!domain || saving} className="min-h-11 rounded-md bg-accent px-4 text-sm font-medium text-on-accent disabled:opacity-50">
            Save
          </button>
        </form>
      )}
      {full && <p className="text-sm text-muted">That's the maximum of {MAX_SAVED_DOMAINS}. Remove one to add another.</p>}
      {error && (
        <p aria-live="polite" className="flex items-start gap-2 text-sm">
          <Badge tone="warn">Error</Badge>
          <span>{error.message}</span>
        </p>
      )}
    </div>
  );
}

/** "Your domains": saved and monitored domains when signed in, otherwise an invitation to sign in. */
export function MyDomains({ onCheck }: { onCheck: (domain: string) => void }) {
  const me = useAccount();
  return (
    <section aria-labelledby="my-domains-heading" className="space-y-3">
      <h2 id="my-domains-heading" className="text-lg font-semibold">
        Your domains
      </h2>
      {me === null && <p className="text-sm text-muted">Loading…</p>}
      {me?.signedIn && <DomainList onCheck={onCheck} />}
      {me && !me.signedIn && (
        <SignInForm
          lead={`Sign in to save up to ${MAX_SAVED_DOMAINS} domains. Bluebench re-checks verified ones daily and alerts you when a grade drops, a certificate is close to expiring or a lookalike domain appears.`}
        />
      )}
    </section>
  );
}
