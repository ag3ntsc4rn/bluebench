import { matchesKev, RECENT_DAYS, watchMatches, type ApiError, type KevEntry, type KevResponse, type Watch } from "@bluebench/shared";
import { useEffect, useId, useState } from "react";
import { Badge, WhatsThis } from "../components/ui";
import { Watchlist } from "../components/Watchlist";
import { addWatch, listWatches, removeWatch, useAccount } from "../lib/account";
import { fetchKev } from "../lib/api";
import { EPSS_EXPLAINER, KEV_EXPLAINER } from "../lib/explainers";

/** Entries shown at a time; "Show more" adds another page. */
const PAGE = 30;

const date = (d: string) => new Date(`${d}T00:00:00Z`).toLocaleDateString(undefined, { dateStyle: "medium", timeZone: "UTC" });
const pct = (p: number) => (p >= 0.995 ? ">99%" : p < 0.01 ? "<1%" : `${Math.round(p * 100)}%`);

/** Signed in: whether this entry's product is already watched, and how to watch it. */
type WatchControl = { watched: boolean; onWatch: () => void };

function Entry({ e, watch }: { e: KevEntry; watch?: WatchControl }) {
  return (
    <li className="space-y-2 rounded-lg border border-border bg-surface p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">
          {e.vendor} {e.product}
        </span>
        {e.ransomware && <Badge tone="critical">Used in ransomware</Badge>}
      </div>
      <p className="text-sm">{e.name}</p>
      <p className="flex flex-wrap items-center gap-x-3 text-sm text-muted">
        <a
          href={`https://www.cve.org/CVERecord?id=${e.cve}`}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex min-h-11 items-center font-mono underline hover:text-fg"
        >
          {e.cve}
        </a>
        <span>Added {date(e.added)}</span>
        {e.epss !== undefined && <span>Exploit likelihood (EPSS): {pct(e.epss)}</span>}
      </p>
      {e.description && <p className="text-sm text-muted">{e.description}</p>}
      <p className="rounded-md border border-border bg-ground p-2 text-sm">
        <span className="font-medium">What to do: </span>
        {e.action}
        {e.advisory && (
          <>
            {" "}
            <a href={e.advisory} target="_blank" rel="noopener noreferrer" className="text-accent underline">
              Vendor advisory
            </a>
          </>
        )}
      </p>
      {e.due && <p className="text-xs text-muted">CISA deadline for US federal agencies: {date(e.due)}</p>}
      {watch &&
        (watch.watched ? (
          <p className="flex min-h-11 items-center gap-2 text-sm text-muted">
            <Badge tone="ok">Watching</Badge> You'll be alerted about new entries for {e.vendor} {e.product}.
          </p>
        ) : (
          <button type="button" onClick={watch.onWatch} className="min-h-11 rounded-md border border-border px-3 text-sm text-muted hover:text-fg">
            Watch {e.vendor} {e.product}
          </button>
        ))}
    </li>
  );
}

type Load = { phase: "loading" } | { phase: "ready"; doc: KevResponse } | { phase: "error"; error: ApiError };

/** The Intel tab: actively exploited vulnerabilities, newest first, searchable by vendor or product. */
export function IntelPage() {
  const searchId = useId();
  const [recent, setRecent] = useState<Load>({ phase: "loading" });
  // The whole catalogue (~175 KB) is only fetched to search or to show older entries.
  const [all, setAll] = useState<Load | null>(null);
  const [query, setQuery] = useState("");
  const [shown, setShown] = useState(PAGE);
  const [older, setOlder] = useState(false);
  const me = useAccount();
  const [watches, setWatches] = useState<Watch[] | null>(null);

  useEffect(() => {
    void fetchKev("recent").then((res) => setRecent(res.ok ? { phase: "ready", doc: res } : { phase: "error", error: res }));
  }, []);

  const signedIn = me?.signedIn === true;
  const refreshWatches = async (): Promise<string | null> => {
    const res = await listWatches();
    if (!res.ok) return res.message;
    setWatches(res.watches);
    return null;
  };
  useEffect(() => {
    if (signedIn) void refreshWatches();
  }, [signedIn]);

  // The server may drop single-product watches covered by a new vendor watch, so reload the list after a change.
  const onAdd = async (vendor: string, product: string | null) => {
    const res = await addWatch(vendor, product);
    return res.ok ? refreshWatches() : res.message;
  };
  const onRemove = async (id: string) => {
    const res = await removeWatch(id);
    return res.ok ? refreshWatches() : res.message;
  };

  const loadAll = () => {
    if (all) return;
    setAll({ phase: "loading" });
    void fetchKev("all").then((res) => setAll(res.ok ? { phase: "ready", doc: res } : { phase: "error", error: res }));
  };

  const searching = query.trim().length > 0;
  const source = (searching || older) && all ? all : recent;
  const doc = source.phase === "ready" ? source.doc : null;
  const matches = doc ? doc.entries.filter((e) => matchesKev(e, query)) : [];
  const watchControl = (e: KevEntry): WatchControl | undefined =>
    signedIn && watches ? { watched: watches.some((w) => watchMatches(w, e)), onWatch: () => void onAdd(e.vendor, e.product) } : undefined;

  return (
    <section aria-labelledby="intel-heading" className="space-y-4">
      <div>
        <h1 id="intel-heading" className="text-2xl font-semibold tracking-tight">
          Exploited vulnerabilities
        </h1>
        <p className="mt-1 text-muted">
          Flaws attackers are using right now, from CISA's Known Exploited Vulnerabilities catalog. If you run one of these
          products, patch it first.
        </p>
        <WhatsThis>{KEV_EXPLAINER}</WhatsThis>
      </div>

      <Watchlist me={me} watches={watches} onAdd={onAdd} onRemove={onRemove} />

      <div>
        <label htmlFor={searchId} className="block text-sm font-medium">
          Search by vendor, product or CVE
        </label>
        <input
          id={searchId}
          type="search"
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          data-guard-reload
          placeholder="e.g. Fortinet, Exchange, CVE-2024-3400"
          value={query}
          onFocus={loadAll}
          onChange={(e) => {
            setQuery(e.target.value.slice(0, 100));
            setShown(PAGE);
            loadAll();
          }}
          className="mt-1 min-h-11 w-full rounded-md border border-border bg-surface px-3 text-sm text-fg placeholder:text-muted focus:border-accent focus:outline-none"
        />
        <p className="mt-1 text-xs text-muted">Searches the whole catalogue, in your browser.</p>
      </div>

      <div aria-live="polite" className="space-y-3">
        {source.phase === "loading" && <p className="text-sm text-muted">Loading…</p>}
        {source.phase === "error" && (
          <p className="flex items-start gap-2 text-sm">
            <Badge tone="warn">Unavailable</Badge>
            <span>{source.error.message}</span>
          </p>
        )}
        {doc && (
          <p className="text-sm text-muted">
            {searching
              ? `${matches.length} match${matches.length === 1 ? "" : "es"} in all ${doc.entries.length} known exploited vulnerabilities.`
              : older
                ? `All ${doc.entries.length} known exploited vulnerabilities, newest first.`
                : `${doc.entries.length} added in the last ${RECENT_DAYS} days, newest first.`}
          </p>
        )}
      </div>

      {doc && (
        <ul className="space-y-3">
          {matches.slice(0, shown).map((e) => (
            <Entry key={e.cve} e={e} watch={watchControl(e)} />
          ))}
        </ul>
      )}

      {doc && (
        <div className="flex flex-wrap gap-2">
          {matches.length > shown && (
            <button type="button" onClick={() => setShown((n) => n + PAGE)} className="min-h-11 rounded-md border border-border px-4 text-sm text-muted hover:text-fg">
              Show more
            </button>
          )}
          {!searching && !older && (
            <button
              type="button"
              onClick={() => {
                setOlder(true);
                loadAll();
              }}
              className="min-h-11 rounded-md border border-border px-4 text-sm text-muted hover:text-fg"
            >
              Show older entries
            </button>
          )}
        </div>
      )}

      <div className="space-y-1 border-t border-border pt-4 text-sm text-muted">
        <p>
          Data:{" "}
          <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer" className="underline hover:text-fg">
            CISA Known Exploited Vulnerabilities catalog
          </a>{" "}
          (CC0). Exploit likelihood:{" "}
          <a href="https://www.first.org/epss/" target="_blank" rel="noopener noreferrer" className="underline hover:text-fg">
            EPSS by FIRST
          </a>
          . Neither CISA nor FIRST endorses Bluebench.
        </p>
        {doc && (
          <p>
            Catalog version {doc.catalogVersion}
            {doc.epssDate && `, EPSS scores from ${date(doc.epssDate)}`}. Refreshed twice a day.
          </p>
        )}
        <WhatsThis>{EPSS_EXPLAINER}</WhatsThis>
      </div>
    </section>
  );
}
