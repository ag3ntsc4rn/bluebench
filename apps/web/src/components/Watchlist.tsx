import { MAX_WATCHES, suggestVendors, type Me, type Watch } from "@bluebench/shared";
import { useId, useState, type FormEvent } from "react";
import { fetchKevVendors } from "../lib/api";
import { AppLink } from "./AppLink";
import { Badge, Panel } from "./ui";

const ALL = "";

interface WatchlistProps {
  me: Me | null;
  watches: Watch[] | null;
  onAdd: (vendor: string, product: string | null) => Promise<string | null>;
  onRemove: (id: string) => Promise<string | null>;
}

/** Products the account watches: a new known exploited vulnerability in one of them raises an alert. */
type Vendors = { vendor: string; products: string[] }[];
type VendorLoad = { phase: "idle" | "loading" } | { phase: "ready"; vendors: Vendors } | { phase: "error"; message: string };

export function Watchlist({ me, watches, onAdd, onRemove }: WatchlistProps) {
  const vendorId = useId();
  const productId = useId();
  // Just the names (~8 KB), loaded when the vendor box is first used.
  const [load, setLoad] = useState<VendorLoad>({ phase: "idle" });
  const [vendor, setVendor] = useState("");
  const [product, setProduct] = useState(ALL);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (me === null) return null;
  if (!me.signedIn) {
    return (
      <Panel title="Watch your products">
        <p className="text-sm">
          Get a push or email alert when something you run is added to this list.{" "}
          <AppLink href="/alerts" className="text-accent underline">
            Sign in (free)
          </AppLink>{" "}
          to choose vendors or products to watch.
        </p>
      </Panel>
    );
  }

  const vendors = load.phase === "ready" ? load.vendors : null;
  const fetchVendors = () => {
    setLoad({ phase: "loading" });
    void fetchKevVendors().then((res) => setLoad(res.ok ? { phase: "ready", vendors: res.vendors } : { phase: "error", message: res.message }));
  };
  const loadVendors = () => {
    if (load.phase === "idle") fetchVendors();
  };
  const match = vendors?.find((v) => v.vendor.toLowerCase() === vendor.trim().toLowerCase()) ?? null;
  const suggestions = vendors && !match ? suggestVendors(vendors, vendor) : [];
  const full = (watches?.length ?? 0) >= MAX_WATCHES;

  const run = async (fn: () => Promise<string | null>) => {
    setBusy(true);
    setError(await fn());
    setBusy(false);
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!match) return;
    void run(async () => {
      const err = await onAdd(match.vendor, product === ALL ? null : product);
      if (!err) {
        setVendor("");
        setProduct(ALL);
      }
      return err;
    });
  };

  return (
    <Panel title="Your watchlist">
      <p className="text-sm text-muted">
        When a vendor or product you watch is added here, you get an alert the way your other alerts reach you (set that up on
        the Alerts tab).
      </p>
      {watches === null ? (
        <p className="text-sm text-muted">Loading…</p>
      ) : watches.length === 0 ? (
        <p className="text-sm text-muted">Nothing watched yet.</p>
      ) : (
        <ul className="flex flex-wrap gap-2">
          {watches.map((w) => (
            <li key={w.id} className="flex items-center gap-1 rounded-full border border-border bg-ground pl-3 text-sm">
              <span>
                {w.vendor}
                {w.product ? ` ${w.product}` : <span className="text-muted"> (all products)</span>}
              </span>
              <button
                type="button"
                disabled={busy}
                onClick={() => void run(() => onRemove(w.id))}
                aria-label={`Stop watching ${w.vendor}${w.product ? ` ${w.product}` : ""}`}
                className="flex size-11 items-center justify-center rounded-full text-muted hover:text-fg disabled:opacity-50"
              >
                ✕
              </button>
            </li>
          ))}
        </ul>
      )}
      {!full ? (
        <form onSubmit={submit} className="flex flex-wrap items-end gap-2">
          <div className="min-w-0 flex-1 basis-40">
            <label htmlFor={vendorId} className="block text-sm">
              Vendor
            </label>
            <input
              id={vendorId}
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              data-guard-reload
              placeholder="e.g. Fortinet"
              value={vendor}
              onFocus={loadVendors}
              onChange={(e) => {
                setVendor(e.target.value.slice(0, 100));
                setProduct(ALL);
                loadVendors();
              }}
              className="mt-1 min-h-11 w-full rounded-md border border-border bg-ground px-3 text-sm text-fg placeholder:text-muted focus:border-accent focus:outline-none"
            />
          </div>
          <div className="min-w-0 flex-1 basis-40">
            <label htmlFor={productId} className="block text-sm">
              Product
            </label>
            <select
              id={productId}
              value={product}
              disabled={!match}
              onChange={(e) => setProduct(e.target.value)}
              className="mt-1 min-h-11 w-full rounded-md border border-border bg-ground px-3 text-sm text-fg focus:border-accent focus:outline-none disabled:opacity-50"
            >
              <option value={ALL}>All products</option>
              {match?.products.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </div>
          <button type="submit" disabled={!match || busy} className="min-h-11 rounded-md bg-accent px-4 text-sm font-medium text-on-accent disabled:opacity-50">
            Watch
          </button>
        </form>
      ) : (
        <p className="text-sm text-muted">That's the maximum of {MAX_WATCHES}. Remove one to add another.</p>
      )}
      {suggestions.length > 0 && (
        <ul aria-label="Matching vendors" className="flex flex-wrap gap-2">
          {suggestions.map((v) => (
            <li key={v.vendor}>
              <button
                type="button"
                onClick={() => {
                  setVendor(v.vendor);
                  setProduct(ALL);
                }}
                className="min-h-11 rounded-full border border-border px-4 text-sm text-muted hover:text-fg"
              >
                {v.vendor}
              </button>
            </li>
          ))}
        </ul>
      )}
      {vendor.trim() && load.phase === "loading" && <p className="text-sm text-muted">Loading vendor names…</p>}
      {vendor.trim() && vendors && !match && suggestions.length === 0 && (
        <p className="text-sm text-muted">No vendor by that name in this catalogue. Only names it uses can match.</p>
      )}
      {load.phase === "error" && (
        <p aria-live="polite" className="flex flex-wrap items-center gap-2 text-sm">
          <Badge tone="warn">Error</Badge>
          <span>{load.message}</span>
          <button type="button" onClick={fetchVendors} className="min-h-11 rounded-md border border-border px-3 text-muted hover:text-fg">
            Try again
          </button>
        </p>
      )}
      {error && (
        <p aria-live="polite" className="flex items-start gap-2 text-sm">
          <Badge tone="warn">Error</Badge>
          <span>{error}</span>
        </p>
      )}
    </Panel>
  );
}
