import { MAX_WATCHES, type Me, type Watch } from "@bluebench/shared";
import { useId, useState, type FormEvent } from "react";
import { AppLink } from "./AppLink";
import { Badge, Panel } from "./ui";

const ALL = "";

interface WatchlistProps {
  me: Me | null;
  watches: Watch[] | null;
  /** KEV's vendors and their products; null until the whole catalogue has loaded. */
  vendors: { vendor: string; products: string[] }[] | null;
  /** Ask for the whole catalogue (the picker needs every vendor name). */
  onNeedVendors: () => void;
  onAdd: (vendor: string, product: string | null) => Promise<string | null>;
  onRemove: (id: string) => Promise<string | null>;
}

/** Products the account watches: a new known exploited vulnerability in one of them raises an alert. */
export function Watchlist({ me, watches, vendors, onNeedVendors, onAdd, onRemove }: WatchlistProps) {
  const vendorId = useId();
  const productId = useId();
  const listId = useId();
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

  const match = vendors?.find((v) => v.vendor.toLowerCase() === vendor.trim().toLowerCase()) ?? null;
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
              list={listId}
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              placeholder={vendors ? "e.g. Fortinet" : "Loading vendors…"}
              value={vendor}
              onFocus={onNeedVendors}
              onChange={(e) => {
                setVendor(e.target.value.slice(0, 100));
                setProduct(ALL);
              }}
              className="mt-1 min-h-11 w-full rounded-md border border-border bg-ground px-3 text-sm text-fg placeholder:text-muted focus:border-accent focus:outline-none"
            />
            <datalist id={listId}>
              {vendors?.map((v) => (
                <option key={v.vendor} value={v.vendor} />
              ))}
            </datalist>
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
      {vendor.trim() && vendors && !match && (
        <p className="text-sm text-muted">Pick a vendor from the list: only names this catalogue uses can match.</p>
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
