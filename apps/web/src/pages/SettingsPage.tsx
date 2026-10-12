import { BYO_SOURCE_IDS, BYO_SOURCES, ByoKeySchema, type ByoSourceId, type Me } from "@bluebench/shared";
import { useId, useState, type FormEvent, type ReactNode } from "react";
import { AppLink } from "../components/AppLink";
import { SignInForm } from "../components/SignInForm";
import { Badge, Panel } from "../components/ui";
import { deleteAccount, signOut, useAccount } from "../lib/account";
import { byoKeys, useByoKeys } from "../lib/byo-keys";
import { disablePush } from "../lib/push";
import { DONATE_URL, SOURCE_URL } from "../routes";

type SignedIn = Extract<Me, { signedIn: true }>;

const button = "min-h-11 rounded-md border border-border px-3 text-sm text-muted hover:text-fg disabled:opacity-50";

function Ext({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className="inline-flex min-h-11 items-center underline hover:text-fg">
      {children}
    </a>
  );
}

function Problem({ children }: { children: ReactNode }) {
  return (
    <p aria-live="polite" className="flex items-start gap-2 text-sm">
      <Badge tone="warn">Error</Badge>
      <span>{children}</span>
    </p>
  );
}

function AccountPanel({ me }: { me: SignedIn }) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const remove = async () => {
    setBusy(true);
    await disablePush().catch(() => {});
    const res = await deleteAccount();
    setBusy(false);
    if (!res.ok) setError(res.message);
  };

  return (
    <Panel title="Account">
      <p className="text-sm">
        Signed in as <span className="font-mono break-all">{me.email}</span>
      </p>
      <div className="flex flex-wrap gap-2">
        <button type="button" onClick={() => void signOut()} className={button}>
          Sign out
        </button>
        {!confirming && (
          <button type="button" onClick={() => setConfirming(true)} className={button}>
            Delete account
          </button>
        )}
      </div>
      {confirming && (
        <div className="space-y-2 rounded-md border border-critical/50 p-3">
          <p className="text-sm">This deletes your account, saved domains, alert history and push subscriptions straight away. It can't be undone.</p>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              disabled={busy}
              onClick={() => void remove()}
              className="min-h-11 rounded-md border border-critical px-3 text-sm font-medium text-critical disabled:opacity-50"
            >
              Yes, delete everything
            </button>
            <button type="button" onClick={() => setConfirming(false)} className={button}>
              Cancel
            </button>
          </div>
        </div>
      )}
      {error && <Problem>{error}</Problem>}
    </Panel>
  );
}

function Account() {
  const me = useAccount();
  if (me === null) return <p className="text-sm text-muted">Loading…</p>;
  if (me.signedIn) return <AccountPanel me={me} />;
  return (
    <Panel title="Account">
      <SignInForm lead="Not signed in. An account is free and only needed to save domains and get alerts. Sign in with a link or code sent to your email; no password." />
    </Panel>
  );
}

/** Last 4 characters, so people can tell which key is saved without showing it. */
const masked = (key: string) => `••••${key.slice(-4)}`;

function KeyRow({ source, saved }: { source: ByoSourceId; saved: string | undefined }) {
  const id = useId();
  const info = BYO_SOURCES[source];
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const valid = ByoKeySchema.safeParse(value.trim()).success;

  const store = async (e: FormEvent) => {
    e.preventDefault();
    if (!valid) return setError("That doesn't look like an API key. Copy it again from the provider's site.");
    try {
      await byoKeys.save(source, value.trim());
      setValue("");
      setError(null);
    } catch {
      setError("This browser won't let Bluebench store data (private browsing, or site data blocked), so keys can't be saved.");
    }
  };

  const forget = async () => {
    try {
      await byoKeys.remove(source);
    } catch {
      setError("Couldn't remove the key. Clearing this site's data in your browser settings removes it too.");
    }
  };

  return (
    <li className="space-y-2 border-t border-border pt-3 first:border-t-0 first:pt-0">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{info.label}</span>
        {saved ? <Badge tone="ok">Saved</Badge> : <Badge tone="neutral">Not set</Badge>}
        {saved && <span className="font-mono text-sm text-muted">{masked(saved)}</span>}
      </div>
      <p className="text-sm text-muted">
        {info.relay ? "Sent through our server, which passes it on without storing it." : "Sent straight from your browser."} {info.limits}
      </p>
      {saved ? (
        <button type="button" onClick={() => void forget()} className={button}>
          Remove key
        </button>
      ) : (
        <form onSubmit={(e) => void store(e)} className="flex flex-wrap items-end gap-2">
          <div className="min-w-0 flex-1">
            <label htmlFor={id} className="block text-sm">
              {info.label} API key
            </label>
            <input
              id={id}
              type="password"
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              value={value}
              onChange={(e) => setValue(e.target.value.slice(0, 256))}
              className="mt-1 min-h-11 w-full rounded-md border border-border bg-ground px-3 font-mono text-sm text-fg focus:border-accent focus:outline-none"
            />
          </div>
          <button type="submit" disabled={!value.trim()} className="min-h-11 rounded-md bg-accent px-4 text-sm font-medium text-on-accent disabled:opacity-50">
            Save
          </button>
          <Ext href={info.keyUrl}>Get a free key</Ext>
        </form>
      )}
      {error && <Problem>{error}</Problem>}
    </li>
  );
}

function ApiKeys() {
  const keys = useByoKeys();
  return (
    <Panel title="Your API keys">
      <p className="text-sm">
        Add your own free keys to check indicators against more sources when you press Check reputation. Keys are kept only in
        this browser, never in our database, and you can remove them at any time.
      </p>
      {keys === null ? (
        <p className="text-sm text-muted">Loading…</p>
      ) : (
        <ul className="space-y-3">
          {BYO_SOURCE_IDS.map((s) => (
            <KeyRow key={s} source={s} saved={keys[s]} />
          ))}
        </ul>
      )}
    </Panel>
  );
}

export function Support() {
  return (
    <Panel title="Support Bluebench">
      <p className="text-sm">
        Bluebench is free, has no ads and doesn't track you. It runs on donations. If it saves you time, chipping in keeps it
        going.
      </p>
      {DONATE_URL ? (
        <a
          href={DONATE_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex min-h-11 items-center rounded-md bg-accent px-4 text-sm font-medium text-on-accent"
        >
          Donate
        </a>
      ) : (
        <p className="text-sm text-muted">Donations open soon, through GitHub Sponsors.</p>
      )}
      <p className="text-sm text-muted">
        You can also help by reporting bugs or contributing on <Ext href={SOURCE_URL}>GitHub</Ext>.
      </p>
    </Panel>
  );
}

export function SettingsPage() {
  return (
    <section aria-labelledby="settings-heading" className="space-y-4">
      <div>
        <h1 id="settings-heading" className="text-2xl font-semibold tracking-tight">
          Settings
        </h1>
        <p className="mt-1 text-muted">Your account, your own API keys, and how to support Bluebench.</p>
      </div>
      <Account />
      <ApiKeys />
      <Support />
      <p className="flex flex-wrap gap-x-4 text-sm text-muted">
        <AppLink href="/about" className="inline-flex min-h-11 items-center underline hover:text-fg">
          About Bluebench
        </AppLink>
        <AppLink href="/privacy" className="inline-flex min-h-11 items-center underline hover:text-fg">
          Privacy
        </AppLink>
      </p>
    </section>
  );
}
