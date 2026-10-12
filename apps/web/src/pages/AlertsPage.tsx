import { MAX_SAVED_DOMAINS, type AlertItem, type AlertKind, type ApiError, type Me } from "@bluebench/shared";
import { useEffect, useState, type ReactNode } from "react";
import { SignInForm } from "../components/SignInForm";
import { Badge, Panel, type Tone } from "../components/ui";
import { deleteAccount, listAlerts, setEmailAlerts, signOut, useAccount } from "../lib/account";
import { currentSubscription, disablePush, enablePush, pushSupport, sendTestPush, type PushSupport } from "../lib/push";

type SignedIn = Extract<Me, { signedIn: true }>;

const KIND: Record<AlertKind, { tone: Tone; label: string }> = {
  "grade-drop": { tone: "warn", label: "Grade drop" },
  "cert-expiry": { tone: "warn", label: "Certificate" },
  "verification-lost": { tone: "neutral", label: "Paused" },
  lookalike: { tone: "warn", label: "Lookalike" },
  test: { tone: "neutral", label: "Test" },
};

const CHANNEL: Record<NonNullable<AlertItem["channel"]>, string> = {
  push: "Sent as a push notification",
  email: "Sent by email",
  none: "Not sent (no device with push, and email alerts off or unavailable)",
};

function Note({ tone = "neutral", label, children }: { tone?: Tone; label: string; children: ReactNode }) {
  return (
    <p aria-live="polite" className="flex items-start gap-2 text-sm">
      <Badge tone={tone}>{label}</Badge>
      <span>{children}</span>
    </p>
  );
}

const PUSH_HELP: Record<Exclude<PushSupport, "supported">, string> = {
  "install-first": "On iPhone and iPad, push works once Bluebench is on your home screen: tap Share, then Add to Home Screen, and open it from there. Sign in inside the app with the 6-digit code from the email (email links open in Safari, not the app).",
  unsupported: "This browser doesn't support push notifications, so alerts come by email.",
  denied: "Notifications are blocked for this site. Allow them in your browser's site settings to get push alerts here.",
};

function Notifications({ me }: { me: SignedIn }) {
  const [support, setSupport] = useState<PushSupport | null>(null);
  const [subscribed, setSubscribed] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<{ tone: Tone; label: string; text: string } | null>(null);

  useEffect(() => {
    const s = pushSupport();
    setSupport(s);
    void currentSubscription().then((sub) => setSubscribed(Boolean(sub)));
  }, []);

  const act = async (fn: () => Promise<void>) => {
    setBusy(true);
    setNote(null);
    await fn();
    setBusy(false);
  };

  const turnOn = () =>
    act(async () => {
      const res = await enablePush(me.pushKey!);
      if (res.ok) {
        setSubscribed(true);
        setNote({ tone: "ok", label: "On", text: "Push alerts are on for this device." });
      } else {
        setSupport(pushSupport());
        setNote({ tone: "warn", label: "Error", text: res.message });
      }
    });

  const turnOff = () =>
    act(async () => {
      await disablePush();
      setSubscribed(false);
    });

  const test = () =>
    act(async () => {
      const res = await sendTestPush();
      if (!res.ok) setNote({ tone: "warn", label: "Error", text: res.message });
      else if (!res.sent) setNote({ tone: "warn", label: "Not sent", text: "No device accepted the test. Try turning push off and on again." });
      else setNote({ tone: "ok", label: "Sent", text: "Test sent to every device with push on. It can take a few seconds to arrive." });
    });

  const toggleEmail = (on: boolean) =>
    act(async () => {
      const res = await setEmailAlerts(on);
      if (!res.ok) setNote({ tone: "warn", label: "Error", text: res.message });
    });

  return (
    <Panel title="How alerts reach you">
      {!me.pushKey ? (
        <p className="text-sm text-muted">Push notifications aren't switched on yet, so alerts come by email.</p>
      ) : support === null || subscribed === null ? (
        <p className="text-sm text-muted">Checking this browser…</p>
      ) : support !== "supported" ? (
        <p className="text-sm text-muted">{PUSH_HELP[support]}</p>
      ) : subscribed ? (
        <div className="space-y-3">
          <p className="flex items-center gap-2 text-sm">
            <Badge tone="ok">On</Badge> Push notifications are on for this device.
          </p>
          <div className="flex flex-wrap gap-2">
            <button type="button" disabled={busy} onClick={() => void test()} className="min-h-11 rounded-md border border-border px-3 text-sm text-muted hover:text-fg disabled:opacity-50">
              Send a test
            </button>
            <button type="button" disabled={busy} onClick={() => void turnOff()} className="min-h-11 rounded-md border border-border px-3 text-sm text-muted hover:text-fg disabled:opacity-50">
              Turn off on this device
            </button>
          </div>
        </div>
      ) : (
        <div className="space-y-2">
          <p className="text-sm text-muted">Get alerts as notifications on this device, even when Bluebench isn't open.</p>
          <button type="button" disabled={busy} onClick={() => void turnOn()} className="min-h-11 rounded-md bg-accent px-4 text-sm font-medium text-on-accent disabled:opacity-50">
            Turn on push notifications
          </button>
        </div>
      )}
      <label className="flex min-h-11 cursor-pointer items-center gap-3 text-sm">
        <input
          type="checkbox"
          checked={me.emailAlerts}
          disabled={busy}
          onChange={(e) => void toggleEmail(e.target.checked)}
          className="size-5 accent-accent"
        />
        <span>Email me an alert when no device gets the push notification</span>
      </label>
      {note && (
        <Note tone={note.tone} label={note.label}>
          {note.text}
        </Note>
      )}
    </Panel>
  );
}

function History() {
  const [alerts, setAlerts] = useState<AlertItem[] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  useEffect(() => {
    void listAlerts().then((res) => (res.ok ? setAlerts(res.alerts) : setError(res)));
  }, []);

  return (
    <Panel title="Recent alerts">
      {error && <Note label="Error">{error.message}</Note>}
      {!alerts && !error && <p className="text-sm text-muted">Loading…</p>}
      {alerts?.length === 0 && (
        <p className="text-sm text-muted">
          No alerts yet. Verified domains are checked once a day; you'll hear from us only when something changes for the worse.
        </p>
      )}
      {alerts && alerts.length > 0 && (
        <ul className="space-y-3">
          {alerts.map((a) => (
            <li key={a.id} className="space-y-1 border-t border-border pt-3 first:border-t-0 first:pt-0">
              <div className="flex flex-wrap items-center gap-2">
                <Badge tone={KIND[a.kind].tone}>{KIND[a.kind].label}</Badge>
                <span className="font-medium break-words">{a.title}</span>
              </div>
              <p className="text-sm break-words whitespace-pre-line">{a.body}</p>
              <p className="text-xs text-muted">
                {new Date(a.createdAt).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })} ·{" "}
                {a.channel ? CHANNEL[a.channel] : "Sending…"}
              </p>
            </li>
          ))}
        </ul>
      )}
    </Panel>
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
        <button type="button" onClick={() => void signOut()} className="min-h-11 rounded-md border border-border px-3 text-sm text-muted hover:text-fg">
          Sign out
        </button>
        {!confirming && (
          <button type="button" onClick={() => setConfirming(true)} className="min-h-11 rounded-md border border-border px-3 text-sm text-muted hover:text-fg">
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
            <button type="button" onClick={() => setConfirming(false)} className="min-h-11 rounded-md border border-border px-3 text-sm text-muted hover:text-fg">
              Cancel
            </button>
          </div>
        </div>
      )}
      {error && <Note label="Error">{error}</Note>}
    </Panel>
  );
}

export function AlertsPage({ heading = "Alerts", lead }: { heading?: string; lead?: string }) {
  const me = useAccount();
  return (
    <section aria-labelledby="alerts-heading" className="space-y-4">
      <div>
        <h1 id="alerts-heading" className="text-2xl font-semibold tracking-tight">
          {heading}
        </h1>
        <p className="mt-1 text-muted">
          {lead ??
            `Save up to ${MAX_SAVED_DOMAINS} domains on the Domains tab and verify them; Bluebench re-checks them daily and tells you when a grade drops, a certificate is close to expiring or a lookalike domain starts resolving.`}
        </p>
      </div>
      {me === null && <p className="text-sm text-muted">Loading…</p>}
      {me && !me.signedIn && <SignInForm lead="Alerts need a free account. Sign in with a link sent to your email; no password." />}
      {me?.signedIn && (
        <>
          <Notifications me={me} />
          <History />
          <AccountPanel me={me} />
        </>
      )}
    </section>
  );
}
