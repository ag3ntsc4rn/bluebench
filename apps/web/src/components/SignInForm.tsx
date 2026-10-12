import type { ApiError } from "@bluebench/shared";
import { useId, useRef, useState, type FormEvent } from "react";
import { finishSignInWithCode, requestSignIn } from "../lib/account";
import { runTurnstile } from "../lib/turnstile";
import { Badge } from "./ui";

type State = { phase: "idle" } | { phase: "sending" } | { phase: "sent"; email: string } | { phase: "error"; error: ApiError };

/**
 * After the email is sent: tap the link, or type the 6-digit code. The code is for the home-screen app,
 * because iOS opens email links in Safari, which doesn't share the app's cookies.
 */
function CodeEntry({ email, onRetry }: { email: string; onRetry: () => void }) {
  const id = useId();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const digits = code.replace(/\D/g, "");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (digits.length !== 6) return;
    setBusy(true);
    setError(null);
    const res = await finishSignInWithCode(email, digits);
    // On success the shared account state flips and the page re-renders signed in.
    if (!res.ok) {
      setBusy(false);
      setError(res.message);
    }
  };

  return (
    <form onSubmit={(e) => void submit(e)} aria-live="polite" className="space-y-3 rounded-lg border border-border bg-surface p-4">
      <p className="font-medium">Check your inbox</p>
      <p className="text-sm text-muted">
        We sent a sign-in link and code to <span className="font-mono break-all text-fg">{email}</span>. Tap the link, or enter
        the code here (best if you're using Bluebench from your home screen). Both work once, for 15 minutes.
      </p>
      <label htmlFor={id} className="block text-sm font-medium">
        6-digit code
      </label>
      <input
        id={id}
        type="text"
        inputMode="numeric"
        autoComplete="one-time-code"
        enterKeyHint="go"
        maxLength={7}
        placeholder="123456"
        value={code}
        onChange={(e) => setCode(e.target.value.slice(0, 7))}
        className="min-h-11 w-40 rounded-md border border-border bg-ground px-3 font-mono text-lg tracking-widest text-fg placeholder:text-muted focus:border-accent focus:outline-none"
      />
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="submit"
          disabled={digits.length !== 6 || busy}
          className="min-h-11 rounded-md bg-accent px-4 text-sm font-medium text-on-accent disabled:opacity-50"
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>
        <button type="button" onClick={onRetry} className="min-h-11 text-sm text-muted underline hover:text-fg">
          Nothing arrived? Send again
        </button>
      </div>
      {error && (
        <p className="flex items-start gap-2 text-sm">
          <Badge tone="warn">Error</Badge>
          <span>{error}</span>
        </p>
      )}
    </form>
  );
}

/** Email a magic link and code. No passwords; the account exists once one of them is used. */
export function SignInForm({ lead }: { lead?: string }) {
  const id = useId();
  const [email, setEmail] = useState("");
  const [state, setState] = useState<State>({ phase: "idle" });
  const challengeRef = useRef<HTMLDivElement>(null);
  const valid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!valid) return;
    setState({ phase: "sending" });
    const address = email.trim();
    const res = await requestSignIn(address, (siteKey) => runTurnstile(challengeRef.current!, siteKey));
    setState(res.ok ? { phase: "sent", email: address } : { phase: "error", error: res });
  };

  if (state.phase === "sent") {
    return <CodeEntry email={state.email} onRetry={() => setState({ phase: "idle" })} />;
  }

  return (
    <form onSubmit={(e) => void submit(e)} className="space-y-3 rounded-lg border border-border bg-surface p-4">
      {lead && <p className="text-sm text-muted">{lead}</p>}
      <label htmlFor={id} className="block text-sm font-medium">
        Email address
      </label>
      <input
        id={id}
        type="email"
        inputMode="email"
        autoComplete="email"
        enterKeyHint="send"
        placeholder="you@example.com"
        value={email}
        onChange={(e) => setEmail(e.target.value.slice(0, 254))}
        className="min-h-11 w-full rounded-md border border-border bg-ground px-3 text-sm text-fg placeholder:text-muted focus:border-accent focus:outline-none"
      />
      <button
        type="submit"
        disabled={!valid || state.phase === "sending"}
        className="min-h-11 rounded-md bg-accent px-4 text-sm font-medium text-on-accent disabled:opacity-50"
      >
        {state.phase === "sending" ? "Sending…" : "Email me a sign-in link"}
      </button>
      <p className="text-xs text-muted">No password. We use your address only for sign-in links and the alerts you ask for.</p>
      {state.phase === "error" && (
        <p aria-live="polite" className="flex items-start gap-2 text-sm">
          <Badge tone="warn">{state.error.error === "daily-limit" || state.error.error === "rate-limited" ? "Limit" : "Error"}</Badge>
          <span>{state.error.message}</span>
        </p>
      )}
      {/* Turnstile renders here, and only becomes visible if Cloudflare needs an interaction. */}
      <div ref={challengeRef} />
    </form>
  );
}
