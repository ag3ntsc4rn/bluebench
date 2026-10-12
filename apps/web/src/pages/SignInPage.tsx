import { useEffect, useState } from "react";
import { SignInForm } from "../components/SignInForm";
import { Badge } from "../components/ui";
import { finishSignIn } from "../lib/account";

type State = { phase: "reading" } | { phase: "no-token" } | { phase: "ready"; token: string } | { phase: "working" } | { phase: "error"; message: string };

/**
 * Where the emailed link lands (/signin#token=…). The token is in the fragment, so it never reaches a
 * server log, and it's only used when the person presses the button: mail scanners that open links
 * can't use it up.
 */
export function SignInPage({ onDone }: { onDone: () => void }) {
  const [state, setState] = useState<State>({ phase: "reading" });

  useEffect(() => {
    const token = new URLSearchParams(location.hash.slice(1)).get("token");
    // Drop the token from the address bar and history straight away.
    if (location.hash) history.replaceState(null, "", location.pathname);
    setState(token && /^[A-Za-z0-9_-]{16,128}$/.test(token) ? { phase: "ready", token } : { phase: "no-token" });
  }, []);

  const finish = async (token: string) => {
    setState({ phase: "working" });
    const res = await finishSignIn(token);
    if (res.ok) onDone();
    else setState({ phase: "error", message: res.message });
  };

  return (
    <section aria-labelledby="signin-heading" className="space-y-4">
      <h1 id="signin-heading" className="text-2xl font-semibold tracking-tight">
        Sign in
      </h1>
      {state.phase === "reading" && <p className="text-muted">One moment…</p>}
      {(state.phase === "ready" || state.phase === "working") && (
        <div className="space-y-3 rounded-lg border border-border bg-surface p-4">
          <p>You're one tap from signing in to Bluebench.</p>
          <button
            type="button"
            disabled={state.phase === "working"}
            onClick={() => state.phase === "ready" && void finish(state.token)}
            className="min-h-11 rounded-md bg-accent px-4 text-sm font-medium text-on-accent disabled:opacity-50"
          >
            {state.phase === "working" ? "Signing in…" : "Finish signing in"}
          </button>
        </div>
      )}
      {(state.phase === "no-token" || state.phase === "error") && (
        <>
          {state.phase === "error" ? (
            <p aria-live="polite" className="flex items-start gap-2 text-sm">
              <Badge tone="warn">Expired</Badge>
              <span>{state.message}</span>
            </p>
          ) : (
            <p className="text-muted">Open the link from your sign-in email, or ask for a new one here.</p>
          )}
          <SignInForm />
        </>
      )}
    </section>
  );
}
