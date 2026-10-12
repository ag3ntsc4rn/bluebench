import type { ApiError } from "@bluebench/shared";
import { useId, useRef, useState, type FormEvent } from "react";
import { requestSignIn } from "../lib/account";
import { runTurnstile } from "../lib/turnstile";
import { Badge } from "./ui";

type State = { phase: "idle" } | { phase: "sending" } | { phase: "sent"; email: string } | { phase: "error"; error: ApiError };

/** Email a magic link. No passwords; the account exists once the link is used. */
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
    return (
      <div aria-live="polite" className="space-y-2 rounded-lg border border-border bg-surface p-4">
        <p className="font-medium">Check your inbox</p>
        <p className="text-sm text-muted">
          We sent a sign-in link to <span className="font-mono break-all text-fg">{state.email}</span>. It works once, for 15
          minutes. Nothing there? Check spam, or{" "}
          <button type="button" onClick={() => setState({ phase: "idle" })} className="min-h-11 underline hover:text-fg">
            try again
          </button>
          .
        </p>
      </div>
    );
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
