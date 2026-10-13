import { AppLink } from "../components/AppLink";
import { RUNBOOKS } from "../runbooks";

/** The Respond tab: a list of incident runbooks. */
export function RespondPage() {
  return (
    <section aria-labelledby="respond-heading" className="space-y-4">
      <div>
        <h1 id="respond-heading" className="text-2xl font-semibold tracking-tight">
          Respond
        </h1>
        <p className="mt-1 text-muted">
          Short checklists for common incidents, written to use on your phone while it's happening. Pick the one that fits.
        </p>
      </div>
      <ul className="space-y-3">
        {RUNBOOKS.map((r) => (
          <li key={r.slug}>
            <AppLink href={r.path} className="block min-h-11 rounded-lg border border-border bg-surface p-4 hover:border-accent">
              <span className="block font-medium text-fg">{r.name}</span>
              <span className="mt-1 block text-sm text-muted">{r.summary}</span>
            </AppLink>
          </li>
        ))}
      </ul>
      <p className="text-sm text-muted">
        General guidance, not a substitute for your own incident response plan or professional help. When in doubt, call in an
        expert early: it's cheaper than calling them late.
      </p>
    </section>
  );
}
