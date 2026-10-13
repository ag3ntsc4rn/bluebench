import { AppLink } from "../components/AppLink";
import { IR_FRAMEWORKS, RUNBOOKS } from "../runbooks";

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

      <section aria-labelledby="sources-heading" className="space-y-2">
        <h2 id="sources-heading" className="text-lg font-semibold">
          Incident response frameworks
        </h2>
        <ul className="space-y-1 text-sm">
          {IR_FRAMEWORKS.map((src) => (
            <li key={src.url}>
              <a href={src.url} target="_blank" rel="noopener noreferrer" className="inline-flex min-h-11 items-center text-accent underline">
                {src.label}
              </a>
            </li>
          ))}
        </ul>
        <p className="text-sm text-muted">For building your own plan. Each checklist above lists the specific guides it was checked against.</p>
      </section>

      <p className="text-sm text-muted">
        General guidance, not a substitute for your own incident response plan or professional help. When in doubt, call in an
        expert early: it's cheaper than calling them late.
      </p>
    </section>
  );
}
