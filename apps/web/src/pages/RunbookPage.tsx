import { useState } from "react";
import { AppLink } from "../components/AppLink";
import { Badge, CopyButton } from "../components/ui";
import { runbookText, stepId, type Runbook } from "../runbooks";

/**
 * One runbook as a checklist. Ticks live only in this page (nothing is stored); the app won't reload
 * itself for an update while any box is ticked (see main.tsx). "Copy checklist" includes the ticks.
 */
export function RunbookPage({ runbook }: { runbook: Runbook }) {
  const [done, setDone] = useState<ReadonlySet<string>>(new Set());
  const total = runbook.phases.reduce((n, p) => n + p.steps.length, 0);

  const toggle = (id: string, on: boolean) =>
    setDone((prev) => {
      const next = new Set(prev);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });

  return (
    <article aria-labelledby="runbook-heading" className="space-y-6">
      <header className="space-y-2">
        <p className="text-sm">
          <AppLink href="/respond" className="inline-flex min-h-11 items-center text-muted underline hover:text-fg">
            All checklists
          </AppLink>
        </p>
        <h1 id="runbook-heading" className="text-2xl font-semibold tracking-tight">
          {runbook.h1}
        </h1>
        <p className="text-muted">{runbook.lead}</p>
      </header>

      <section aria-labelledby="escalate-heading" className="space-y-2 rounded-lg border border-warn/60 p-4">
        <h2 id="escalate-heading" className="flex items-center gap-2 font-semibold">
          <Badge tone="warn">Get help</Badge> Bring in an expert now if
        </h2>
        <ul className="list-disc space-y-1 pl-5 text-sm">
          {runbook.escalate.map((e) => (
            <li key={e}>{e}</li>
          ))}
        </ul>
      </section>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <p aria-live="polite" className="text-sm text-muted">
          {done.size} of {total} done
        </p>
        <CopyButton value={runbookText(runbook, done)} label="Copy checklist" />
      </div>

      {runbook.phases.map((phase, p) => (
        <section key={phase.heading} aria-labelledby={`phase-${p}`} className="space-y-3">
          <h2 id={`phase-${p}`} className="text-lg font-semibold">
            {phase.heading}
          </h2>
          <ul className="space-y-2">
            {phase.steps.map((step, s) => {
              const id = stepId(p, s);
              return (
                <li key={id} className="rounded-lg border border-border bg-surface p-3">
                  <label className="flex min-h-11 cursor-pointer items-start gap-3">
                    <input
                      type="checkbox"
                      data-runbook-step
                      checked={done.has(id)}
                      onChange={(e) => toggle(id, e.target.checked)}
                      className="mt-0.5 size-5 shrink-0 accent-accent"
                    />
                    <span className={done.has(id) ? "text-muted line-through" : undefined}>{step.do}</span>
                  </label>
                  {(step.why || step.tool) && (
                    <div className="mt-1 space-y-1 pl-8 text-sm text-muted">
                      {step.why && <p>{step.why}</p>}
                      {step.tool && (
                        <p>
                          <AppLink href={step.tool.path} className="inline-flex min-h-11 items-center text-accent underline">
                            Open the {step.tool.label}
                          </AppLink>
                        </p>
                      )}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        </section>
      ))}

      <p className="text-sm text-muted">
        General guidance, not a substitute for your own incident response plan or professional help. Your ticks stay on this
        page only and aren't saved.
      </p>
    </article>
  );
}
