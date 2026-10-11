import type { ToolRoute } from "../routes";
import { LookupPage } from "./LookupPage";

/** A tool's own landing page: the same smart paste box, introduced for that tool, plus a short explainer. */
export function ToolPage({ tool }: { tool: ToolRoute }) {
  return (
    <div className="space-y-8">
      <LookupPage heading={tool.h1} lead={tool.lead} example={tool.example} />
      <div className="space-y-6 text-[0.9375rem] leading-relaxed">
        {tool.sections.map((section) => (
          <section key={section.heading} className="space-y-2">
            <h2 className="text-lg font-semibold">{section.heading}</h2>
            {section.paragraphs.map((p, i) => (
              <p key={i} className="text-muted">
                {p}
              </p>
            ))}
          </section>
        ))}
      </div>
    </div>
  );
}
