import type { ToolRoute, ToolSection } from "../routes";
import { LookupPage } from "./LookupPage";

/** The short explainer under a tool: what it does, how, and why it's private. Real text for search engines too. */
export function Explainer({ sections }: { sections: readonly ToolSection[] }) {
  return (
    <div className="space-y-6 text-[0.9375rem] leading-relaxed">
      {sections.map((section) => (
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
  );
}

/** A tool's own landing page: the same smart paste box, introduced for that tool, plus a short explainer. */
export function ToolPage({ tool }: { tool: ToolRoute }) {
  return (
    <div className="space-y-8">
      <LookupPage heading={tool.h1} lead={tool.lead} example={tool.example} placeholder={tool.placeholder} />
      <Explainer sections={tool.sections} />
    </div>
  );
}
