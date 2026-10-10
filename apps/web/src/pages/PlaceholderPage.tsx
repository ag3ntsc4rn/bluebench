interface PlaceholderPageProps {
  title: string;
  comingSoon?: boolean;
}

export function PlaceholderPage({ title, comingSoon }: PlaceholderPageProps) {
  return (
    <section aria-labelledby="page-heading" className="space-y-2">
      <h1 id="page-heading" className="text-2xl font-semibold tracking-tight">
        {title}
      </h1>
      <p className="text-muted">
        {comingSoon ? "Coming soon." : "Not built yet. This tab arrives in a later update."}
      </p>
    </section>
  );
}
