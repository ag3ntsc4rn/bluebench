export function LookupPage() {
  return (
    <section aria-labelledby="lookup-heading" className="space-y-4">
      <div>
        <h1 id="lookup-heading" className="text-2xl font-semibold tracking-tight">
          Lookup
        </h1>
        <p className="mt-1 text-muted">
          Paste an IP, domain, URL, hash, email address, JWT, base64 or raw email headers.
        </p>
      </div>
      <div className="rounded-lg border border-border bg-surface p-4">
        <label htmlFor="paste" className="block text-sm font-medium">
          Indicator or text
        </label>
        <textarea
          id="paste"
          rows={6}
          maxLength={65536}
          spellCheck={false}
          autoComplete="off"
          placeholder="e.g. 203.0.113.7 or example.com"
          className="mt-2 w-full resize-y rounded-md border border-border bg-ground p-3 font-mono text-sm text-fg placeholder:text-muted focus:border-accent focus:outline-none"
        />
        <p className="mt-2 text-sm text-muted">
          Detection and tools are coming in the next update. Nothing you paste leaves your browser yet.
        </p>
      </div>
    </section>
  );
}
