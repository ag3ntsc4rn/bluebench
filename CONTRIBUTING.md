# Contributing to Bluebench

Thanks for helping. Bluebench is a free, open-source security toolkit at [bluebench.dev](https://bluebench.dev), maintained by one person. Bug reports, fixes and well-argued ideas are all welcome.

- **Found a security problem?** Don't open an issue. See [SECURITY.md](SECURITY.md).
- **Bug or idea?** Open an issue with the bug report or feature request form.
- **Code?** For anything bigger than a small fix, open an issue first so we can agree the approach before you spend time on it.

Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

## Run it locally

You need Node 22+ and pnpm (`corepack enable`).

```sh
pnpm install
pnpm dev:api     # wrangler dev on :8787 (serves apps/web/dist and /api)
pnpm dev:web     # vite on :5173, proxies /api to :8787
```

The browser-only tools (decoders, email header analyser, IOC extractor) work with just `pnpm dev:web`. For lookups, copy `apps/api/.dev.vars.example` to `apps/api/.dev.vars`; it uses Cloudflare's always-pass Turnstile test keys. Never commit `.dev.vars` or any API key.

## Test

CI runs these on every pull request, and they must pass:

```sh
pnpm typecheck
pnpm test        # Vitest in every package (the API tests run in Miniflare)
pnpm build
```

Add tests with your change, especially for indicator detection, parsing, the SSRF guard and rate limiting. API tests mock upstream services with `vi.spyOn(globalThis, "fetch")` (see `apps/api/test/upstream.ts`); they never call real services.

## How changes land

- Nobody commits to `main`, including the maintainer. A push to `main` deploys to bluebench.dev, so `main` is protected.
- Work on a branch, open a pull request and fill in the template. CI must pass and the maintainer must approve before it's merged.
- Keep commits small and well described.
- If your change alters a decision recorded in [CLAUDE.md](CLAUDE.md) (the project brief), update it in the same PR.

## The non-negotiables

These come from the project brief and aren't up for debate in a PR:

1. **Nothing pasted is logged.** Never write raw indicators, email headers or decoded content to logs, analytics or the database. Cache keys use a SHA-256 hash of the normalised indicator.
2. **Do what the browser can do in the browser.** Decoders and email header parsing run client-side. Only reputation lookups and domain checks call the API.
3. **Ask before adding a dependency.** Open an issue first. Every dependency adds weight to the page or the Worker, and attack surface.
4. **Honour every data source's terms.** abuse.ch is not-for-profit only; Google Safe Browsing verdicts must never be shown past their cache duration; the BYO-key sources (VirusTotal, AbuseIPDB, OTX, GreyNoise) are never cached or shown to other users. When unsure, don't share or cache it.
5. **Free forever.** No paywalls, ads or tracking scripts.
6. **Explain the value a feature adds.** Lots of good free security tools already exist. A feature proposal should say what Bluebench adds over them, for whom, and what it costs (free-tier quotas, upstream quotas, page weight).

Also:

- Any change to what data leaves the browser, what's stored, or which third parties see it needs the privacy policy (`apps/web/src/pages/PrivacyPage.tsx`) updated, with its date, in the same PR.
- No inline scripts or styles, and no React `style` props: the Content Security Policy blocks them. A new origin goes in `packages/shared/src/security-headers.ts`.
- Stay on Cloudflare's free tier (see the limits in CLAUDE.md).
- Accessibility: touch targets of at least 44 px, text contrast of at least 4.5:1, real `<button>`, `<a>` and `<label>` elements, and colour always paired with a text label.

## Licence

By contributing, you agree that your contribution is licensed under this repository's [licence](LICENSE).
