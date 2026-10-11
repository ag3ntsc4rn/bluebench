# Bluebench

A free, open-source security "Swiss Army knife" — [bluebench.dev](https://bluebench.dev). No paywalls, no ads, no tracking, and nothing you paste is logged.

See [CLAUDE.md](CLAUDE.md) for the project brief, principles and roadmap.

## Layout

```
apps/web         React + Vite + Tailwind PWA (built to apps/web/dist)
apps/api         Hono on Cloudflare Workers; serves /api/* and the web build as static assets
packages/shared  Code shared by both (indicator detection, IP/domain helpers, security headers, API types)
```

One Worker serves the whole site on bluebench.dev. Only `/api/*` runs Worker code; everything else is served straight from static assets.

## Develop

Requires Node 22+ and pnpm (`corepack enable` or `npm i -g pnpm`).

```sh
pnpm install
pnpm dev:api     # wrangler dev on :8787 (serves apps/web/dist + /api)
pnpm dev:web     # vite on :5173, proxies /api to :8787
pnpm test        # vitest in every package
pnpm typecheck
pnpm build       # build the web app
```

For lookups in `wrangler dev`, copy `apps/api/.dev.vars.example` to `apps/api/.dev.vars`. It uses Cloudflare's always-pass Turnstile test keys; add real abuse.ch / Safe Browsing keys there to try live lookups.

Security headers live in `packages/shared/src/security-headers.ts`. The API applies them with middleware, and the web build emits them as a `_headers` file for static assets.

## Deploy

Every push to `main` runs the tests and then `wrangler deploy` via GitHub Actions (`.github/workflows/ci.yml`). This needs the `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` repository secrets.

### Lookup API setup (owner, one-time)

Lookups stay switched off (the API says so politely) until these are set:

1. **Turnstile:** the invisible widget for `bluebench.dev` exists and its public site key is in `apps/api/wrangler.jsonc`. Set its secret key with `wrangler secret put TURNSTILE_SECRET_KEY` (or in the dashboard as a Secret). Invisible mode requires the privacy policy to link Cloudflare's Turnstile Privacy Addendum; `/privacy` does.
2. **Session signing:** `openssl rand -base64 32 | wrangler secret put SESSION_SECRET`.
3. **abuse.ch:** get a free Auth-Key at <https://auth.abuse.ch/> → `wrangler secret put ABUSECH_AUTH_KEY` (used for URLhaus, ThreatFox and MalwareBazaar).
4. **Google Safe Browsing:** enable the Safe Browsing API in a Google Cloud project and create an API key restricted to it → `wrangler secret put SAFE_BROWSING_API_KEY`.
5. **KV:** the `VERDICTS` namespace (`bluebench-verdicts`) already exists and its id is pinned in `wrangler.jsonc`.
6. **workers.dev subdomain:** the account needs one before this Worker will deploy (error 10063), even though `workers_dev` is off and nothing is served there. Open **Workers & Pages** in the dashboard once and it's created automatically.
7. **Edge rate limit:** in the dashboard, go to Security → WAF → Rate limiting rules and add a rule for `URI Path starts with /api/`: more than 60 requests per minute from one IP → Block for 1 minute. This stops floods before they reach the Worker's request quota.

Each source can be switched on independently; a missing key shows that source as "not switched on".

IBM Plex fonts are © IBM Corp., licensed under the SIL Open Font License (`apps/web/public/fonts/OFL.txt`).
