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

Security headers live in `packages/shared/src/security-headers.ts`. The API applies them with middleware, and the web build emits them as a `_headers` file for static assets.

## Deploy

Every push to `main` runs the tests and then `wrangler deploy` via GitHub Actions (`.github/workflows/ci.yml`). This needs the `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` repository secrets.

IBM Plex fonts are © IBM Corp., licensed under the SIL Open Font License (`apps/web/public/fonts/OFL.txt`).
