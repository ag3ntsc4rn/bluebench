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
7. **Edge rate limit: skipped on purpose.** Cloudflare's WAF rate-limiting rules are a paid add-on, and Bluebench stays on the free tier. Turnstile and the Worker's own rate limits refuse floods. If the Worker's daily request quota ever runs out, only lookups stop until midnight UTC; pages and the in-browser tools keep working. If abuse shows up, enable **Bot Fight Mode** (Security → Bots, free).

8. **security@bluebench.dev:** add it in Email Routing like privacy@ (`/.well-known/security.txt` lists it).
9. **Search engines:** add `bluebench.dev` to [Google Search Console](https://search.google.com/search-console) and [Bing Webmaster Tools](https://www.bing.com/webmasters) using the **DNS TXT** verification method (no script on the site), then submit `https://bluebench.dev/sitemap.xml`.

Each source can be switched on independently; a missing key shows that source as "not switched on".

### Accounts and monitoring setup (owner, one-time)

Sign-in, saved domains and alerts stay switched off (the site says so) until these are done:

1. **D1 database:** `wrangler d1 create bluebench`, then paste the printed `database_id` into `apps/api/wrangler.jsonc` (replacing the zeros). CI applies `apps/api/migrations` before each deploy, so the `CLOUDFLARE_API_TOKEN` needs **D1: Edit** as well as its Workers permissions.
2. **Better Auth secret:** `openssl rand -base64 32 | wrangler secret put BETTER_AUTH_SECRET`.
3. **Resend (email):** create a free account, add and verify the `bluebench.dev` domain (Resend shows the DNS records: DKIM plus a `send` subdomain for bounces, which doesn't clash with Email Routing), keep open and click tracking **off**, then create a sending-only API key → `wrangler secret put RESEND_API_KEY`. Mail comes from `EMAIL_FROM` in `wrangler.jsonc`.
4. **Web Push (VAPID keys):** generate a pair once:

   ```sh
   node -e 'const c=require("crypto");const k=c.generateKeyPairSync("ec",{namedCurve:"P-256"}).privateKey.export({format:"jwk"});console.log("public ",Buffer.concat([Buffer.from([4]),Buffer.from(k.x,"base64url"),Buffer.from(k.y,"base64url")]).toString("base64url"));console.log("private",k.d)'
   ```

   Put the public key in `VAPID_PUBLIC_KEY` in `wrangler.jsonc` and the private one in `wrangler secret put VAPID_PRIVATE_KEY`. Without them alerts fall back to email. Don't rotate the pair casually: existing browser subscriptions are tied to it.
5. **Cron:** nothing to do. The `* * * * *` trigger in `wrangler.jsonc` is created on deploy. Locally, run `wrangler dev --test-scheduled` and open `/__scheduled` to fire one run.

The schema lives in `apps/api/src/db/schema.ts`. After changing it, run `pnpm --filter @bluebench/api db:generate` and commit the new file in `apps/api/migrations`.

IBM Plex fonts are © IBM Corp., licensed under the SIL Open Font License (`apps/web/public/fonts/OFL.txt`).
