# Bluebench

A free, open-source security "Swiss Army knife" for the community. Web app at **bluebench.dev**, built as a PWA that works well on desktop and phone. No paid tiers; funded by donations.

## Principles (non-negotiable)

- **Free forever.** No paywalls, no ads, no tracking scripts.
- **Nothing pasted is logged.** Never write raw indicators, email headers or decoded content to logs, analytics or the database. Cache keys use a SHA-256 hash of the normalized indicator.
- **Do what the browser can do in the browser.** Decoders and email-header parsing run client-side. Only reputation lookups and domain checks hit the API.
- **Honour every data source's terms** (see Data sources). When unsure, don't share or cache it.
- **Never commit secrets.** API keys live in Wrangler secrets / GitHub Actions secrets. `.dev.vars` is gitignored.

## Stack

TypeScript everywhere, pnpm workspaces monorepo.

```
apps/web      React + Vite + Tailwind PWA (vite-plugin-pwa), built to apps/web/dist
apps/api      Hono on Cloudflare Workers; also serves apps/web/dist as Workers static assets
packages/shared   types, indicator detection, validation (zod), used by both
```

- **One Worker (`bluebench`) serves bluebench.dev.** `apps/api/wrangler.jsonc` attaches the custom domain and the web build as assets with `run_worker_first: ["/api/*"]`. Static requests never invoke the Worker, so they don't count toward the 100k/day limit.
- **Security headers have one source:** `packages/shared/src/security-headers.ts`. Hono middleware applies them to API responses, and a Vite plugin emits them as `dist/_headers` for static assets. Any new origin (e.g. Turnstile in M3) must be added to the CSP there.
- **No inline scripts or styles** (CSP has no `'unsafe-inline'`). IBM Plex is self-hosted in `apps/web/public/fonts` (OFL), with no third-party font requests.
- Shared package imports use explicit `.ts` extensions, because Vite 8 loads its config through Node's native TS support.
- `packages/shared` holds pure, runtime-neutral code (detection, refanging, IP classification, domain helpers, base64/text). Its tsconfig adds the `DOM` lib only for web-standard globals (`URL`, `TextDecoder`, `atob`) that browsers, Workers and Node all provide. Browser-only analysers (JWT, URL, email headers) live in `apps/web/src/lib`.
- Tool UI must not use React `style` props: CSP `style-src 'self'` blocks inline style attributes.
- PWA updates: `registerType: "prompt"`, registered by `apps/web/src/pwa.ts` with the plain Service Worker API (no workbox-window). It checks for a new version whenever the page becomes visible; it reloads straight away if the paste box is empty, otherwise it shows a Reload bar.
- pnpm 12: only deps listed under `allowBuilds` in `pnpm-workspace.yaml` may run install scripts.
- The Worker entry module (`apps/api/src/index.ts`) may export only handlers and Durable Object classes; workerd refuses to start otherwise. A test enforces this.
- Lookup API (M3):
  - Lookups are opt-in: the browser sends nothing until the user presses **Check reputation**.
  - `POST /api/lookup` without a valid session cookie gets a 401 `challenge` carrying the Turnstile site key (the `TURNSTILE_SITE_KEY` wrangler var). The page then runs Turnstile, calls `POST /api/session` and retries once. The session is a 24 h `__Host-bb_session` cookie, HMAC-signed.
  - Daily caps are counted in the `UsageCounter` Durable Object, not D1, keyed by HMACs of the session id and IP group. D1/Drizzle arrives with accounts in M5.
  - `ProviderQuota` (one per source) only grants permits; the Worker makes the upstream call. Identical concurrent lookups are coalesced per isolate.
  - KV holds one entry per indicator (all sources). Cached text has the indicator replaced by a placeholder. abuse.ch answers are fresh for 6 h and may be served stale up to 24 h only when the live call can't be made. Safe Browsing matches are cached exactly for `cacheDuration` and never served stale; Safe Browsing non-matches have no cache duration, so they aren't cached.
  - The merged verdict is `listed` / `not-listed` / `incomplete`, never "clean".
  - A missing secret switches a source (or lookups) off with a plain message; it never crashes.
  - `apps/api/src/safe-fetch.ts` is the SSRF guard for M4's user-supplied hosts.
- Domain report card (M4):
  - `POST /api/domain` (`apps/api/src/domain/`) uses the same session, per-minute and daily limits as lookups (one report = one unit of the daily cap). It adds `TARGET_LIMITER`: 5 fresh reports per minute per target domain, keyed by hash, so nobody can use us to hammer a site.
  - Every report runs on a 45-subrequest budget (`Budget` in `dns.ts`; the free plan allows 50). DNS goes through one memoised `Resolver`. A check that can't get budget reports `skipped`, which isn't graded.
  - Grading weights and letter cut-offs live in `packages/shared/src/domain-report.ts`. `pass` = full credit, `warn` = half, `fail` = none; `info` and `skipped` drop out of the total.
  - Site fetches use `safeFetch` with the shared resolver, the budget hook and the `Bluebench/1.0` user agent. The HTTPS probe returns at the 3-redirect cap instead of failing. Plain HTTP passes if its chain reaches `https://`.
  - crt.sh is unreliable (502s, empty answers). We retry once with `match==`. Empty answers are `skipped` and not cached. Results are cached 24 h and the reports themselves 1 h, both under hashed keys with the domain redacted (`src/redact.ts`). Certificates warn under 14 days and fail under 7, because short-lived certificates (Let's Encrypt ~45 days) renew with about two weeks left.
- Routes and SEO: every URL is listed in `apps/web/src/routes.ts`: home, `/privacy`, one landing page per tool (`/ioc-lookup`, `/jwt-decoder`, …) and the 404 page. The build pre-renders each route to its own HTML file in `dist`, with its own title, description, canonical URL and Open Graph tags, and writes `sitemap.xml` (`prerender()` in `apps/web/vite.config.ts` plus `src/prerender.tsx`). `main.tsx` hydrates that HTML. Assets use `not_found_handling: "404-page"`, so unknown paths get a real 404. To add a page, add it to `routes.ts`. `public/og.png` (the link-preview image) is rendered from `apps/web/scripts/og-image.html`; that file explains how to regenerate it.
- `public/robots.txt` and `public/.well-known/security.txt` (contact: security@bluebench.dev; renew its `Expires` date before 2027-10-01).
- The privacy policy lives at `/privacy` (`apps/web/src/pages/PrivacyPage.tsx`), linked from every page's footer. Update it, and its date, **before** shipping any change to what data leaves the browser, is stored, or which third parties see it. It must keep linking Cloudflare's Turnstile Privacy Addendum: that's a condition of the invisible Turnstile widget. Contact: privacy@bluebench.dev (Cloudflare Email Routing).
- API tests mock upstreams with `vi.spyOn(globalThis, "fetch")` (see `apps/api/test/upstream.ts`); the vitest plugin has no `fetchMock`.

- Database: Cloudflare D1 via Drizzle ORM (users, domains, alert history, daily counters)
- Cache: Workers KV for lookup verdicts, TTL 6–24 h (Safe Browsing: obey its cache duration exactly)
- Quota guard: one Durable Object per upstream provider (token bucket + daily budget)
- Scheduling: Cron Triggers (daily domain re-checks)
- Auth: Better Auth, magic link only; email via Resend
- Alerts: Web Push (VAPID) by default, email as fallback
- Bot protection: Cloudflare Turnstile
- Tests: Vitest 4 (+ Miniflare via `@cloudflare/vitest-plugin`, the renamed `vitest-pool-workers`, for the API)
- CI/CD: GitHub Actions → `wrangler deploy` on push to `main`

Stay on Cloudflare's free tier. Free-tier limits that shape the design:
- Workers: 100k requests/day, 10 ms CPU per request
- KV: **1,000 writes/day** — KV is for cached verdicts only, never counters
- D1: 100k rows written/day
- Resend free: 100 emails/day — prefer push; email for magic links and digests

Ask before adding any dependency outside this list.

## Design

Match the approved mockup: dark theme, five-tab bottom nav on mobile (side nav on desktop).

- Colors: ground `#0E1116`, surface `#171B22`, border `#262C36`, text `#E8EAED`, muted `#9AA3AE`, accent blue `#5B8CFF` (dark text `#050B18` on it, 6.2:1)
- Status: OK sky blue `#6CB4FF`, warning amber `#F5A524`, critical coral `#FF8A6B`. Always pair color with a text label. The accent is used for actions and brand (filled buttons, active nav, focus rings), the status colours only for outlined labels, so the two blues don't compete.
- Type: IBM Plex Sans for UI, IBM Plex Mono for indicators, hashes and code
- Touch targets ≥ 44 px; text contrast ≥ 4.5:1; real `<button>`/`<a>`/`<label>` elements
- Tabs: **Lookup** (home), **Domains**, **Alerts**, **Respond** (coming soon), **Learn** (coming soon)

## v1 features

**Lookup (no account needed)**
- Smart paste box: auto-detect IPv4/IPv6, domain, URL, MD5/SHA-1/SHA-256, email address, JWT, base64, raw email headers; route to the right tool
- IOC lookup: merged verdict plus per-source detail
- Email header analyzer (client-side): SPF/DKIM/DMARC results, hop path with delays, plain-English red flags
- Decoders (client-side): JWT, base64, URL
- Bring-your-own API keys, stored only in the browser (IndexedDB), never sent to our DB

**Domains**
- Report card (letter grade): SPF, DMARC, DKIM selector discovery, DNSSEC, MX, HSTS, security headers — each with a one-line fix
- Cert expiry and issuer from Certificate Transparency (crt.sh), cached; daily re-check only
- Lookalike watcher: typo/homoglyph/TLD variants, flag ones that resolve or have MX; daily

**Accounts & alerts**
- Magic-link sign-in, only needed to save domains
- Up to 5 saved domains; continuous monitoring requires a DNS TXT ownership record (`bluebench-verify=<token>`)
- Daily cron: alert on grade drop, cert at 30/14/7 days, new lookalike

**App basics**
- Installable PWA, About page (free, open source, no logging, donate link), donate link in settings and footer

Out of scope for v1: CVE feed, one-time secrets, incident runbook, phishing quiz, team/MSP views.

## Data sources

| Source | Use | Rules |
|---|---|---|
| abuse.ch (URLhaus, ThreatFox, MalwareBazaar) | Shared, server-side | Not-for-profit use only; Auth-Key required; modest volume |
| Google Safe Browsing v4 | Shared, server-side | Never show a verdict past its cache duration; hedge wording ("suspected", "possible"); show "Advisory provided by Google"; state protection isn't perfect |
| DNS-over-HTTPS (Cloudflare 1.1.1.1) | Shared | — |
| crt.sh | Shared | ~5 req/min, no published limit; cache hard |
| VirusTotal, AbuseIPDB, AlienVault OTX, GreyNoise | **BYO key only** | Call with the user's key; never cache in KV or show to other users |

## Abuse protection

- **Anonymous identity:** invisible Turnstile on first lookup → short-lived signed token (HMAC, ~24 h) in an HttpOnly cookie. No token, no lookups.
- **Rate limits:** Workers rate-limiting binding per token and per IP (IPv6 grouped by /64), e.g. 10/min; daily caps (anon ~100, signed-in higher) counted in D1 or a Durable Object, **not KV**.
- **Edge:** no WAF rate-limit rule. As of 2026-10 it's a paid add-on on this account, and we stay on the free tier. Floods are refused by Turnstile and the in-Worker limits, but still count toward the 100k Worker requests/day. If that runs out, only `/api/*` fails until midnight UTC: pages and browser-only tools are static assets and keep working. If abuse appears, turn on Bot Fight Mode (free) for the zone.
- **Upstream budget:** each provider's Durable Object enforces its per-minute rate and daily budget; anonymous traffic may spend at most ~60 % of a budget. Coalesce concurrent lookups of the same indicator.
- **Degrade gracefully:** budget exhausted → serve stale cache if allowed, list skipped sources, suggest sign-in or BYO key. Never a bare error.
- **SSRF:** any server-side fetch to a user-supplied host must resolve DNS first and reject private, loopback, link-local, CGNAT, multicast and cloud-metadata ranges (v4 and v6); allow only ports 80/443; follow at most 3 redirects, re-checking each hop; time out at 5 s.
- **Input caps:** 64 KB max paste; validate everything with zod.
- **Headers:** strict CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy: no-referrer`, `Permissions-Policy`.
- No port scanning; cap checks per target domain.

## Milestones

1. ✅ **Scaffold & deploy** — monorepo, web + api skeletons, shared package, Vitest, GitHub Actions deploy, "hello" page live on bluebench.dev
2. ✅ **Browser-only tools** — paste box with detection, decoders, email header analyzer
3. ✅ **Lookup API** — abuse.ch + Safe Browsing, KV cache, provider Durable Objects, Turnstile, rate limits, SSRF guard
4. ✅ **Domain report card** — DNS checks, headers, crt.sh cert expiry
5. **Accounts & monitoring** — Better Auth magic link, saved domains, TXT verification, daily cron, push + email alerts
6. **Finish v1** — lookalike watcher, BYO keys, About page, donate links

## Working agreement

- One milestone per session. Plan briefly, build, test, then summarize what changed and what the owner must do (secrets, dashboard settings).
- Write tests for detection, parsing, SSRF guard and rate limiting.
- Small, well-described commits.
- Never commit to `main` directly (a push to `main` deploys). Work on a branch per milestone or change, push it and open a PR with `gh pr create`; merge only after CI passes and the owner approves.
- Keep this file current when a decision changes.
