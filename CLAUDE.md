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
- PWA updates: `registerType: "prompt"`, registered by `apps/web/src/pwa.ts` with the plain Service Worker API (no workbox-window). It checks for a new version whenever the page becomes visible; it reloads straight away unless something's typed (the paste box or any `input[data-guard-reload]`) or a runbook step is ticked, otherwise it shows a Reload bar. The service worker caches no API responses except the public `/api/intel/kev` data (stale-while-revalidate, `vite.config.ts`).
- pnpm 12: only deps listed under `allowBuilds` in `pnpm-workspace.yaml` may run install scripts.
- The Worker entry module (`apps/api/src/index.ts`) may export only handlers and Durable Object classes; workerd refuses to start otherwise. A test enforces this.
- Lookup API (M3):
  - Lookups are opt-in: the browser sends nothing until the user presses **Check reputation**.
  - `POST /api/lookup` without a valid session cookie gets a 401 `challenge` carrying the Turnstile site key (the `TURNSTILE_SITE_KEY` wrangler var). The page then runs Turnstile, calls `POST /api/session` and retries once. The session is a 24 h `__Host-bb_session` cookie, HMAC-signed.
  - Daily caps are counted in the `UsageCounter` Durable Object, not D1, keyed by HMACs of the session id and IP group (anon, 100/day) or of the account id (signed in, 300/day, no IP key).
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
  - Bluebench can't grade its own site. Cloudflare answers a Worker's fetch of a host in its own zone with an error page (it has X-Frame-Options and Referrer-Policy, but no HSTS and no redirect). So for the zone the request arrived on (`selfZone`, e.g. bluebench.dev and its subdomains), the HTTPS, HSTS and headers checks are `skipped`, with a note to check from outside.
  - crt.sh is unreliable (502s, empty answers). We retry once with `match==`; if it still fails or comes back empty, SSLMate's Cert Spotter is the fallback (only with the `CERTSPOTTER_API_KEY` secret: its terms allow keyless use only for personal/evaluation use). Cert Spotter returns unexpired issuances in discovery order, 100 a page, ending with an empty page, so we read to the end (max 3 pages, else `skipped`) rather than judge a partial list. The cert check shows a `Source` fact. Empty answers are `skipped` and not cached. Results are cached 24 h and the reports themselves 1 h, both under hashed keys with the domain redacted (`src/redact.ts`). Certificates warn under 14 days and fail under 7, because short-lived certificates (Let's Encrypt ~45 days) renew with about two weeks left.
- Accounts and monitoring (M5):
  - D1 via Drizzle (`apps/api/src/db/schema.ts`). Migrations are generated by `pnpm --filter @bluebench/api db:generate` into `apps/api/migrations` and applied by CI (`wrangler d1 migrations apply DB --remote`) before `wrangler deploy`, so keep each migration compatible with the previous release. Tests apply them in `test/setup.ts`.
  - Better Auth (magic link only, `better-auth/minimal` + Drizzle adapter, `src/auth.ts`). Its HTTP handler is **never mounted**: our routes in `src/account.ts` call `auth.api.*`, so nothing else is exposed. Telemetry, Better Auth's own rate limiter and IP/user-agent tracking are off (sessions store null for both). Magic-link tokens are stored hashed and expire after 15 min. Session cookie `__Secure-bb.session_token`, SameSite=Strict, 30 days rolling.
  - The emailed link opens `/signin#token=…` (fragment: never in a server log); the page needs a click to `POST /api/signin/verify`, so mail scanners can't burn the link. `POST /api/signin` needs the anonymous Turnstile session and is capped per address (5/day), per session (10/day), and globally: 90 emails/day of Resend's 100, magic links at most 60 (`src/mail.ts`).
  - The same email also carries a 6-digit code (Better Auth `emailOTP`, created by our route with the server-only `createVerificationOTP`, hashed, 15 min, 3 tries; a new email replaces the old code). It's for the home-screen app: iOS opens email links in Safari, which doesn't share the installed app's cookies, so without the code the app (the only place iOS allows push) can't sign in. `POST /api/signin/code` takes address + code.
  - A signed-in account counts as a session for lookups and domain checks (no Turnstile) with tier `user`. The web app keeps a `bb.signedIn` hint in localStorage and only calls `GET /api/me` when it's set, so anonymous visitors cost no Worker requests.
  - Saved domains: max 5 per account. Monitoring starts once `bluebench-verify=<token>` is a TXT record at the domain itself. SERVFAIL or a network error is never treated as "record removed".
  - Cron `* * * * *` (`src/monitor/run.ts`): each run does one job, in priority order: deliver up to 10 pending alerts; re-check the most overdue verified domain (once a day each, report budget 40); or scan the next chunk of a domain's lookalikes. Each job claims its row first so a failure can't hog later runs. A verified domain costs about 4 runs a day (1 report + ~3 lookalike chunks), so the scaling ceiling is roughly 350 monitored domains.
  - Lookalike watcher (M6, `src/monitor/lookalike.ts`): `lookalikes()` in shared generates up to 120 variants of the registrable name (homoglyphs incl. Cyrillic IDNs, other TLDs, omission, transposition, repetition, hyphen, QWERTY neighbours), deterministic so a scan resumes at `domain.lookalike_cursor`. Each variant costs one A query (NXDOMAIN ends it) plus an MX query if it exists; 40 per run. Hits with A or MX (null MX `0 .` doesn't count) are rows in `lookalike`; a variant that stops resolving is deleted, but SERVFAIL/network errors never count as gone. The first full scan is a silent baseline; afterwards new hits raise one defanged `lookalike` alert per run. The owner's other saved domains are skipped. Variants are only resolved, never fetched.
  - Alerts: a **grade drop** fires only if the letter fell *and* a check's graded status got worse (statuses of skipped checks carry forward). **Cert expiry** at 30/14/7 days, applying only thresholds below a third of the cert's lifetime minus a day, so healthy auto-renewal (45/90-day certs) never alerts. **Verification lost** pauses monitoring. History is kept 180 days. Hourly housekeeping deletes old alerts, expired sessions and expired magic links.
  - Delivery: Web Push first (`src/push.ts`: VAPID + RFC 8291 aes128gcm in WebCrypto, tested against the RFC's vector), email fallback via Resend (plain text, if the user allows it). Push endpoints are user-supplied URLs, so only known push-service hosts are accepted (`isPushEndpoint` in shared). Gone (404/410) subscriptions are deleted. 3 attempts, then the alert is marked unsent. Max 5 push subscriptions per account.
  - The service worker's push handlers are in `apps/web/public/push-sw.js`, pulled in with workbox `importScripts`.
- Bring-your-own keys (M6): keys live only in the browser's IndexedDB (`apps/web/src/lib/byo-keys.ts`), managed in Settings. Request builders and parsers for all four providers are in `packages/shared/src/byo.ts`. Only OTX allows cross-site calls (it's the one third-party origin in CSP `connect-src`), so the browser asks it directly. VirusTotal, AbuseIPDB and GreyNoise go through `POST /api/byo` (`apps/api/src/byo.ts`): session + per-minute limits but not the daily cap (it spends the user's quota), fixed hosts only (`RELAY_HOSTS`), no redirects, nothing logged, stored or cached. Check reputation runs the shared lookup first (it sets up the session), then the own-key sources; all feed `mergeVerdict`. VirusTotal needs 2+ malicious engines to count as listed, AbuseIPDB a 25 % confidence score, OTX pulses unless OTX validation marks it known good.
- Bulk extraction (`packages/shared/src/extract.ts`, page `/ioc-extractor`, and an "All indicators (N)" chip on Lookup whenever a paste holds several): refang, then pull out URLs, emails, hashes, IPv4/IPv6 and domains, de-duplicated, with a URL's or email's host not listed again. Domains must end in a real TLD (`tlds.ts`, IANA's list; refresh by re-downloading), minus a few that are mostly file extensions (.md .py .sh .so .rs). Exports run in the browser: a defanged list, CSV (with formula-injection guard) and a STIX 2.1 bundle (one `indicator` per item, no verdict). When bulk reputation is added, exports must leave out Safe Browsing verdicts: Google forbids showing them past their cache duration, and a file keeps them indefinitely.
- Settings (`/settings`, noindex) holds the account controls (Sign out, Delete account), own API keys and the support panel; it's in the mobile top bar and under the desktop side nav. About is `/about`. Donate links use `DONATE_URL` in `routes.ts` (GitHub Sponsors; `.github/FUNDING.yml` adds the repo's Sponsor button). `SOURCE_URL` is the GitHub repo.
- Respond tab: incident runbooks in `apps/web/src/runbooks.ts` (phishing click, compromised email account, ransomware, leaked secret, lost laptop), each with "get help now if…" triggers and five phases (Right now, Contain, Investigate, Recover, Afterwards). Pages are `/respond` and `/respond/<slug>`, pre-rendered as `respond.html` and `respond/<slug>.html`. Checkbox ticks live only in React state (never stored). The PWA won't auto-reload while a step is ticked (`data-runbook-step`). Keep the advice vendor-neutral and conservative; steps link to tools by path, and a test checks those paths exist.
- Intel tab (`/exploited-vulnerabilities`): CISA KEV (CC0; no CISA logo, no implied endorsement) with FIRST EPSS scores (free, attribution requested, permitted for preventative cybersecurity use). `.github/workflows/intel.yml` runs `apps/api/scripts/update-intel.ts` twice a day: it fetches KEV from CISA's GitHub mirror and EPSS's daily CSV (FIRST asks bulk users not to use the API), builds the document with `buildKevDocument` (shared `intel.ts`; refuses fewer than 1,000 entries so bad data never replaces good), and writes three KV keys (`KEV_KV_KEYS`: last 90 days ≈14 KB, the whole catalogue ≈150 KB, and vendor/product names ≈8 KB compressed for the watchlist picker). The workflow deploys nothing. `GET /api/intel/kev[?scope=all|vendors]` streams the KV value as-is (no parsing in the Worker), read with `cacheTtl` so the edge keeps a copy (an uncached read of the 1.1 MB catalogue took 4 s), is cacheable for 15 min and per-IP limited. CISA's federal "required action" boilerplate is rewritten into plain instructions (`plainAction`). Search runs in the browser on the whole catalogue, fetched only when needed.
- Intel watchlist: signed-in accounts watch up to 25 vendors (product null = all products) or vendor+product pairs, by KEV's own names, matched case-insensitively (`watchMatches`). Names aren't validated against the catalogue (that would mean parsing it in the Worker); the picker loads only the vendor list and suggests matches as buttons (no `<datalist>`: iOS Safari handles hundreds of options badly). A vendor watch replaces that vendor's product watches. At minute 30 of each hour the cron (`src/monitor/kev.ts`) reads the recent KEV document. If its `updatedAt` changed, entries not yet in `kev_seen` are matched against `watch` rows, raising one `kev` alert per account per run. The first run is a silent baseline. `kev_seen` is pruned after 120 days (past the 90-day window), so an entry alerts at most once.
- Routes and SEO: every URL is listed in `apps/web/src/routes.ts`: home, `/privacy`, `/about`, `/respond` and its runbooks, one landing page per tool (`/ioc-lookup`, `/jwt-decoder`, …), `/domain-checker`, `/alerts`, `/signin` and `/settings` (both noindex, not in the sitemap) and the 404 page. The build pre-renders each route to its own HTML file in `dist`, with its own title, description, canonical URL and Open Graph tags, and writes `sitemap.xml` (`prerender()` in `apps/web/vite.config.ts` plus `src/prerender.tsx`). `main.tsx` hydrates that HTML. Assets use `not_found_handling: "404-page"`, so unknown paths get a real 404. To add a page, add it to `routes.ts`. `public/og.png` (the link-preview image) is rendered from `apps/web/scripts/og-image.html`; that file explains how to regenerate it.
- `public/robots.txt` and `public/.well-known/security.txt` (contact: security@bluebench.dev; renew its `Expires` date before 2027-10-01).
- The privacy policy lives at `/privacy` (`apps/web/src/pages/PrivacyPage.tsx`), linked from every page's footer. Update it, and its date, **before** shipping any change to what data leaves the browser, is stored, or which third parties see it. It must keep linking Cloudflare's Turnstile Privacy Addendum: that's a condition of the invisible Turnstile widget. Contact: privacy@bluebench.dev (Cloudflare Email Routing).
- API tests mock upstreams with `vi.spyOn(globalThis, "fetch")` (see `apps/api/test/upstream.ts`); the vitest plugin has no `fetchMock`.

- Database: Cloudflare D1 via Drizzle ORM (users, sessions, domains, alert history, push subscriptions; daily counters stay in the `UsageCounter` DO)
- Cache: Workers KV for lookup verdicts, TTL 6–24 h (Safe Browsing: obey its cache duration exactly), plus the Intel data
- Quota guard: one Durable Object per upstream provider (token bucket + daily budget)
- Scheduling: Cron Triggers (daily domain re-checks)
- Auth: Better Auth, magic link only; email via Resend
- Alerts: Web Push (VAPID, implemented with WebCrypto, no library) by default, email as fallback (Resend REST API via fetch, no SDK)
- Bot protection: Cloudflare Turnstile
- Tests: Vitest 4 (+ Miniflare via `@cloudflare/vitest-plugin`, the renamed `vitest-pool-workers`, for the API)
- CI/CD: GitHub Actions → `wrangler deploy` on push to `main`

Stay on Cloudflare's free tier. Free-tier limits that shape the design:
- Workers: 100k requests/day, 10 ms CPU per request
- KV: **1,000 writes/day** — KV is for cached verdicts, domain reports and the Intel data (≤6 writes/day), never counters
- D1: 100k rows written/day
- Resend free: 100 emails/day — prefer push; email for magic links and digests

Ask before adding any dependency outside this list.

## Design

Match the approved mockup: dark theme, five-tab bottom nav on mobile (side nav on desktop). The fifth tab, Learn, was dropped on 2026-10-12: a standalone glossary or phishing quiz adds little that Cloudflare, NIST or Google don't already do better. Explanations live where terms appear instead ("What's this?" in results, `apps/web/src/lib/explainers.ts`).

- Colors: ground `#0E1116`, surface `#171B22`, border `#262C36`, text `#E8EAED`, muted `#9AA3AE`, accent blue `#5B8CFF` (dark text `#050B18` on it, 6.2:1)
- Status: OK sky blue `#6CB4FF`, warning amber `#F5A524`, critical coral `#FF8A6B`. Always pair color with a text label. The accent is used for actions and brand (filled buttons, active nav, focus rings), the status colours only for outlined labels, so the two blues don't compete.
- Type: IBM Plex Sans for UI, IBM Plex Mono for indicators, hashes and code
- Touch targets ≥ 44 px; text contrast ≥ 4.5:1; real `<button>`/`<a>`/`<label>` elements
- Tabs: **Lookup** (home), **Domains**, **Alerts**, **Respond** (incident runbooks), **Intel** (exploited vulnerabilities)

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
| CISA KEV | Shared, Intel tab | CC0. Don't use the CISA logo or DHS seal or imply endorsement |
| FIRST EPSS | Shared, Intel tab | Free, no registration. Attribution requested ("EPSS by FIRST"); use for preventative cybersecurity only; bulk = daily CSV, not the API |
| SSLMate Cert Spotter | Shared, fallback for crt.sh | API key required for production use (keyless is personal/evaluation only). Free "Small" plan: 100 single-hostname queries/hour; we cap at 90 (`ProviderQuota` counts each page). Terms (sslmate.com/policies/tos, California law) say nothing on caching or display; SSLMate may change or end the free plan without notice |
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
5. ✅ **Accounts & monitoring** — Better Auth magic link, saved domains, TXT verification, daily cron, push + email alerts (lookalike alerts arrive with the watcher in M6)
6. ✅ **Finish v1** — lookalike watcher, BYO keys, About and Settings pages, donate links

## Working agreement

- One milestone per session. Plan briefly, build, test, then summarize what changed and what the owner must do (secrets, dashboard settings).
- Write tests for detection, parsing, SSRF guard and rate limiting.
- Small, well-described commits.
- Never commit to `main` directly (a push to `main` deploys). Work on a branch per milestone or change, push it and open a PR with `gh pr create`; merge only after CI passes and the owner approves.
- Keep this file current when a decision changes.
