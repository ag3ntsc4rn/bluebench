## What and why

<!-- What does this change, and what does it add for people using Bluebench? Link the issue: "Fixes #123". -->

## Checklist

- [ ] **Tests:** added or updated (detection, parsing, SSRF guard and rate limiting always need them), and `pnpm typecheck`, `pnpm test` and `pnpm build` pass.
- [ ] **Privacy policy:** this doesn't change what data leaves the browser, what's stored, or which third parties see it. Or it does, and `PrivacyPage.tsx` and its date are updated.
- [ ] **CLAUDE.md:** updated if a decision, limit or workflow it records has changed.
- [ ] **Nothing pasted is logged:** no raw indicators, headers or decoded content in logs, analytics or the database.
- [ ] **No new dependencies,** or the maintainer agreed to them in an issue first.
- [ ] **Data-source terms** are honoured (caching, display, attribution).
- [ ] **Secrets:** none committed.
