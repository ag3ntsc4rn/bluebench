# Security policy

Thank you for helping keep Bluebench and the people who use it safe.

## Reporting a vulnerability

Please report security problems **privately**. Don't open a public issue, pull request or discussion.

- **GitHub:** use [private vulnerability reporting](https://github.com/ag3ntsc4rn/bluebench/security/advisories/new) (the **Report a vulnerability** button on the Security tab). This is the preferred route.
- **Email:** [security@bluebench.dev](mailto:security@bluebench.dev).

Please include what you found, where (a URL, endpoint or file), how to reproduce it, and what an attacker could do with it. A proof of concept helps, but please keep it minimal (see the safe harbour rules below).

## What to expect

Bluebench is maintained by one person in their spare time.

- **Acknowledgement within 7 days** of your report.
- An initial assessment, and a fix or a plan, as soon as practical after that. I'll keep you updated as it progresses.
- Fixes ship through the normal pull request process. Once a fix is live, I'll publish a GitHub security advisory where that makes sense.
- Please give me a reasonable chance to fix the problem before you disclose it publicly. I'm happy to agree a disclosure date with you.

## Scope

In scope:

- **bluebench.dev** and its subdomains: the web app, the `/api/*` endpoints, sign-in, saved domains, monitoring and alerts.
- **This repository**: the code, the GitHub Actions workflows and the build.

Out of scope:

- Volumetric denial of service (flooding, load testing). Bluebench runs on free-tier quotas, so a flood takes it offline for everyone.
- Findings in third-party data sources (abuse.ch, Google Safe Browsing, crt.sh, Cert Spotter, CISA KEV, FIRST EPSS, VirusTotal, AbuseIPDB, AlienVault OTX, GreyNoise). Please report those to their owners. A wrong verdict from a source isn't a vulnerability in Bluebench, but a bug in how Bluebench handles a source's answer is.
- Social engineering, phishing or physical attacks against the maintainer, contributors or users.
- Reports from automated scanners without a demonstrated impact, and missing best-practice headers or settings that have no practical exploit.

## Safe harbour

If you make a good-faith effort to follow this policy, I consider your research authorised, won't pursue or support legal action against you, and will say so if anyone else does. Good faith means you:

- only test against your own account and your own data, and stop as soon as you see anyone else's;
- don't access, change, keep or share data that isn't yours beyond the minimum needed to show the problem;
- don't degrade the service for others: no denial of service, no spamming sign-in emails or alerts, no draining the shared daily quotas;
- don't use Bluebench to scan or attack third-party sites (for example through the domain checker);
- report the problem privately and give a reasonable time to fix it before disclosing it.

If you're unsure whether something is allowed, ask first at security@bluebench.dev.

## Recognition

Bluebench is free and funded by donations, so there's **no bug bounty**. With your permission, I'll credit you by name or handle in the release notes for the fix and in the security advisory.
