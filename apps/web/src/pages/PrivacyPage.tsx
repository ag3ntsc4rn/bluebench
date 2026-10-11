import type { ReactNode } from "react";

export const PRIVACY_CONTACT = "privacy@bluebench.dev";
export const PRIVACY_UPDATED = "11 October 2026";

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="space-y-2">
      <h2 className="text-lg font-semibold">{title}</h2>
      {children}
    </section>
  );
}

function Ext({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className="text-accent underline">
      {children}
    </a>
  );
}

export function PrivacyPage() {
  return (
    <article aria-labelledby="privacy-heading" className="space-y-6 text-[0.9375rem] leading-relaxed">
      <header className="space-y-1">
        <h1 id="privacy-heading" className="text-2xl font-semibold tracking-tight">
          Privacy
        </h1>
        <p className="text-sm text-muted">Last updated {PRIVACY_UPDATED}</p>
      </header>

      <Section title="The short version">
        <ul className="list-disc space-y-1 pl-5">
          <li>No accounts needed, no ads, no analytics, no tracking scripts.</li>
          <li>Nothing you paste is logged.</li>
          <li>Most tools run entirely in your browser. Something leaves your device only when you press Check reputation.</li>
          <li>We set one cookie, and only after you ask for a reputation lookup.</li>
        </ul>
      </Section>

      <Section title="What stays in your browser">
        <p>
          Indicator detection, the JWT, base64 and URL decoders, and the email header analyzer run on your device. What you
          paste into them is never sent to us or anyone else.
        </p>
      </Section>

      <Section title="Reputation lookups">
        <p>
          When you press <strong>Check reputation</strong>, your browser sends that one indicator (an IP address, domain,
          URL or file hash) to our server. The server asks these sources about it, depending on its type:
        </p>
        <ul className="list-disc space-y-1 pl-5">
          <li>
            abuse.ch: URLhaus, ThreatFox and MalwareBazaar (<Ext href="https://abuse.ch/privacy-policy/">their privacy policy</Ext>)
          </li>
          <li>
            Google Safe Browsing, for URLs and domains only (<Ext href="https://policies.google.com/privacy">Google's privacy policy</Ext>)
          </li>
        </ul>
        <p>Those services receive the indicator from our server, not from your browser, and don't receive your IP address from us.</p>
      </Section>

      <Section title="What we store, and for how long">
        <ul className="list-disc space-y-2 pl-5">
          <li>
            <strong>Cached results</strong>, so repeat lookups don't hit the sources again: kept for up to 24 hours (Safe
            Browsing results only as long as Google allows). They're filed under a one-way hash of the indicator, and the
            indicator itself is removed from the stored result.
          </li>
          <li>
            <strong>Daily lookup counters</strong>, for fair-use limits: a count per session and per network address, stored
            only as keyed one-way hashes and deleted after the day ends (UTC).
          </li>
          <li>
            <strong>Per-minute rate limits</strong>: Cloudflare's rate-limiting service briefly sees your IP address (for IPv6,
            your /64 network) to stop floods.
          </li>
        </ul>
        <p>
          We don't keep request logs. The site is hosted on Cloudflare, which processes IP addresses to deliver and protect
          it under the <Ext href="https://www.cloudflare.com/privacypolicy/">Cloudflare privacy policy</Ext>.
        </p>
      </Section>

      <Section title="Bot check (Cloudflare Turnstile)">
        <p>
          To keep the free lookups free, your first lookup runs an invisible bot check from Cloudflare Turnstile, loaded from
          challenges.cloudflare.com. It isn't loaded until then. Turnstile processes signals such as your IP address, TLS
          fingerprint and browser User-Agent to tell people from bots, and Cloudflare also uses them to improve its bot
          detection. Cloudflare says these signals aren't used to identify, profile or target you. See the{" "}
          <Ext href="https://www.cloudflare.com/turnstile-privacy-policy/">Cloudflare Turnstile Privacy Addendum</Ext>.
        </p>
      </Section>

      <Section title="Cookies and local storage">
        <p>
          After the bot check we set one cookie, <code className="font-mono text-sm">__Host-bb_session</code>: a random,
          signed session ID that expires after 24 hours. It's needed for lookups to work and isn't used for anything else.
          The app also caches its own files on your device so it works offline and can be installed.
        </p>
      </Section>

      <Section title="Questions and requests">
        <p>
          Email <a href={`mailto:${PRIVACY_CONTACT}`} className="text-accent underline">{PRIVACY_CONTACT}</a>. We don't
          have accounts or logs, so we usually hold nothing that identifies you, but we'll answer any question about your
          data, including on Cloudflare Turnstile's processing for this site.
        </p>
      </Section>

      <Section title="Changes">
        <p>
          If this changes, for example when optional sign-in arrives, we'll update this page before the change goes live
          and change the date at the top.
        </p>
      </Section>
    </article>
  );
}
