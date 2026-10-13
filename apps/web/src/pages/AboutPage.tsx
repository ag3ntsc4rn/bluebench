import type { ReactNode } from "react";
import { AppLink } from "../components/AppLink";
import { DONATE_URL, SOURCE_URL } from "../routes";

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

export function AboutPage() {
  return (
    <article aria-labelledby="about-heading" className="space-y-6 text-[0.9375rem] leading-relaxed">
      <header className="space-y-1">
        <h1 id="about-heading" className="text-2xl font-semibold tracking-tight">
          About Bluebench
        </h1>
        <p className="text-muted">A free security toolkit for defenders, on your desk or your phone.</p>
      </header>

      <Section title="Why it exists">
        <p>
          Checking a suspicious link, decoding a token or reading email headers shouldn't mean pasting incident data into a
          site that logs it, shows you ads or wants a subscription. Bluebench puts those everyday tools in one place, works
          without an account, and does as much as it can inside your browser.
        </p>
      </Section>

      <Section title="What it will never do">
        <ul className="list-disc space-y-1 pl-5">
          <li>Charge for a tier, show ads or load tracking scripts.</li>
          <li>Log what you paste. Decoders and the email header analyzer never send it anywhere.</li>
          <li>Send an indicator to our server until you press Check reputation or Check domain.</li>
          <li>Store your own API keys anywhere but your browser.</li>
        </ul>
        <p>
          The <AppLink href="/privacy">privacy policy</AppLink> lists exactly what leaves your browser, what's stored and for how
          long.
        </p>
      </Section>

      <Section title="Where the answers come from">
        <p>
          Reputation lookups use abuse.ch (URLhaus, ThreatFox and MalwareBazaar) and Google Safe Browsing, within each
          source's terms. With your own keys you can add VirusTotal, AbuseIPDB, GreyNoise and AlienVault OTX. Domain checks
          read public DNS through Cloudflare's 1.1.1.1 and certificates from crt.sh or SSLMate's Cert Spotter. A result of "not listed" means just
          that: it's never a promise that something is safe.
        </p>
      </Section>

      <Section title="Open source">
        <p>
          Every line is public under the MIT licence on <Ext href={SOURCE_URL}>GitHub</Ext>, so you can check these promises
          for yourself, report a bug or send a fix. Found a security problem? Email{" "}
          <a href="mailto:security@bluebench.dev" className="text-accent underline">
            security@bluebench.dev
          </a>
          .
        </p>
      </Section>

      <Section title="Support it">
        <p>
          Bluebench runs on donations and on Cloudflare's free tier.{" "}
          {DONATE_URL ? (
            <>
              If it saves you time, <Ext href={DONATE_URL}>a donation</Ext> keeps it free for everyone.
            </>
          ) : (
            "Donations open soon through GitHub Sponsors."
          )}
        </p>
      </Section>
    </article>
  );
}
