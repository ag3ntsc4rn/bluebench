import type { ReactNode } from "react";

export const PRIVACY_CONTACT = "privacy@bluebench.dev";
export const PRIVACY_UPDATED = "20 October 2026";

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
          <li>No ads, no analytics, no tracking scripts. Every tool works without an account.</li>
          <li>Nothing you paste is logged.</li>
          <li>
            Most tools run entirely in your browser. Something leaves your device only when you press Check reputation or
            Check domain.
          </li>
          <li>We set a cookie only when you use something that needs it: a lookup or domain check, or signing in.</li>
          <li>
            An account is optional. It holds your email address, the domains you save, the products you watch and your
            alerts, and you can delete it yourself at any time.
          </li>
        </ul>
      </Section>

      <Section title="Accounts and alerts (optional)">
        <p>
          You only need an account to save domains and get alerts about them. Signing in works with a one-time link or code sent
          to your email address; there's no password. If you have an account, we store:
        </p>
        <ul className="list-disc space-y-2 pl-5">
          <li>
            <strong>Your email address</strong>, used only for sign-in links and the alert emails you allow.
          </li>
          <li>
            <strong>The domains you save</strong> (up to 5), a random verification code for each, and the latest daily
            result: the grade, each check's status, the certificate's expiry date, and any lookalike domains found with a
            website or mail (the name, which of the two it has, and when we first saw it).
          </li>
          <li>
            <strong>The vendors and products you watch</strong> on the Intel tab (up to 25). Once an hour our server compares
            them with newly listed exploited vulnerabilities; nothing about your watchlist is sent to anyone else.
          </li>
          <li>
            <strong>Your alerts</strong> (for example "grade dropped from A to C"), kept for 180 days so you can see them on
            the Alerts tab.
          </li>
          <li>
            <strong>Push subscriptions</strong>, if you turn on notifications: the address your browser's push service gave
            this device, and the keys used to encrypt notifications for it.
          </li>
          <li>
            <strong>Your sign-in session</strong>: a random token that lasts 30 days, renewed while you use it. We don't store
            your IP address or browser details with it. Sign-in links and codes work once, expire after 15 minutes, and are
            stored only as a one-way hash. A code stops working after 3 wrong tries.
          </li>
        </ul>
        <p>
          This is kept in Cloudflare's D1 database. <strong>Delete account</strong> in Settings erases all of it straight
          away.
        </p>
        <p>
          <strong>Daily checks.</strong> Once you prove you control a saved domain (with a DNS TXT record), our server runs
          the same domain check described below on it once a day, and compares the result with the day before. It also
          looks up about 120 lookalike names (typos, look-alike characters and other endings, such as examp1e.com or
          example.net) in public DNS through Cloudflare's 1.1.1.1, to see which have a website or mail. It doesn't visit them.
        </p>
        <p>
          <strong>Who helps deliver alerts.</strong> Emails (sign-in links and codes, and alerts when push isn't available) are sent
          through Resend, which receives your address and the email's text (
          <Ext href="https://resend.com/legal/privacy-policy">Resend's privacy policy</Ext>). Push notifications travel
          through your browser's push service (Google for Chrome and Android, Mozilla for Firefox, Apple for Safari,
          Microsoft for older Edge). They're encrypted for your device, so the push service can't read them.
        </p>
      </Section>

      <Section title="What stays in your browser">
        <p>
          Indicator detection and bulk extraction (including CSV and STIX exports), the JWT, base64 and URL decoders, and
          the email header analyzer run on your device. What you
          paste into them is never sent to us or anyone else.
        </p>
        <p>
          The About page loads a short service-status summary from our server, and the Intel tab loads its list of exploited
          vulnerabilities. Neither request carries anything you've typed.
        </p>
        <p>
          On the Intel tab, searching the list happens in your browser.
        </p>
      </Section>

      <Section title="Reputation lookups">
        <p>
          When you press <strong>Check reputation</strong>, your browser sends that indicator (an IP address, domain,
          URL or file hash) to our server. From the bulk view, it sends the listed indicators you chose to check, up to 50 at
          a time. The server asks these sources about each one, depending on its type:
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

      <Section title="Your own API keys (optional)">
        <p>
          In Settings you can add your own keys for VirusTotal, AbuseIPDB, GreyNoise and AlienVault OTX. They're stored only
          in your browser (in its IndexedDB storage), never in our database. Remove them in Settings, or by clearing this
          site's data. When you press <strong>Check reputation</strong> with keys saved:
        </p>
        <ul className="list-disc space-y-2 pl-5">
          <li>
            <strong>AlienVault OTX</strong>: your browser sends the indicator and your key straight to OTX, so it sees your IP
            address. We don't see this request (<Ext href="https://otx.alienvault.com/privacy-policy">OTX's privacy policy</Ext>).
          </li>
          <li>
            <strong>VirusTotal, AbuseIPDB and GreyNoise</strong> don't accept requests from web pages, so your browser sends the
            indicator and your key to our server, which passes them on and returns the answer. Neither is logged, stored or
            cached, and the answer isn't shown to anyone else. The provider sees the request coming from Cloudflare's network,
            not from you (<Ext href="https://www.virustotal.com/gui/privacy-policy">VirusTotal</Ext>,{" "}
            <Ext href="https://www.abuseipdb.com/legal">AbuseIPDB</Ext> and <Ext href="https://www.greynoise.io/privacy">GreyNoise</Ext>{" "}
            privacy policies).
          </li>
        </ul>
        <p>Each provider's own terms apply to how you use your key.</p>
      </Section>

      <Section title="Domain checks">
        <p>
          When you press <strong>Check domain</strong>, your browser sends that domain name to our server. The server then:
        </p>
        <ul className="list-disc space-y-1 pl-5">
          <li>reads the domain's public DNS records through Cloudflare's 1.1.1.1 resolver;</li>
          <li>
            requests the site's home page over HTTPS and over plain HTTP, following at most 3 redirects and identifying
            itself as Bluebench. The site sees requests from Cloudflare's network, not from you;
          </li>
          <li>
            looks up the domain's certificates on crt.sh, run by Sectigo (
            <Ext href="https://www.sectigo.com/privacy-policy">Sectigo's privacy policy</Ext>), or, when crt.sh is down, on
            SSLMate's Cert Spotter (<Ext href="https://sslmate.com/policies/privacy">SSLMate's privacy policy</Ext>).
          </li>
        </ul>
        <p>It never scans ports or crawls beyond the home page.</p>
        <p>
          <strong>Report links.</strong> Every report has its own link (bluebench.dev/domain-checker/ and the domain), so
          you can share it. Opening one runs the same check, as if you'd typed the domain in. Anyone with the link can do
          that, since domain checks only use public information. These pages ask search engines not to list them, and we
          don't keep a list of which domains were checked or shared.
        </p>
        <p>
          <strong>Grade badges.</strong> If you turn on the badge for a domain you've verified, its grade from the daily
          check becomes public at bluebench.dev/api/badge/ and the domain name, for anyone to see or embed. Only the grade
          letter is shown. It's off until you turn it on, and turning it off (or removing the domain) hides it again;
          copies already fetched may be cached for up to an hour.
        </p>
      </Section>

      <Section title="What we store, and for how long">
        <ul className="list-disc space-y-2 pl-5">
          <li>
            <strong>Cached results</strong>, so repeat lookups don't hit the sources again: kept for up to 24 hours (Safe
            Browsing results only as long as Google allows). They're filed under a one-way hash of the indicator, and the
            indicator itself is removed from the stored result.
          </li>
          <li>
            <strong>Domain reports</strong>: kept for an hour, and certificate results for a day, so repeat checks don't hit
            the site or the certificate services again. They're filed under a one-way hash, and the domain name is removed from what's stored.
          </li>
          <li>
            <strong>Daily counters</strong> for lookups, domain checks and sign-in emails, for fair-use limits: a count per
            session, per account, per email address and per network address, stored only as keyed one-way hashes and
            deleted after the day ends (UTC).
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
          After the bot check we set <code className="font-mono text-sm">__Host-bb_session</code>: a random, signed session
          ID that expires after 24 hours. It's needed for lookups and domain checks to work and isn't used for anything
          else.
        </p>
        <p>
          If you sign in, we also set <code className="font-mono text-sm">__Secure-bb.session_token</code>, which keeps you
          signed in for up to 30 days, and the app remembers in your browser's local storage that you're signed in (
          <code className="font-mono text-sm">bb.signedIn</code>), so it only asks our server about your account when you
          have one. For 15 minutes after you ask for a sign-in email, it also keeps the address it went to (
          <code className="font-mono text-sm">bb.pendingSignIn</code>), so the code box is still there if your phone
          reloads the app while you check your email.
        </p>
        <p>
          If you add your own API keys, they're kept in an IndexedDB database named{" "}
          <code className="font-mono text-sm">bluebench</code> in your browser, and nowhere else.
        </p>
        <p>
          The app also caches its own files on your device so it works offline and can be installed, along with the Intel
          tab's public list of exploited vulnerabilities, so it opens instantly.
        </p>
      </Section>

      <Section title="Questions and requests">
        <p>
          Email <a href={`mailto:${PRIVACY_CONTACT}`} className="text-accent underline">{PRIVACY_CONTACT}</a>. Without an
          account we hold nothing that identifies you, as we keep no logs. With one, we hold only what's listed above, and
          we'll send you a copy if you ask. We'll answer any question about your data, including on Cloudflare
          Turnstile's processing for this site.
        </p>
      </Section>

      <Section title="Changes">
        <p>
          If what we collect or who we share it with changes, we'll update this page before the change goes live and change
          the date at the top.
        </p>
      </Section>
    </article>
  );
}
