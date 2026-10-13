import type { CheckId } from "@bluebench/shared";
import type { AuthMethod } from "./email-headers";

/**
 * "What's this?" text, shown where a term appears in a result. Two or three plain sentences: what it
 * is and why it matters for the result in front of the reader. Not a glossary: only terms our tools show.
 */

/** Domain report card checks. */
export const CHECK_EXPLAINERS: Readonly<Record<CheckId, string>> = {
  mx: "MX records name the servers that accept email for this domain. A domain without them doesn't receive mail, so the email checks below are judged differently.",
  spf: "SPF is a DNS record listing the servers allowed to send email for this domain, so receiving servers can spot forged senders. On its own it doesn't protect the From address people see: that's DMARC's job.",
  dmarc:
    "DMARC tells receiving servers what to do with mail that claims to be from this domain but fails SPF and DKIM: nothing (p=none), send it to spam (quarantine) or reject it. It's what actually stops others sending email as you, and its reports show who's sending in your name.",
  dkim: "DKIM adds a cryptographic signature to outgoing mail, with the public key published in DNS under a name called a selector. Receivers use it to confirm a message really came from this domain and wasn't changed on the way.",
  dnssec:
    "DNSSEC signs a domain's DNS records so resolvers can detect forged answers. Without it, someone able to tamper with DNS responses could send visitors or email to the wrong server.",
  https:
    "Whether the site loads over encrypted HTTPS, and whether plain-HTTP visits are redirected to it. Without HTTPS, anyone on the network path can read or change what visitors see and send.",
  hsts: "HSTS (the Strict-Transport-Security header) tells browsers to only ever use HTTPS for this site, even when someone types http:// or follows an old link. It closes the gap where that first plain request could be intercepted.",
  headers:
    "Security headers are instructions a site sends to browsers: which scripts may run (Content-Security-Policy), whether other sites may embed it, and how much of the address to share with other sites. They limit the damage when the site has a bug such as cross-site scripting.",
  cert: "The TLS certificate proves the site is genuine and makes HTTPS work. Bluebench finds the newest one in public Certificate Transparency logs. When it expires, browsers warn visitors away, so renewal needs to be automatic.",
};

/** Authentication results in the email header analyzer: what each one says about this message. */
export const AUTH_EXPLAINERS: Readonly<Record<AuthMethod, string>> = {
  spf: "Was the server that delivered this message allowed to send mail for the bounce (envelope) domain? A pass doesn't prove the From address you see is genuine: that domain can be different.",
  dkim: "Was the message signed with a domain's key, and is it unchanged since? Check which domain signed it: a pass for a domain unrelated to the sender proves little.",
  dmarc: "Did SPF or DKIM pass for the same domain as the visible From address? This is the result that matters most for spotting a forged sender.",
};

export const HOPS_EXPLAINER =
  "Each mail server that handles a message adds a Received line at the top of the headers, so raw headers read bottom-up (they're shown here oldest first). Only the hops added by your own provider can be trusted: anything before them can be faked by the sender.";

/** Intel tab. */
export const KEV_EXPLAINER =
  "CISA's Known Exploited Vulnerabilities catalog lists flaws with reliable evidence that attackers are using them, out of the tens of thousands published each year. US federal agencies must patch them by a deadline; everyone else should treat the list as a patch-first queue.";
export const EPSS_EXPLAINER =
  "EPSS, from FIRST, estimates the chance that exploitation of a vulnerability will be seen in the next 30 days, updated daily. It's a probability, not a full risk score: a low number doesn't make a listed flaw safe to ignore.";
