/**
 * Incident response runbooks for the Respond tab: short, practical checklists for common incidents,
 * written for IT generalists working on a phone mid-incident. Each one is pre-rendered at
 * /respond/<slug> (see routes.ts). Steps can point at a Bluebench tool by path.
 *
 * Keep the advice vendor-neutral and conservative. When it isn't clear-cut, say "consider" and why.
 */

export type RunbookSlug = "phishing-link-clicked" | "compromised-email-account" | "ransomware" | "leaked-secret" | "lost-laptop";

export interface RunbookStep {
  /** The action, as an instruction. */
  do: string;
  /** One line on why, or how. */
  why?: string;
  /** A Bluebench page that helps with this step. */
  tool?: { path: string; label: string };
}

export interface RunbookPhase {
  heading: string;
  steps: RunbookStep[];
}

export interface Runbook {
  slug: RunbookSlug;
  path: `/respond/${RunbookSlug}`;
  /** Short name for lists and links. */
  name: string;
  /** One line for the Respond index. */
  summary: string;
  title: string;
  description: string;
  h1: string;
  lead: string;
  /** When to stop and get professional help. */
  escalate: string[];
  phases: RunbookPhase[];
}

const IOC = { path: "/ioc-lookup", label: "IOC lookup" };
const HEADERS = { path: "/email-header-analyzer", label: "Email header analyzer" };
const URLS = { path: "/url-decoder", label: "URL decoder" };
const DOMAINS = { path: "/domain-checker", label: "Domain checker" };

const LEGAL =
  "Personal data may have been exposed: some laws set short deadlines to notify a regulator (72 hours under GDPR) or the people affected. Bring in whoever handles legal or privacy early.";

export const RUNBOOKS: readonly Runbook[] = [
  {
    slug: "phishing-link-clicked",
    path: "/respond/phishing-link-clicked",
    name: "Someone clicked a phishing link",
    summary: "They clicked, maybe typed a password or opened a file. Work out which, then contain it.",
    title: "Clicked a phishing link? What to do, step by step | Bluebench",
    description:
      "A checklist for when someone clicks a phishing link: find out what happened, secure the account or device, check the link safely and stop the rest of the campaign.",
    h1: "Someone clicked a phishing link",
    lead: "Thank them for telling you: fast reporting is what limits the damage. Then find out exactly what happened, because the next steps depend on it.",
    escalate: [
      "They entered an admin or finance account's password, or approved an MFA prompt they didn't start.",
      "They opened a file and the device is acting oddly, or security software raised an alert.",
      "The email asked to change bank details or pay an invoice, and money has already moved.",
    ],
    phases: [
      {
        heading: "Right now",
        steps: [
          {
            do: "Ask what they did after clicking: just looked, typed a password, approved an MFA prompt, or downloaded or opened a file.",
            why: "Each answer leads to different steps below. Ask calmly; people hide mistakes when they expect blame.",
          },
          {
            do: "If they typed a password: change it now, from a different, trusted device, and sign the account out of all sessions.",
            why: "Changing the password alone doesn't end a session the attacker already has.",
          },
          {
            do: "If they opened a file: disconnect that device from the network (unplug it, or turn off Wi-Fi), but leave it powered on.",
            why: "Stops spread and data theft while keeping evidence in memory for an investigator.",
          },
        ],
      },
      {
        heading: "Contain",
        steps: [
          {
            do: "Check the account's MFA methods and remove any that the person didn't add.",
            why: "Attackers often register their own authenticator app to get back in after a password reset.",
          },
          {
            do: "Look for new mail forwarding or inbox rules on the account, and remove any they didn't create.",
            why: "Hidden rules that forward or delete mail are the most common way attackers stay in.",
          },
          {
            do: "Block the sender, the link's domain and any lookalike domains at your email filter and web filter or DNS.",
          },
          {
            do: "Search all mailboxes for the same email (same sender, subject or link) and remove it.",
            why: "Phishing rarely goes to one person. Others may not have reported it.",
          },
        ],
      },
      {
        heading: "Investigate",
        steps: [
          {
            do: "Check the link's reputation without opening it. Paste it defanged if you like.",
            tool: IOC,
          },
          {
            do: "Decode the link to see where it really leads, including redirects hidden in its parameters.",
            tool: URLS,
          },
          {
            do: "Analyse the email's full headers: who really sent it, and whether SPF, DKIM and DMARC passed.",
            tool: HEADERS,
          },
          {
            do: "Review the account's recent sign-ins for unfamiliar locations, devices or times, and check their IP addresses.",
            tool: IOC,
          },
          {
            do: "If a file was opened, run a full scan with your security software, or have the device checked before it reconnects.",
            why: "If you can't be confident it's clean, reinstalling the device is safer than cleaning it.",
          },
        ],
      },
      {
        heading: "Recover",
        steps: [
          {
            do: "If the password was reused anywhere else, change it there too.",
          },
          {
            do: "Check the account's sent mail for phishing sent to colleagues or customers, and warn anyone who received it.",
          },
          {
            do: "Report the phishing page to Google Safe Browsing and to the brand it imitated, so it gets taken down for everyone.",
          },
        ],
      },
      {
        heading: "Afterwards",
        steps: [
          {
            do: "Write down what happened, when, and what you did. A short timeline is enough.",
          },
          {
            do: "If the email imitated your own domain, check that SPF, DKIM and DMARC protect it, and watch for lookalike domains.",
            tool: DOMAINS,
          },
          {
            do: "Share a short, blame-free note with staff about this campaign and how to report the next one.",
          },
        ],
      },
    ],
  },
  {
    slug: "compromised-email-account",
    path: "/respond/compromised-email-account",
    name: "An email account was taken over",
    summary: "Microsoft 365, Google Workspace or similar. Lock the attacker out and find what they changed.",
    title: "Compromised email account: Microsoft 365 and Google checklist | Bluebench",
    description:
      "Step-by-step checklist for a taken-over email account: lock the attacker out, remove forwarding rules and rogue MFA, check for invoice fraud, and find what they did.",
    h1: "An email account was taken over",
    lead: "Signs include sent mail the owner didn't write, odd sign-in alerts, missing emails or contacts asking about strange messages. Lock the attacker out first, then work out what they did.",
    escalate: [
      "It's an admin account, or the attacker changed tenant-wide settings.",
      "Payment or bank details were changed, or an invoice was paid to a new account. Call the bank straight away: recalls work best within hours.",
      "Several accounts show the same signs.",
    ],
    phases: [
      {
        heading: "Right now",
        steps: [
          {
            do: "Reset the password from a trusted device, and sign the account out of all sessions.",
            why: "In Microsoft 365 and Google Workspace, admins can revoke a user's sessions from the admin console.",
          },
          {
            do: "Remove MFA methods and app passwords the owner doesn't recognise, then have them re-register MFA.",
          },
          {
            do: "If you can't do these quickly, block sign-in for the account until you can.",
          },
        ],
      },
      {
        heading: "Contain",
        steps: [
          {
            do: "Remove forwarding addresses and inbox rules the owner didn't create, especially ones that move, delete or mark mail as read.",
            why: "Attackers hide replies from the real owner, often for mail about invoices or payments.",
          },
          {
            do: "Check third-party apps the account granted access to (OAuth consents), and remove any that are unfamiliar.",
            why: "An app consent keeps working after a password reset.",
          },
          {
            do: "Check delegates and shared access on the mailbox, and remove any that were added recently.",
          },
        ],
      },
      {
        heading: "Investigate",
        steps: [
          {
            do: "Review the sign-in logs: when the attacker first got in, from which IP addresses, and how.",
            tool: IOC,
          },
          {
            do: "Read the sent items and deleted items for what the attacker sent, especially to finance contacts or customers.",
          },
          {
            do: "Check whether files were shared, downloaded or deleted from the account's cloud storage.",
          },
          {
            do: "Find the way in: a phishing email (check its headers), a reused password from another breach, or an MFA prompt approved by mistake.",
            tool: HEADERS,
          },
        ],
      },
      {
        heading: "Recover",
        steps: [
          {
            do: "Warn the people the attacker emailed, by phone or a separate channel, so they don't act on the messages.",
          },
          {
            do: "Confirm any recent changes to bank details or invoices with the other party by phone, using a number you already had.",
          },
          {
            do: "Restore deleted mail or files if needed, then let the owner back in with fresh credentials and MFA.",
          },
        ],
      },
      {
        heading: "Afterwards",
        steps: [
          {
            do: "Turn on phishing-resistant MFA (passkeys or security keys) for this account, and for admins and finance first.",
          },
          {
            do: "Set up alerts for new forwarding rules and for sign-ins from unusual locations, if your platform supports them.",
          },
          {
            do: "Write a short timeline: first sign-in, what changed, when you contained it.",
            why: LEGAL,
          },
        ],
      },
    ],
  },
  {
    slug: "ransomware",
    path: "/respond/ransomware",
    name: "Ransomware on a computer",
    summary: "Files encrypted or a ransom note on screen. Isolate first, then get help.",
    title: "Ransomware response checklist: first steps after an attack | Bluebench",
    description:
      "What to do in the first hours of a ransomware attack: isolate machines, preserve evidence, protect backups, report it and plan a clean recovery. A practical checklist.",
    h1: "Ransomware on a computer",
    lead: "Files won't open, their names have changed, or a ransom note is on screen. Act fast to stop it spreading, and don't try to fix it alone: ransomware is usually the last stage of a longer intrusion.",
    escalate: [
      "Always, for ransomware. Call your incident response provider, your cyber insurer (they often require it and provide help) or your IT support partner now.",
      "Report it to the police or your national cyber security centre: for example IC3 (FBI) in the US, or Action Fraud and the NCSC in the UK.",
    ],
    phases: [
      {
        heading: "Right now",
        steps: [
          {
            do: "Disconnect affected machines from the network: unplug the cable and turn off Wi-Fi. Leave them powered on.",
            why: "Powering off destroys evidence in memory. Only power off if you can't disconnect a machine.",
          },
          {
            do: "If several machines are affected, take the network itself offline at the switch or firewall.",
          },
          {
            do: "Photograph the ransom note and note the time, the machine name and who found it.",
          },
          {
            do: "Don't contact the attackers or pay anything yet.",
            why: "Paying doesn't guarantee your data back, may be illegal in some cases, and should be decided with your insurer and advisers.",
          },
        ],
      },
      {
        heading: "Contain",
        steps: [
          {
            do: "Disconnect backups from the network and check they weren't touched.",
            why: "Attackers target backups first. Offline or immutable copies are your way back.",
          },
          {
            do: "Reset passwords for admin accounts and service accounts from a clean device, and turn on MFA where it's missing.",
            why: "The attackers almost certainly had admin access before encrypting.",
          },
          {
            do: "Block remote access (VPN, remote desktop) until you know how they got in.",
          },
        ],
      },
      {
        heading: "Investigate",
        steps: [
          {
            do: "Work out which machines and shares are affected, and which aren't.",
          },
          {
            do: "Check No More Ransom (nomoreransom.org) for a free decryptor for this ransomware family.",
          },
          {
            do: "Look for signs of data theft: large uploads, new cloud storage tools, or a note saying data was stolen.",
            why: LEGAL,
          },
          {
            do: "Check suspicious IP addresses, domains and file hashes from logs or security alerts.",
            tool: IOC,
          },
        ],
      },
      {
        heading: "Recover",
        steps: [
          {
            do: "Rebuild affected machines from clean installs rather than trying to clean them.",
          },
          {
            do: "Restore data from backups taken before the intrusion began, and scan it before it goes back into use.",
          },
          {
            do: "Bring systems back gradually, watching for signs the attacker is still there.",
          },
        ],
      },
      {
        heading: "Afterwards",
        steps: [
          {
            do: "Fix the way in (often an exposed remote desktop, an unpatched VPN or a phished password) before you're fully back online.",
          },
          {
            do: "Keep at least one backup copy offline or immutable, and test restoring from it regularly.",
          },
          {
            do: "Write up the timeline and lessons while they're fresh.",
          },
        ],
      },
    ],
  },
  {
    slug: "leaked-secret",
    path: "/respond/leaked-secret",
    name: "A password or API key leaked",
    summary: "Pushed to a public repo, pasted in chat, or found in a breach. Rotate first, clean up second.",
    title: "Leaked API key or password: what to do right now | Bluebench",
    description:
      "A checklist for leaked secrets: revoke and rotate the key, check whether it was used, clean it out of git history and stop it happening again.",
    h1: "A password or API key leaked",
    lead: "A key pushed to a public repository can be found by automated scanners within minutes. Assume it has been seen: rotating it matters more than hiding it.",
    escalate: [
      "It was a cloud provider's key with broad permissions (for example an admin access key).",
      "Logs show the key or password was used by someone else.",
      "It gave access to customer or personal data.",
    ],
    phases: [
      {
        heading: "Right now",
        steps: [
          {
            do: "Revoke the key, or change the password, at the service it belongs to. Then issue a new one.",
            why: "Deleting the commit or message doesn't help: copies already exist in history, forks, caches and scanners.",
          },
          {
            do: "Update everything that used the old secret, so services keep working with the new one.",
          },
          {
            do: "If a password was reused anywhere, change it there too.",
          },
        ],
      },
      {
        heading: "Contain",
        steps: [
          {
            do: "If it's a cloud key, check for new users, keys, machines or permission changes, and remove anything you didn't create.",
            why: "Stolen cloud keys are often used to create their own access, or to run crypto miners on your bill.",
          },
          {
            do: "Check the service's billing for unexpected usage.",
          },
        ],
      },
      {
        heading: "Investigate",
        steps: [
          {
            do: "Read the service's access logs from the moment of the leak: what the key was used for, and from which IP addresses.",
            tool: IOC,
          },
          {
            do: "Find out how long it was exposed, and where else it might have been copied: forks, CI logs, chat history, tickets.",
          },
          {
            do: "Search the rest of the repository and its history for other secrets.",
          },
        ],
      },
      {
        heading: "Recover",
        steps: [
          {
            do: "After rotating, remove the secret from git history with a tool like git filter-repo, then force-push and ask collaborators to re-clone.",
            why: "Only after rotation: cleaning history takes time and doesn't make an unrotated key safe.",
          },
          {
            do: "If it was on GitHub, contact GitHub Support to purge cached views of the old commits.",
          },
        ],
      },
      {
        heading: "Afterwards",
        steps: [
          {
            do: "Turn on secret scanning and push protection for your repositories, and add a pre-commit check (for example gitleaks).",
          },
          {
            do: "Keep secrets in a secrets manager or environment variables, never in code or config files that get committed.",
          },
          {
            do: "Prefer short-lived, narrowly scoped credentials, so a leak does less harm.",
          },
        ],
      },
    ],
  },
  {
    slug: "lost-laptop",
    path: "/respond/lost-laptop",
    name: "A laptop was lost or stolen",
    summary: "Lock or wipe it, cut off its access, and work out whether data was exposed.",
    title: "Lost or stolen laptop: security checklist for IT | Bluebench",
    description:
      "What to do when a work laptop is lost or stolen: lock or wipe it remotely, sign out its sessions, rotate saved credentials and decide whether data was exposed.",
    h1: "A laptop was lost or stolen",
    lead: "Whether this is an incident or an inconvenience depends mostly on one thing: was the disk encrypted? Find out first, but cut off the laptop's access either way.",
    escalate: [
      "The disk wasn't encrypted, or you can't tell, and it held personal or confidential data.",
      "Accounts used on the laptop show sign-ins after it went missing.",
    ],
    phases: [
      {
        heading: "Right now",
        steps: [
          {
            do: "Lock the laptop remotely, and wipe it if it isn't recovered quickly, using your device management tool or Find My (Apple) or Find my device (Microsoft).",
          },
          {
            do: "Sign the owner's accounts out of all sessions, starting with email, single sign-on and cloud storage.",
            why: "Browsers on the laptop may stay signed in even when it's locked.",
          },
          {
            do: "Check whether the disk was encrypted (BitLocker on Windows, FileVault on Mac).",
          },
        ],
      },
      {
        heading: "Contain",
        steps: [
          {
            do: "Change passwords that were saved in the browser or a password manager on the laptop, if the manager wasn't locked.",
          },
          {
            do: "Revoke anything stored on it that grants access: VPN certificates, SSH keys, API tokens, remembered-device MFA.",
          },
          {
            do: "Remove the laptop from your device management and network access lists once wiped.",
          },
        ],
      },
      {
        heading: "Investigate",
        steps: [
          {
            do: "Check the owner's accounts for sign-ins since the laptop went missing, and look up any unfamiliar IP addresses.",
            tool: IOC,
          },
          {
            do: "List what data was on the laptop: synced folders, downloads, email cached for offline use.",
            why: LEGAL,
          },
        ],
      },
      {
        heading: "Recover",
        steps: [
          {
            do: "Report a theft to the police and get a reference number: insurers usually need it.",
          },
          {
            do: "Set up a replacement with fresh credentials and restore the owner's data from backups or cloud sync.",
          },
        ],
      },
      {
        heading: "Afterwards",
        steps: [
          {
            do: "Make sure every laptop has disk encryption turned on and is enrolled for remote lock and wipe.",
          },
          {
            do: "Write down when it went missing, what you did and when, and whether data was exposed.",
          },
        ],
      },
    ],
  },
];

/** A runbook as plain text with checkboxes, for tickets and incident notes. `done` holds ticked step ids. */
export function runbookText(r: Runbook, done: ReadonlySet<string> = new Set()): string {
  const lines = [r.h1, ""];
  r.phases.forEach((phase, p) => {
    lines.push(`${phase.heading}:`);
    phase.steps.forEach((step, s) => lines.push(`[${done.has(stepId(p, s)) ? "x" : " "}] ${step.do}`));
    lines.push("");
  });
  lines.push(`Checklist from https://bluebench.dev${r.path}`);
  return lines.join("\n");
}

export const stepId = (phase: number, step: number) => `${phase}.${step}`;
