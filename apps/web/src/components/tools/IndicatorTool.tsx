import { classifyIp, KIND_LABELS, parseIp, type Detection } from "@bluebench/shared";
import type { ReactNode } from "react";
import { Badge, CopyButton, Facts, Panel } from "../ui";

export function LookupComingSoon() {
  return (
    <p className="text-sm text-muted">
      Reputation lookups arrive in a later update. Nothing has been sent anywhere: this ran in your browser.
    </p>
  );
}

/** IPs, domains, hashes and email addresses: show the normalized value until reputation lookups exist. */
export function IndicatorTool({ detection }: { detection: Detection }) {
  const { kind, value } = detection;
  const ip = kind === "ipv4" || kind === "ipv6" ? parseIp(value) : null;
  const ipClass = ip && classifyIp(ip);
  const rows: [string, ReactNode, boolean?][] = [["Type", KIND_LABELS[kind], true]];
  if (ipClass) {
    rows.push([
      "Range",
      <span className="flex flex-wrap items-center gap-2">
        <Badge tone={ipClass.global ? "ok" : "warn"}>{ipClass.global ? "Public" : "Not public"}</Badge>
        {ipClass.range}
      </span>,
      true,
    ]);
  }
  if (kind === "email") rows.push(["Domain", value.slice(value.lastIndexOf("@") + 1)]);

  return (
    <Panel title={KIND_LABELS[kind]}>
      <div className="flex items-start justify-between gap-3">
        <p className="min-w-0 font-mono text-base break-all">{value}</p>
        <CopyButton value={value} />
      </div>
      <Facts rows={rows} />
      {ipClass && !ipClass.global && (
        <p className="text-sm text-muted">
          This is a special-purpose address, not a host on the public internet. Reputation services won't know it.
        </p>
      )}
      <LookupComingSoon />
    </Panel>
  );
}
