import { classifyIp, isLookupKind, KIND_LABELS, parseIp, type Detection } from "@bluebench/shared";
import type { ReactNode } from "react";
import { Badge, CopyButton, Facts, Panel } from "../ui";
import { Reputation } from "./Reputation";

/** IPs, domains, hashes and email addresses: the normalized value, plus an opt-in reputation check. */
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
      {isLookupKind(kind) && (!ipClass || ipClass.global) && <Reputation kind={kind} value={value} />}
      {kind === "email" && (
        <p className="text-sm text-muted">To check reputation, paste just the domain after the @.</p>
      )}
    </Panel>
  );
}
