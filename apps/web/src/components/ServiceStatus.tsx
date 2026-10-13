import type { ApiError, StatusResponse } from "@bluebench/shared";
import { useEffect, useState } from "react";
import { fetchStatus } from "../lib/api";
import { Badge } from "./ui";

const when = (iso: string) => new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

/** The hourly self-tests of each outside service, loaded when shown (pre-rendered HTML says "Checking…"). */
export function ServiceStatus() {
  const [status, setStatus] = useState<StatusResponse | ApiError | null>(null);
  useEffect(() => {
    void fetchStatus().then(setStatus);
  }, []);

  if (!status) return <p className="text-sm text-muted">Checking…</p>;
  if (!status.ok) return <p className="text-sm text-muted">Couldn't load the status just now.</p>;
  if (!status.checkedAt) return <p className="text-sm text-muted">The first check hasn't run yet.</p>;

  const failing = status.checks.filter((c) => c.state === "failing");
  return (
    <div className="space-y-2">
      <p className="flex items-center gap-2 text-sm">
        {failing.length === 0 ? <Badge tone="ok">Working</Badge> : <Badge tone="warn">Problem</Badge>}
        <span>
          {failing.length === 0
            ? "Every outside service Bluebench relies on is answering."
            : `${failing.map((c) => c.label).join(", ")} ${failing.length === 1 ? "isn't" : "aren't"} answering properly; results from ${failing.length === 1 ? "it" : "them"} may be missing.`}
        </span>
      </p>
      <ul className="space-y-1 text-sm">
        {status.checks.map((c) => (
          <li key={c.id} className="flex flex-wrap items-center gap-x-2">
            <Badge tone={c.state === "ok" ? "ok" : c.state === "failing" ? "warn" : "neutral"}>{c.state === "ok" ? "OK" : c.state === "failing" ? "Failing" : "Off"}</Badge>
            <span>{c.label}</span>
            {c.since && <span className="text-muted">since {when(c.since)}</span>}
          </li>
        ))}
      </ul>
      <p className="text-xs text-muted">Checked hourly with queries whose answers are known. Last check {when(status.checkedAt)}.</p>
    </div>
  );
}
