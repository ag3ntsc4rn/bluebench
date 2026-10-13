export interface HealthResponse {
  ok: true;
}

/** Health of one thing Bluebench depends on, from the hourly watchdog. */
export interface ServiceCheck {
  id: string;
  label: string;
  /** "off": not configured on this server, so not checked. */
  state: "ok" | "failing" | "off";
  /** ISO time the current failure started, when failing. */
  since: string | null;
}

/** GET /api/status. `checkedAt` is null before the watchdog's first run. */
export interface StatusResponse {
  ok: true;
  checkedAt: string | null;
  checks: ServiceCheck[];
}
