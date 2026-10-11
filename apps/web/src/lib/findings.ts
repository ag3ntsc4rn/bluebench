export type Severity = "critical" | "warning" | "info";

/** A plain-English observation shown to the user. Colour is always paired with the severity label. */
export interface Finding {
  severity: Severity;
  title: string;
  detail?: string;
}

const ORDER: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
}

/** "3 s", "4 min 5 s", "2 h 10 min". Negative durations keep their sign. */
export function formatDuration(seconds: number): string {
  const sign = seconds < 0 ? "−" : "";
  let s = Math.round(Math.abs(seconds));
  if (s < 60) return `${sign}${s} s`;
  const h = Math.floor(s / 3600);
  s -= h * 3600;
  const m = Math.floor(s / 60);
  s -= m * 60;
  if (h > 0) return `${sign}${h} h${m ? ` ${m} min` : ""}`;
  return `${sign}${m} min${s ? ` ${s} s` : ""}`;
}

/** UTC timestamp, stable across locales: "2024-10-08 10:00:05 UTC". */
export function formatUtc(ms: number): string {
  return `${new Date(ms).toISOString().slice(0, 19).replace("T", " ")} UTC`;
}
