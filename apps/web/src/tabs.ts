export type TabId = "lookup" | "domains" | "alerts" | "respond" | "intel";

export interface Tab {
  id: TabId;
  label: string;
}

export const TABS: readonly Tab[] = [
  { id: "lookup", label: "Lookup" },
  { id: "domains", label: "Domains" },
  { id: "alerts", label: "Alerts" },
  { id: "respond", label: "Respond" },
  { id: "intel", label: "Intel" },
];
