export type TabId = "lookup" | "domains" | "alerts" | "respond" | "learn";

export interface Tab {
  id: TabId;
  label: string;
  comingSoon?: boolean;
}

export const TABS: readonly Tab[] = [
  { id: "lookup", label: "Lookup" },
  { id: "domains", label: "Domains" },
  { id: "alerts", label: "Alerts" },
  { id: "respond", label: "Respond" },
  { id: "learn", label: "Learn", comingSoon: true },
];
