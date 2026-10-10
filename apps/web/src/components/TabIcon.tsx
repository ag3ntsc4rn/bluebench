import type { TabId } from "../tabs";

const PATHS: Record<TabId, string> = {
  lookup: "M11 4a7 7 0 1 0 4.4 12.4L20 21M11 4a7 7 0 0 1 0 14",
  domains: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Zm-9 9h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3Z",
  alerts: "M6 16V11a6 6 0 1 1 12 0v5l2 2H4l2-2Zm4 4h4",
  respond: "M12 3 4 6v6c0 4.4 3.4 8.2 8 9 4.6-.8 8-4.6 8-9V6l-8-3Zm-3 9 2 2 4-4",
  learn: "M3 7l9-4 9 4-9 4-9-4Zm4 2v5c0 1.7 2.2 3 5 3s5-1.3 5-3V9",
};

export function TabIcon({ id }: { id: TabId }) {
  return (
    <svg
      viewBox="0 0 24 24"
      width="24"
      height="24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d={PATHS[id]} />
    </svg>
  );
}
