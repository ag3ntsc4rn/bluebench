import { useState } from "react";
import { Nav } from "./components/Nav";
import { UpdateBanner } from "./components/UpdateBanner";
import { LookupPage } from "./pages/LookupPage";
import { PlaceholderPage } from "./pages/PlaceholderPage";
import { TABS, type TabId } from "./tabs";

export function App({ initialTab = "lookup" }: { initialTab?: TabId }) {
  const [active, setActive] = useState<TabId>(initialTab);
  const tab = TABS.find((t) => t.id === active) ?? TABS[0]!;

  return (
    <div className="min-h-dvh md:pl-60">
      <UpdateBanner />
      <header className="flex items-center border-b border-border px-4 py-3 md:hidden">
        <p className="text-lg font-semibold tracking-tight">
          <span className="text-accent">Blue</span>bench
        </p>
      </header>
      <main className="mx-auto max-w-3xl px-4 pt-6 pb-28 md:px-8 md:pt-10 md:pb-10">
        {tab.id === "lookup" ? <LookupPage /> : <PlaceholderPage title={tab.label} comingSoon={tab.comingSoon} />}
      </main>
      <Nav active={active} onSelect={setActive} />
    </div>
  );
}
