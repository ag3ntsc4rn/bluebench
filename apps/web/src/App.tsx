import { useEffect, useState, type MouseEvent } from "react";
import { Nav } from "./components/Nav";
import { UpdateBanner } from "./components/UpdateBanner";
import { LookupPage } from "./pages/LookupPage";
import { PlaceholderPage } from "./pages/PlaceholderPage";
import { PrivacyPage } from "./pages/PrivacyPage";
import { TABS, type TabId } from "./tabs";

/** Pages with their own URL. Tabs all live at "/". */
type Page = "app" | "privacy";
const PATHS: Record<Page, string> = { app: "/", privacy: "/privacy" };
const pageFromPath = (path: string): Page => (path.replace(/\/$/, "") === PATHS.privacy ? "privacy" : "app");

export function App({ initialTab = "lookup", initialPath }: { initialTab?: TabId; initialPath?: string }) {
  const [active, setActive] = useState<TabId>(initialTab);
  const [page, setPage] = useState<Page>(() =>
    pageFromPath(initialPath ?? (typeof location === "undefined" ? "/" : location.pathname)),
  );
  const tab = TABS.find((t) => t.id === active) ?? TABS[0]!;

  useEffect(() => {
    const onPop = () => setPage(pageFromPath(location.pathname));
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  const go = (next: Page) => {
    if (next !== page) history.pushState(null, "", PATHS[next]);
    setPage(next);
    window.scrollTo(0, 0);
  };
  // Plain links that work without JS too (the Worker serves the app for /privacy); with JS, skip the reload.
  const link = (next: Page) => (e: MouseEvent<HTMLAnchorElement>) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    e.preventDefault();
    go(next);
  };

  return (
    <div className="min-h-dvh md:pl-60">
      <UpdateBanner />
      <header className="flex items-center border-b border-border px-4 py-3 md:hidden">
        <p className="text-lg font-semibold tracking-tight">
          <span className="text-accent">Blue</span>bench
        </p>
      </header>
      <main className="mx-auto max-w-3xl px-4 pt-6 pb-28 md:px-8 md:pt-10 md:pb-10">
        {page === "privacy" ? (
          <PrivacyPage />
        ) : tab.id === "lookup" ? (
          <LookupPage />
        ) : (
          <PlaceholderPage title={tab.label} comingSoon={tab.comingSoon} />
        )}
        <footer className="mt-10 border-t border-border pt-4 text-sm text-muted">
          {page === "privacy" ? (
            <a href={PATHS.app} onClick={link("app")} className="inline-flex min-h-11 items-center underline hover:text-fg">
              Back to Bluebench
            </a>
          ) : (
            <a href={PATHS.privacy} onClick={link("privacy")} className="inline-flex min-h-11 items-center underline hover:text-fg">
              Privacy
            </a>
          )}
        </footer>
      </main>
      <Nav
        active={page === "app" ? active : null}
        onSelect={(id) => {
          setActive(id);
          go("app");
        }}
      />
    </div>
  );
}
