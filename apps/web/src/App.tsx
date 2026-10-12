import { useEffect, useState, type MouseEvent, type ReactNode } from "react";
import { Nav } from "./components/Nav";
import { UpdateBanner } from "./components/UpdateBanner";
import { AlertsPage } from "./pages/AlertsPage";
import { DomainsPage } from "./pages/DomainsPage";
import { LookupPage } from "./pages/LookupPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { PlaceholderPage } from "./pages/PlaceholderPage";
import { PrivacyPage } from "./pages/PrivacyPage";
import { SignInPage } from "./pages/SignInPage";
import { Explainer, ToolPage } from "./pages/ToolPage";
import { DOMAINS, metaFor, pageForPath, pathOf, TOOLS, type Page } from "./routes";
import { TABS, type TabId } from "./tabs";

// Tool pages belong to the Lookup tab, the domain checker to Domains; Privacy, sign-in and 404 to none.
const TAB_OF: Partial<Record<Page["kind"], TabId>> = { tool: "lookup", domains: "domains", alerts: "alerts" };

const currentPath = () => (typeof location === "undefined" ? "/" : location.pathname);

export function App({ initialTab = "lookup", initialPath }: { initialTab?: TabId; initialPath?: string }) {
  const [active, setActive] = useState<TabId>(initialTab);
  const [page, setPage] = useState<Page>(() => pageForPath(initialPath ?? currentPath()));
  const tab = TABS.find((t) => t.id === active) ?? TABS[0]!;

  useEffect(() => {
    const onPop = () => setPage(pageForPath(location.pathname));
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  useEffect(() => {
    document.title = metaFor(page).title;
  }, [page]);

  const go = (next: Page) => {
    const path = pathOf(next);
    if (path !== location.pathname) history.pushState(null, "", path);
    setPage(next);
    window.scrollTo(0, 0);
  };

  // Real links (crawlable, and they work before the script loads); with JS, skip the reload.
  const Link = ({ to, children }: { to: Page; children: ReactNode }) => (
    <a
      href={pathOf(to)}
      onClick={(e: MouseEvent<HTMLAnchorElement>) => {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
        e.preventDefault();
        go(to);
      }}
      className="inline-flex min-h-11 items-center underline hover:text-fg"
    >
      {children}
    </a>
  );

  let content: ReactNode;
  if (page.kind === "privacy") content = <PrivacyPage />;
  else if (page.kind === "domains")
    content = (
      <div className="space-y-8">
        <DomainsPage heading={DOMAINS.h1} lead={DOMAINS.lead} />
        <Explainer sections={DOMAINS.sections} />
      </div>
    );
  else if (page.kind === "alerts") content = <AlertsPage />;
  else if (page.kind === "signin") content = <SignInPage onDone={() => go({ kind: "domains" })} />;
  else if (page.kind === "tool") content = <ToolPage key={page.tool.slug} tool={page.tool} />;
  else if (page.kind === "notfound") content = <NotFoundPage />;
  else if (tab.id === "lookup") content = <LookupPage />;
  else if (tab.id === "domains") content = <DomainsPage />;
  else if (tab.id === "alerts") content = <AlertsPage />;
  else content = <PlaceholderPage title={tab.label} comingSoon={tab.comingSoon} />;

  const navActive = page.kind === "home" ? active : (TAB_OF[page.kind] ?? null);

  return (
    <div className="min-h-dvh md:pl-60">
      <UpdateBanner />
      <header className="flex items-center border-b border-border px-4 py-3 md:hidden">
        <p className="text-lg font-semibold tracking-tight">
          <span className="text-accent">Blue</span>bench
        </p>
      </header>
      <main className="mx-auto max-w-3xl px-4 pt-6 pb-28 md:px-8 md:pt-10 md:pb-10">
        {content}
        <footer className="mt-10 space-y-2 border-t border-border pt-4 text-sm text-muted">
          <nav aria-label="Tools">
            <ul className="flex flex-wrap gap-x-4">
              {TOOLS.map((t) => (
                <li key={t.slug}>
                  <Link to={{ kind: "tool", tool: t }}>{t.name}</Link>
                </li>
              ))}
              <li>
                <Link to={{ kind: "domains" }}>{DOMAINS.name}</Link>
              </li>
            </ul>
          </nav>
          <p className="flex flex-wrap items-center gap-x-4">
            <Link to={{ kind: "privacy" }}>Privacy</Link>
            <span>Free and open source. Nothing you paste is logged.</span>
          </p>
        </footer>
      </main>
      <Nav
        active={navActive}
        onSelect={(id) => {
          setActive(id);
          go(id === "domains" ? { kind: "domains" } : id === "alerts" ? { kind: "alerts" } : { kind: "home" });
        }}
      />
    </div>
  );
}

