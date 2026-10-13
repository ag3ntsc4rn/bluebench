import { useEffect, useState, type MouseEvent, type ReactNode } from "react";
import { Nav, SettingsIcon } from "./components/Nav";
import { UpdateBanner } from "./components/UpdateBanner";
import { AboutPage } from "./pages/AboutPage";
import { AlertsPage } from "./pages/AlertsPage";
import { DomainsPage } from "./pages/DomainsPage";
import { LookupPage } from "./pages/LookupPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { IntelPage } from "./pages/IntelPage";
import { PrivacyPage } from "./pages/PrivacyPage";
import { RespondPage } from "./pages/RespondPage";
import { RunbookPage } from "./pages/RunbookPage";
import { SettingsPage } from "./pages/SettingsPage";
import { SignInPage } from "./pages/SignInPage";
import { Explainer, ToolPage } from "./pages/ToolPage";
import { DOMAINS, DONATE_URL, metaFor, pageForPath, pathOf, SOURCE_URL, TOOLS, type Page } from "./routes";
import { TABS, type TabId } from "./tabs";

// Tool pages belong to the Lookup tab, the domain checker to Domains; Privacy, About, Settings, sign-in and 404 to none.
const TAB_OF: Partial<Record<Page["kind"], TabId>> = {
  tool: "lookup",
  domains: "domains",
  alerts: "alerts",
  respond: "respond",
  runbook: "respond",
  intel: "intel",
};
const TAB_PAGE: Partial<Record<TabId, Page>> = { domains: { kind: "domains" }, alerts: { kind: "alerts" }, respond: { kind: "respond" }, intel: { kind: "intel" } };

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
  else if (page.kind === "about") content = <AboutPage />;
  else if (page.kind === "settings") content = <SettingsPage />;
  else if (page.kind === "respond") content = <RespondPage />;
  else if (page.kind === "intel") content = <IntelPage />;
  else if (page.kind === "runbook") content = <RunbookPage key={page.runbook.slug} runbook={page.runbook} />;
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
  else if (tab.id === "respond") content = <RespondPage />;
  else content = <IntelPage />;

  const navActive = page.kind === "home" ? active : (TAB_OF[page.kind] ?? null);

  return (
    <div className="min-h-dvh md:pl-60">
      <UpdateBanner />
      <header className="flex items-center justify-between border-b border-border py-1 pl-4 pr-1 md:hidden">
        <p className="text-lg font-semibold tracking-tight">
          <span className="text-accent">Blue</span>bench
        </p>
        <a
          href={pathOf({ kind: "settings" })}
          aria-label="Settings"
          aria-current={page.kind === "settings" ? "page" : undefined}
          onClick={(e) => {
            if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
            e.preventDefault();
            go({ kind: "settings" });
          }}
          className={["flex size-11 items-center justify-center rounded-md", page.kind === "settings" ? "text-accent" : "text-muted hover:text-fg"].join(" ")}
        >
          <SettingsIcon />
        </a>
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
            <Link to={{ kind: "about" }}>About</Link>
            <Link to={{ kind: "privacy" }}>Privacy</Link>
            <Link to={{ kind: "settings" }}>Settings</Link>
            <a href={SOURCE_URL} target="_blank" rel="noopener noreferrer" className="inline-flex min-h-11 items-center underline hover:text-fg">
              Source code
            </a>
            {DONATE_URL && (
              <a href={DONATE_URL} target="_blank" rel="noopener noreferrer" className="inline-flex min-h-11 items-center underline hover:text-fg">
                Donate
              </a>
            )}
          </p>
          <p>Free and open source. Nothing you paste is logged.</p>
        </footer>
      </main>
      <Nav
        active={navActive}
        settingsActive={page.kind === "settings"}
        onSettings={() => go({ kind: "settings" })}
        onSelect={(id) => {
          setActive(id);
          go(TAB_PAGE[id] ?? { kind: "home" });
        }}
      />
    </div>
  );
}

