import type { MouseEvent, ReactNode } from "react";

/** Go to another page without a reload. App listens for popstate and picks the page for the new path. */
export function navigate(path: string) {
  if (path !== location.pathname) history.pushState(null, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
  window.scrollTo(0, 0);
}

/** A real link (works without JS and with modifier keys) that navigates in-app on a plain click. */
export function AppLink({ href, className, children }: { href: string; className?: string; children: ReactNode }) {
  return (
    <a
      href={href}
      className={className ?? "underline hover:text-fg"}
      onClick={(e: MouseEvent<HTMLAnchorElement>) => {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
        e.preventDefault();
        navigate(href);
      }}
    >
      {children}
    </a>
  );
}
