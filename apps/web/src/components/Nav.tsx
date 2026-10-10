import { TABS, type TabId } from "../tabs";
import { TabIcon } from "./TabIcon";

interface NavProps {
  active: TabId;
  onSelect: (id: TabId) => void;
}

/** Bottom tab bar on mobile, side nav from `md` up. */
export function Nav({ active, onSelect }: NavProps) {
  return (
    <nav
      aria-label="Main"
      className="fixed inset-x-0 bottom-0 z-10 border-t border-border bg-surface pb-[env(safe-area-inset-bottom)] md:inset-y-0 md:right-auto md:w-60 md:border-t-0 md:border-r md:pb-0"
    >
      <p className="hidden px-5 pt-6 pb-4 text-lg font-semibold tracking-tight md:block">
        <span className="text-accent">Blue</span>bench
      </p>
      <ul className="grid grid-cols-5 md:flex md:flex-col md:gap-1 md:px-3">
        {TABS.map((tab) => {
          const isActive = tab.id === active;
          return (
            <li key={tab.id}>
              <button
                type="button"
                onClick={() => onSelect(tab.id)}
                aria-current={isActive ? "page" : undefined}
                className={[
                  "flex min-h-14 w-full flex-col items-center justify-center gap-0.5 px-1 text-xs font-medium transition-colors",
                  "md:min-h-11 md:flex-row md:justify-start md:gap-3 md:rounded-md md:px-3 md:text-sm",
                  isActive ? "text-accent md:bg-border/60" : "text-muted hover:text-fg",
                ].join(" ")}
              >
                <TabIcon id={tab.id} />
                <span>{tab.label}</span>
                {tab.comingSoon && (
                  <span className="sr-only md:not-sr-only md:ml-auto md:rounded md:border md:border-border md:px-1.5 md:py-0.5 md:text-[0.6875rem] md:text-muted">
                    Soon
                  </span>
                )}
              </button>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
