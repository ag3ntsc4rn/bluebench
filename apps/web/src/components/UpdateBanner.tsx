import { useSyncExternalStore } from "react";
import { pwaUpdate } from "../pwa-update";

export function UpdateBanner() {
  const ready = useSyncExternalStore(pwaUpdate.subscribe, pwaUpdate.isReady, () => false);
  if (!ready) return null;
  return (
    <div role="status" className="flex items-center justify-between gap-3 border-b border-border bg-surface px-4 py-2 text-sm md:px-8">
      <span>A new version of Bluebench is ready.</span>
      <button
        type="button"
        onClick={pwaUpdate.apply}
        className="min-h-11 shrink-0 rounded-md bg-accent px-4 font-medium text-on-accent"
      >
        Reload
      </button>
    </div>
  );
}
