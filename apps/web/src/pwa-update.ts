/**
 * Tiny store for "a new version is waiting". Kept separate from the service worker
 * registration (pwa.ts) so components can use it without the virtual:pwa-register module.
 */
type Listener = () => void;

const listeners = new Set<Listener>();
let ready = false;
let apply: () => void = () => {};

export const pwaUpdate = {
  subscribe(listener: Listener): () => void {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },
  /** True when a new version is installed and waiting for a reload. */
  isReady: (): boolean => ready,
  /** Activate the waiting version and reload. */
  apply: (): void => apply(),
  /** Called by pwa.ts once an update is waiting. */
  setReady(applyUpdate: () => void): void {
    apply = applyUpdate;
    ready = true;
    listeners.forEach((l) => l());
  },
};
