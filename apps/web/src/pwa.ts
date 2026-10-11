import { pwaUpdate } from "./pwa-update";

const HOURLY = 60 * 60 * 1000;

/**
 * Register the service worker and pick up new versions promptly.
 *
 * Phones resume a suspended tab instead of reloading it, so a new deploy could stay invisible
 * until the browser was fully quit. We check for an update whenever the page becomes visible
 * (and hourly). When one is waiting we reload straight away if that loses nothing, otherwise we
 * show a "Reload" bar so a half-finished paste isn't wiped.
 *
 * Uses the plain Service Worker API (no workbox-window). The generated sw.js activates a waiting
 * version when sent { type: "SKIP_WAITING" }.
 */
export function startPwa({ canReloadNow }: { canReloadNow: () => boolean }): void {
  if (!("serviceWorker" in navigator)) return;
  const sw = navigator.serviceWorker;
  // With no controller yet this is a first visit: there is no old version to replace.
  const hadController = Boolean(sw.controller);
  let reloading = false;

  sw.addEventListener("controllerchange", () => {
    if (!hadController || reloading) return;
    reloading = true;
    window.location.reload();
  });

  const onWaiting = (worker: ServiceWorker) => {
    if (!hadController) return; // first visit: nothing old to replace
    const activate = () => worker.postMessage({ type: "SKIP_WAITING" });
    if (canReloadNow()) activate();
    else pwaUpdate.setReady(activate);
  };

  sw.register("/sw.js", { scope: "/" })
    .then((registration) => {
      if (registration.waiting) onWaiting(registration.waiting);
      registration.addEventListener("updatefound", () => {
        const installing = registration.installing;
        installing?.addEventListener("statechange", () => {
          if (installing.state === "installed" && registration.waiting) onWaiting(registration.waiting);
        });
      });

      const check = () => {
        if (navigator.onLine) registration.update().catch(() => {});
      };
      document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "visible") check();
      });
      setInterval(check, HOURLY);
    })
    .catch(() => {
      // Offline support is a nice-to-have; the app works without it.
    });
}
