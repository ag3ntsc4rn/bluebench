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
      const waitingFound = () => {
        if (registration.waiting) onWaiting(registration.waiting);
      };
      // Follow a worker until it's installed. The browser checks for updates by itself when the app
      // opens, so a worker can already be installing before this code runs and "updatefound" has
      // fired: without watching registration.installing too, that version would wait unnoticed.
      const follow = (worker: ServiceWorker | null) => {
        if (!worker) return;
        if (worker.state === "installed") waitingFound();
        else worker.addEventListener("statechange", () => worker.state === "installed" && waitingFound());
      };

      waitingFound();
      follow(registration.installing);
      registration.addEventListener("updatefound", () => follow(registration.installing));

      // Also look for a waiting version after every check, in case one was missed.
      const check = () => {
        if (navigator.onLine) registration.update().then(waitingFound, () => {});
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
