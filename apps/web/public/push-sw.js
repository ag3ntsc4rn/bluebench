// Web Push handlers, imported into the generated service worker (vite.config.ts: workbox.importScripts).
// The payload is { title, body, url, tag } from the API (apps/api/src/push.ts), decrypted by the browser.

self.addEventListener("push", (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    // Not JSON: show a generic notification rather than nothing.
  }
  event.waitUntil(
    self.registration.showNotification(data.title || "Bluebench", {
      body: data.body || "",
      icon: "/pwa-192.png",
      tag: data.tag,
      data: { url: typeof data.url === "string" ? data.url : "/alerts" },
    }),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = new URL(event.notification.data?.url || "/alerts", self.location.origin);
  if (url.origin !== self.location.origin) return; // only ever open our own pages
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((windows) => {
      for (const w of windows) {
        if ("focus" in w) return w.navigate(url.href).then((c) => (c || w).focus());
      }
      return self.clients.openWindow(url.href);
    }),
  );
});
