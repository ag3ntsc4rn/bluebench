import type { ApiError } from "@bluebench/shared";
import { requestJson } from "./api";

/**
 * Web Push in the browser. The service worker (public/push-sw.js, imported into the generated sw.js)
 * shows the notification; the server only ever sees this browser's push endpoint and keys.
 */
export type PushSupport = "supported" | "unsupported" | "install-first" | "denied";

export function pushSupport(): PushSupport {
  if (typeof window === "undefined" || !("serviceWorker" in navigator) || !("PushManager" in window) || !("Notification" in window)) {
    // iPhone and iPad only offer push to apps added to the home screen.
    if (typeof navigator !== "undefined" && /iPhone|iPad|iPod/.test(navigator.userAgent)) return "install-first";
    return "unsupported";
  }
  return Notification.permission === "denied" ? "denied" : "supported";
}

function keyBytes(base64url: string): Uint8Array<ArrayBuffer> {
  const b64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function registration(): Promise<ServiceWorkerRegistration | null> {
  // `ready` never settles without a service worker (e.g. the dev server), so don't wait forever.
  const timeout = new Promise<null>((resolve) => setTimeout(() => resolve(null), 5000));
  return Promise.race([navigator.serviceWorker.ready, timeout]);
}

/** This browser's current subscription, if any. */
export async function currentSubscription(): Promise<PushSubscription | null> {
  if (pushSupport() !== "supported") return null;
  const reg = await navigator.serviceWorker.getRegistration();
  return (await reg?.pushManager.getSubscription()) ?? null;
}

const fail = (message: string): ApiError => ({ ok: false, error: "unavailable", message });

/** Ask permission, subscribe with our VAPID key and register the subscription with the server. */
export async function enablePush(vapidKey: string): Promise<{ ok: true } | ApiError> {
  if ((await Notification.requestPermission()) !== "granted") {
    return fail("Notifications are blocked for this site. Allow them in your browser's site settings, then try again.");
  }
  const reg = await registration();
  if (!reg) return fail("Push needs the installed app's service worker. Reload the page and try again.");
  let sub: PushSubscription;
  try {
    sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes(vapidKey) });
  } catch {
    return fail("This browser couldn't set up push notifications.");
  }
  const res = await requestJson<{ ok: true }>("POST", "/api/push", sub.toJSON());
  if (!res.ok) await sub.unsubscribe().catch(() => {});
  return res;
}

export async function disablePush(): Promise<void> {
  const sub = await currentSubscription();
  if (!sub) return;
  await requestJson("DELETE", "/api/push", { endpoint: sub.endpoint });
  await sub.unsubscribe().catch(() => {});
}

export const sendTestPush = () => requestJson<{ ok: true; sent: boolean }>("POST", "/api/push/test");
