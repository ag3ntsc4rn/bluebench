import { TURNSTILE_ORIGIN } from "@bluebench/shared";

interface TurnstileApi {
  render(
    container: HTMLElement,
    options: {
      sitekey: string;
      appearance?: "always" | "execute" | "interaction-only";
      callback?: (token: string) => void;
      "error-callback"?: () => void;
      "timeout-callback"?: () => void;
    },
  ): string | undefined;
  remove(widgetId: string): void;
}

declare global {
  interface Window {
    turnstile?: TurnstileApi;
  }
}

let loading: Promise<TurnstileApi> | null = null;

/** Load Cloudflare's Turnstile script once, only when a lookup first needs a bot check. */
function loadTurnstile(): Promise<TurnstileApi> {
  if (window.turnstile) return Promise.resolve(window.turnstile);
  loading ??= new Promise<TurnstileApi>((resolve, reject) => {
    const script = document.createElement("script");
    script.src = `${TURNSTILE_ORIGIN}/turnstile/v0/api.js?render=explicit`;
    script.async = true;
    script.onload = () => (window.turnstile ? resolve(window.turnstile) : reject(new Error("Turnstile missing")));
    script.onerror = () => {
      loading = null;
      script.remove();
      reject(new Error("Turnstile failed to load"));
    };
    document.head.appendChild(script);
  });
  return loading;
}

/**
 * Run an invisible Turnstile challenge in `container` and resolve with its token.
 * The widget only shows itself if Cloudflare needs the visitor to interact.
 */
export async function runTurnstile(container: HTMLElement, siteKey: string): Promise<string> {
  const turnstile = await loadTurnstile();
  return new Promise<string>((resolve, reject) => {
    let widgetId: string | undefined;
    const done = (fn: () => void) => {
      fn();
      // Deferred: a callback can fire before render() has returned the id.
      setTimeout(() => widgetId && turnstile.remove(widgetId));
    };
    widgetId = turnstile.render(container, {
      sitekey: siteKey,
      appearance: "interaction-only",
      callback: (token) => done(() => resolve(token)),
      "error-callback": () => done(() => reject(new Error("Turnstile error"))),
      "timeout-callback": () => done(() => reject(new Error("Turnstile timeout"))),
    });
  });
}
