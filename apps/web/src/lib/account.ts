import type { AlertsResponse, ApiError, DomainsResponse, Me, SavedDomain } from "@bluebench/shared";
import { useEffect, useSyncExternalStore } from "react";
import { postWithSession, requestJson, type GetTurnstileToken } from "./api";

/**
 * Who's signed in, shared by every component. The account cookie is HttpOnly, so the page can't see
 * it; instead we keep a "probably signed in" hint in localStorage and only ask the server (GET
 * /api/me) when it's set. Anonymous visitors never cost a Worker request.
 */
const HINT = "bb.signedIn";

const SIGNED_OUT: Me = { ok: true, signedIn: false, accountsEnabled: true };

function hint(): boolean {
  try {
    return localStorage.getItem(HINT) === "1";
  } catch {
    return false;
  }
}

function setHint(on: boolean) {
  try {
    if (on) localStorage.setItem(HINT, "1");
    else localStorage.removeItem(HINT);
  } catch {
    // Private mode or blocked storage: we just ask the server next time.
  }
}

type Listener = () => void;
const listeners = new Set<Listener>();
/** null until we know (only while the hint says signed in and /api/me hasn't answered). */
let me: Me | null = null;
let loading: Promise<void> | null = null;

function set(next: Me) {
  me = next;
  setHint(next.signedIn);
  listeners.forEach((l) => l());
}

export const account = {
  subscribe(l: Listener) {
    listeners.add(l);
    return () => listeners.delete(l);
  },
  get: () => me,
  set,
  /** Load once per page view, and only if we think there's an account session. */
  load(): Promise<void> {
    if (me) return Promise.resolve();
    if (!hint()) {
      set(SIGNED_OUT);
      return Promise.resolve();
    }
    loading ??= requestJson<Me>("GET", "/api/me").then((res) => set(res.ok ? res : SIGNED_OUT));
    return loading;
  },
  /** The server said we're signed out (session expired or revoked). */
  signedOut() {
    set(SIGNED_OUT);
  },
};

/** Current account state; null while it's being checked. Pre-rendered HTML always starts as null. */
export function useAccount(): Me | null {
  const state = useSyncExternalStore(account.subscribe, account.get, () => null);
  useEffect(() => {
    void account.load();
  }, []);
  return state;
}

/** Call an account endpoint; a "signed-out" answer flips the shared state. */
async function authed<T extends { ok: true }>(method: "GET" | "POST" | "PATCH" | "DELETE", path: string, body?: unknown): Promise<T | ApiError> {
  const res = await requestJson<T>(method, path, body);
  if (!res.ok && res.error === "signed-out") account.signedOut();
  return res;
}

/** Ask for a magic link. Runs the bot check if the server wants one. */
export const requestSignIn = (email: string, getToken: GetTurnstileToken) => postWithSession<{ ok: true }>("/api/signin", { email }, getToken, fetch);

export async function finishSignIn(token: string): Promise<Me | ApiError> {
  const res = await requestJson<Me>("POST", "/api/signin/verify", { token });
  if (res.ok) set(res);
  return res;
}

export async function signOut(): Promise<void> {
  await requestJson("POST", "/api/signout");
  set(SIGNED_OUT);
}

export async function deleteAccount(): Promise<ApiError | { ok: true }> {
  const res = await authed<{ ok: true }>("DELETE", "/api/account");
  if (res.ok) set(SIGNED_OUT);
  return res;
}

export async function setEmailAlerts(emailAlerts: boolean): Promise<Me | ApiError> {
  const res = await authed<Me>("PATCH", "/api/account", { emailAlerts });
  if (res.ok) set(res);
  return res;
}

export const listDomains = () => authed<DomainsResponse>("GET", "/api/domains");
export const saveDomain = (domain: string) => authed<{ ok: true; domain: SavedDomain }>("POST", "/api/domains", { domain });
export const verifyDomain = (id: string) => authed<{ ok: true; domain: SavedDomain }>("POST", `/api/domains/${encodeURIComponent(id)}/verify`);
export const removeDomain = (id: string) => authed<{ ok: true }>("DELETE", `/api/domains/${encodeURIComponent(id)}`);
export const listAlerts = () => authed<AlertsResponse>("GET", "/api/alerts");
