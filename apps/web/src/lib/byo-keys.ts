import { BYO_SOURCE_IDS, type ByoSourceId } from "@bluebench/shared";
import { useEffect, useSyncExternalStore } from "react";

/**
 * The user's own API keys, kept only in this browser (IndexedDB). They're sent only to the provider:
 * directly for OTX, through our relay for the others (which doesn't store them). Never to our database.
 */
export type ByoKeys = Partial<Record<ByoSourceId, string>>;

const DB_NAME = "bluebench";
const STORE = "byo-keys";

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") return reject(new Error("IndexedDB unavailable"));
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("IndexedDB error"));
  });
}

async function tx<T>(mode: IDBTransactionMode, run: (store: IDBObjectStore) => IDBRequest<T> | void): Promise<T | undefined> {
  const db = await open();
  try {
    return await new Promise<T | undefined>((resolve, reject) => {
      const t = db.transaction(STORE, mode);
      const req = run(t.objectStore(STORE));
      t.oncomplete = () => resolve(req ? req.result : undefined);
      t.onerror = () => reject(t.error ?? new Error("IndexedDB error"));
      t.onabort = () => reject(t.error ?? new Error("IndexedDB aborted"));
    });
  } finally {
    db.close();
  }
}

async function readAll(): Promise<ByoKeys> {
  const keys: ByoKeys = {};
  await tx("readonly", (store) => {
    const cursor = store.openCursor();
    cursor.onsuccess = () => {
      const c = cursor.result;
      if (!c) return;
      if (BYO_SOURCE_IDS.includes(c.key as ByoSourceId) && typeof c.value === "string") keys[c.key as ByoSourceId] = c.value;
      c.continue();
    };
  });
  return keys;
}

type Listener = () => void;
const listeners = new Set<Listener>();
/** null until loaded. */
let current: ByoKeys | null = null;
let loading: Promise<void> | null = null;

function set(next: ByoKeys) {
  current = next;
  listeners.forEach((l) => l());
}

export const byoKeys = {
  subscribe(l: Listener) {
    listeners.add(l);
    return () => listeners.delete(l);
  },
  get: () => current,
  /** Load once per page view. Blocked storage (private mode, some browsers) just means no keys. */
  load(): Promise<void> {
    loading ??= readAll()
      .catch((): ByoKeys => ({}))
      .then(set);
    return loading;
  },
  async save(source: ByoSourceId, key: string): Promise<void> {
    await tx("readwrite", (store) => store.put(key, source));
    set({ ...current, [source]: key });
  },
  async remove(source: ByoSourceId): Promise<void> {
    await tx("readwrite", (store) => store.delete(source));
    const next = { ...current };
    delete next[source];
    set(next);
  },
};

/** The saved keys; null while loading (and in pre-rendered HTML). */
export function useByoKeys(): ByoKeys | null {
  const state = useSyncExternalStore(byoKeys.subscribe, byoKeys.get, () => null);
  useEffect(() => {
    void byoKeys.load();
  }, []);
  return state;
}
