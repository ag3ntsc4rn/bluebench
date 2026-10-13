import { afterEach, describe, expect, it, vi } from "vitest";

/** A minimal stand-in for a ServiceWorker: state changes fire "statechange", messages are recorded. */
class FakeWorker extends EventTarget {
  messages: unknown[] = [];
  constructor(public state: ServiceWorkerState) {
    super();
  }
  postMessage(m: unknown) {
    this.messages.push(m);
  }
  become(state: ServiceWorkerState, registration: FakeRegistration) {
    this.state = state;
    if (state === "installed") {
      registration.installing = null;
      registration.waiting = this;
    }
    this.dispatchEvent(new Event("statechange"));
  }
}

class FakeRegistration extends EventTarget {
  installing: FakeWorker | null = null;
  waiting: FakeWorker | null = null;
  /** What the next update() finds, applied when it resolves. */
  onUpdate: () => void = () => {};
  update() {
    this.onUpdate();
    return Promise.resolve();
  }
}

const flush = () => new Promise((r) => setTimeout(r, 0));

/** Load pwa.ts fresh against fake browser globals. */
async function start(registration: FakeRegistration, opts: { controller?: boolean; canReload?: boolean } = {}) {
  vi.resetModules();
  const doc = new EventTarget() as EventTarget & { visibilityState: string };
  doc.visibilityState = "visible";
  vi.stubGlobal("document", doc);
  vi.stubGlobal("window", { location: { reload: vi.fn() } });
  vi.stubGlobal("navigator", {
    onLine: true,
    serviceWorker: Object.assign(new EventTarget(), {
      controller: opts.controller === false ? null : {},
      register: async () => registration,
    }),
  });
  const { startPwa } = await import("./pwa");
  const { pwaUpdate } = await import("./pwa-update");
  startPwa({ canReloadNow: () => opts.canReload ?? true });
  await flush();
  return { doc, pwaUpdate };
}

const SKIP = { type: "SKIP_WAITING" };

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("startPwa", () => {
  it("activates a version that was already installing before our listeners were attached", async () => {
    const reg = new FakeRegistration();
    const worker = new FakeWorker("installing");
    reg.installing = worker; // the browser's own launch-time check got there first; updatefound already fired
    await start(reg);
    worker.become("installed", reg);
    expect(worker.messages).toEqual([SKIP]);
  });

  it("activates a version that's already waiting", async () => {
    const reg = new FakeRegistration();
    const worker = new FakeWorker("installed");
    reg.waiting = worker;
    await start(reg);
    expect(worker.messages).toContainEqual(SKIP);
  });

  it("picks up a waiting version after a check, even with no updatefound event", async () => {
    const reg = new FakeRegistration();
    const worker = new FakeWorker("installed");
    reg.onUpdate = () => (reg.waiting = worker);
    const { doc } = await start(reg);
    doc.dispatchEvent(new Event("visibilitychange"));
    await flush();
    expect(worker.messages).toContainEqual(SKIP);
  });

  it("still handles a normal updatefound", async () => {
    const reg = new FakeRegistration();
    await start(reg);
    const worker = new FakeWorker("installing");
    reg.installing = worker;
    reg.dispatchEvent(new Event("updatefound"));
    worker.become("installed", reg);
    expect(worker.messages).toEqual([SKIP]);
  });

  it("shows the Reload bar instead when reloading would lose work", async () => {
    const reg = new FakeRegistration();
    const worker = new FakeWorker("installed");
    reg.waiting = worker;
    const { pwaUpdate } = await start(reg, { canReload: false });
    expect(worker.messages).toEqual([]);
    expect(pwaUpdate.isReady()).toBe(true);
  });

  it("does nothing on a first visit (no old version to replace)", async () => {
    const reg = new FakeRegistration();
    const worker = new FakeWorker("installed");
    reg.waiting = worker;
    await start(reg, { controller: false });
    expect(worker.messages).toEqual([]);
  });
});
