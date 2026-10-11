// Types for `env` and `exports` from "cloudflare:workers" in tests.
import type { Env as WorkerEnv } from "../src/env.ts";

declare global {
  namespace Cloudflare {
    interface Env extends WorkerEnv {
      TEST_MIGRATIONS: import("cloudflare:test").D1Migration[];
    }
    interface GlobalProps {
      mainModule: typeof import("../src/index.ts");
      durableNamespaces: "ProviderQuota" | "UsageCounter";
    }
  }
}
