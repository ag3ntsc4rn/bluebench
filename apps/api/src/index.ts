import { Hono } from "hono";
import { SECURITY_HEADERS, type HealthResponse } from "@bluebench/shared";

export interface Env {
  ASSETS: Fetcher;
}

const app = new Hono<{ Bindings: Env }>().basePath("/api");

// Security headers on every API response, including 404s and errors.
app.use("*", async (c, next) => {
  await next();
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    c.res.headers.set(name, value);
  }
  c.res.headers.set("Cache-Control", "no-store");
});

app.get("/health", (c) => c.json<HealthResponse>({ ok: true }));

app.notFound((c) => c.json({ ok: false, error: "Not found" }, 404));

// Never echo request details or stack traces; nothing pasted is logged.
app.onError((_err, c) => c.json({ ok: false, error: "Internal error" }, 500));

export default app;
