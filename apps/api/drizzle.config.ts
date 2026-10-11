import { defineConfig } from "drizzle-kit";

// Generates SQL migrations from src/db/schema.ts. Wrangler applies them (wrangler.jsonc migrations_dir).
export default defineConfig({
  dialect: "sqlite",
  schema: "./src/db/schema.ts",
  out: "./migrations",
});
