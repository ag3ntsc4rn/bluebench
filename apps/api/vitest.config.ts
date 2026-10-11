import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        // Cloudflare's always-pass Turnstile test site key; outbound calls are mocked in tests.
        bindings: {
          TURNSTILE_SITE_KEY: "1x00000000000000000000AA",
          TURNSTILE_SECRET_KEY: "test-turnstile-secret",
          SESSION_SECRET: "test-session-secret",
          ABUSECH_AUTH_KEY: "test-abusech-key",
          SAFE_BROWSING_API_KEY: "test-sb-key",
        },
      },
    }),
  ],
});
