import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig(async () => ({
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
          BETTER_AUTH_SECRET: "test-better-auth-secret-at-least-32-chars",
          RESEND_API_KEY: "test-resend-key",
          // A throwaway key pair, only ever used in tests.
          VAPID_PUBLIC_KEY: "BBFzJZH2R5ory1PZoudMfhTouQ38IkUxbNQzxd-G9K1EQOn1GzC3IAIzhOKGM00g0Jvz1M5SvG0xu40YkwyrFBg",
          VAPID_PRIVATE_KEY: "rJCsUqfA92tAuNXyjQ8sj18r-rM5cyX_IujLwXQVeCM",
          TEST_MIGRATIONS: await readD1Migrations("./migrations"),
        },
      },
    }),
  ],
  test: { setupFiles: ["./test/setup.ts"] },
}));
