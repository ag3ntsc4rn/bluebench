/// <reference types="vitest/config" />
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { VitePWA } from "vite-plugin-pwa";
import { formatHeadersFile } from "@bluebench/shared";

/** Emit Cloudflare's `_headers` file so static assets get the same security headers as the API. */
function securityHeaders(): Plugin {
  return {
    name: "bluebench:security-headers",
    apply: "build",
    generateBundle() {
      this.emitFile({ type: "asset", fileName: "_headers", source: formatHeadersFile() });
    },
  };
}

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    securityHeaders(),
    VitePWA({
      registerType: "autoUpdate",
      // External registerSW.js rather than an inline script, so the CSP needs no 'unsafe-inline'.
      injectRegister: "script",
      includeAssets: ["favicon.svg", "apple-touch-icon.png", "fonts/*.woff2"],
      manifest: {
        name: "Bluebench",
        short_name: "Bluebench",
        description: "Free, open-source security toolkit. Nothing you paste is logged.",
        theme_color: "#0E1116",
        background_color: "#0E1116",
        display: "standalone",
        start_url: "/",
        scope: "/",
        icons: [
          { src: "/pwa-192.png", sizes: "192x192", type: "image/png" },
          { src: "/pwa-512.png", sizes: "512x512", type: "image/png" },
          { src: "/pwa-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
        ],
      },
      workbox: {
        globPatterns: ["**/*.{js,css,html,svg,png,woff2}"],
        // API responses must never be served from the service worker cache.
        navigateFallbackDenylist: [/^\/api\//],
      },
    }),
  ],
  server: {
    // `pnpm dev:api` runs wrangler dev on :8787
    proxy: { "/api": "http://localhost:8787" },
  },
  test: {
    environment: "node",
  },
});
