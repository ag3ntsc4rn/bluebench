/// <reference types="vitest/config" />
import { execFileSync } from "node:child_process";
import { createServer, defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { VitePWA } from "vite-plugin-pwa";
import { formatHeadersFile } from "@bluebench/shared";

/** The commit being built: short SHA and commit date (YYYY-MM-DD), or "unknown" outside a git checkout. */
function buildVersion() {
  const git = (...args: string[]) => {
    try {
      return execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    } catch {
      return "";
    }
  };
  return { sha: git("rev-parse", "--short", "HEAD") || "unknown", date: git("log", "-1", "--format=%cs") || "unknown" };
}

// Shown on the Settings page (src/lib/version.ts). The prerender server needs it too.
const version = buildVersion();
const define = { __BUILD_SHA__: JSON.stringify(version.sha), __BUILD_DATE__: JSON.stringify(version.date) };

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

/**
 * Render every route (src/routes.ts) to static HTML with its own title, description and
 * link-preview tags, and emit sitemap.xml. The app hydrates on top; this is for crawlers,
 * link previews and first paint. Runs after Vite has emitted index.html, which is the template.
 */
function prerender(): Plugin {
  let root = "";
  return {
    name: "bluebench:prerender",
    apply: "build",
    configResolved(config) {
      root = config.root;
    },
    generateBundle: {
      order: "post",
      async handler(_options, bundle) {
        const index = bundle["index.html"];
        if (index?.type !== "asset") throw new Error("prerender: index.html not found in bundle");
        const server = await createServer({
          root,
          configFile: false,
          define,
          logLevel: "error",
          plugins: [react()],
          server: { middlewareMode: true, hmr: false, ws: false },
          appType: "custom",
        });
        try {
          const mod = (await server.ssrLoadModule("/src/prerender.tsx")) as typeof import("./src/prerender");
          const pages = mod.prerenderPages(String(index.source));
          for (const page of pages) {
            if (page.file === "index.html") index.source = page.html;
            else this.emitFile({ type: "asset", fileName: page.file, source: page.html });
          }
          this.emitFile({ type: "asset", fileName: "sitemap.xml", source: mod.sitemap(pages) });
        } finally {
          await server.close();
        }
      },
    },
  };
}

export default defineConfig({
  define,
  plugins: [
    react(),
    tailwindcss(),
    securityHeaders(),
    prerender(),
    VitePWA({
      // We register from src/pwa.ts (bundled, so no inline script for the CSP) and decide when to
      // activate a new version ourselves, so an update never wipes a half-finished paste.
      registerType: "prompt",
      injectRegister: false,
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
        // Navigations to /api/ are never answered from the cache.
        navigateFallbackDenylist: [/^\/api\//],
        // The Intel data is public and the same for everyone, so the app shows the copy on the device at once
        // and refreshes it in the background. No other API response is cached: they're personal or live.
        runtimeCaching: [
          {
            urlPattern: ({ sameOrigin, url }) => sameOrigin && url.pathname === "/api/intel/kev",
            handler: "StaleWhileRevalidate",
            options: {
              cacheName: "intel",
              expiration: { maxEntries: 5, maxAgeSeconds: 7 * 24 * 3600 },
              cacheableResponse: { statuses: [200] },
            },
          },
        ],
        // Push and notification-click handlers for alerts (public/push-sw.js).
        importScripts: ["/push-sw.js"],
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
