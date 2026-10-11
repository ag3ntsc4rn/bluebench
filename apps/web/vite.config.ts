/// <reference types="vitest/config" />
import { createServer, defineConfig, type Plugin } from "vite";
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
