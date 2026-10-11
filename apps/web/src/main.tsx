import { StrictMode } from "react";
import { createRoot, hydrateRoot } from "react-dom/client";
import { App } from "./App";
import "./index.css";
import { startPwa } from "./pwa";

const root = document.getElementById("root")!;
const app = (
  <StrictMode>
    <App />
  </StrictMode>
);
// Production pages are pre-rendered at build time (see prerender.tsx); the dev server serves an empty root.
if (root.hasChildNodes()) hydrateRoot(root, app);
else createRoot(root).render(app);

// Safe to reload for an update unless the user has something in the paste box.
startPwa({ canReloadNow: () => !document.querySelector<HTMLTextAreaElement>("#paste")?.value.trim() });
