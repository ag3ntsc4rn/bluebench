import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./index.css";
import { startPwa } from "./pwa";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

// Safe to reload for an update unless the user has something in the paste box.
startPwa({ canReloadNow: () => !document.querySelector<HTMLTextAreaElement>("#paste")?.value.trim() });
