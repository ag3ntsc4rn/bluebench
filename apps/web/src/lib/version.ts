import { SOURCE_URL } from "../routes";

// Replaced at build time by `define` in vite.config.ts.
declare const __BUILD_SHA__: string;
declare const __BUILD_DATE__: string;

/** The commit this build came from, shown in Settings so bug reports can say which version they saw. */
export const BUILD_VERSION = {
  sha: __BUILD_SHA__,
  date: __BUILD_DATE__,
  url: /^[0-9a-f]{7,40}$/.test(__BUILD_SHA__) ? `${SOURCE_URL}/commit/${__BUILD_SHA__}` : null,
};
