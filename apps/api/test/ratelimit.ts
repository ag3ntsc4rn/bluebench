/** Long enough for any rate-limit test here to make its requests, with room to spare on a slow CI runner. */
const NEEDED_MS = 15_000;
/** A test that may wait out the rest of a minute needs more than Vitest's default 5 s timeout. */
export const WINDOW_TIMEOUT_MS = 30_000;

/**
 * Wait, if needed, so a test's requests all land in one rate-limit window. Miniflare's windows are aligned
 * to the wall clock (epoch = floor(now / period)), so requests that straddle a minute boundary are counted
 * in two windows and the limit never trips.
 */
export async function inOneWindow(periodSeconds = 60): Promise<void> {
  const period = periodSeconds * 1000;
  const left = period - (Date.now() % period);
  if (left < NEEDED_MS) await new Promise((r) => setTimeout(r, left + 100));
}
