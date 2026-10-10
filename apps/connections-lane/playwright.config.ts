import { defineConfig } from "@playwright/test";

const APPS = process.env.HELIX_APPS_DOMAIN?.trim().toLowerCase() || "";
const hostResolverRules =
  "MAP *.local.helix.azxlabs.io 127.0.0.1" +
  (APPS ? `, MAP *.${APPS} 127.0.0.1, MAP ${APPS} 127.0.0.1` : "");

/**
 * The connections browser lane — real-Chromium
 * acceptance for the OAuth-connections popup journeys, separate from the jsdom
 * SPA project and from the vitest run entirely.
 *
 * Headed, under Xvfb (both locally and in CI): with Playwright's CDP defaults
 * the popup blocker never fires, and the blocked-open journey
 * must be ENGINE evidence. Two changes make it fire:
 *   - `--disable-popup-blocking` is removed from the default args, which
 *     restores Chromium's one-popup-per-user-gesture blocking; and
 *   - the browser runs headed (headless Chromium keeps popups unblocked under
 *     automation even with the switch removed — measured).
 * Run through `xvfb-run -a pnpm --filter @azx-pbc/connections-lane test`
 * (README has the details; the CI job does exactly this).
 */
export default defineConfig({
  testDir: "./src",
  outputDir: "test-results",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  workers: 1,
  fullyParallel: false,
  // One CI retry, fresh fixture per attempt. The lane's specs drive real
  // popups through cross-origin navigations, and the runner has twice eaten
  // one spec per run with a transient popup-close the helper (correctly)
  // read as a cancellation — not reproducible
  // locally in 20+ pressured runs. A genuine platform failure fails both
  // attempts and stays red; the retry only absorbs runner noise, and the
  // failed attempt's trace/screenshot is retained either way.
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI
    ? [["list"], ["junit", { outputFile: "test-results/lane.xml" }]]
    : [["list"]],
  use: {
    headless: false,
    // The dev topology's TLS terminates at the lane's own pump with a
    // self-signed cert the lane generated; the browser is a test instrument
    // here, not a trust boundary.
    ignoreHTTPSErrors: true,
    launchOptions: {
      ignoreDefaultArgs: ["--disable-popup-blocking"],
      args: [
        // The dev base domain maps to loopback — no /etc/hosts edit, so the
        // lane is self-sufficient on a CI runner.
        `--host-resolver-rules=${hostResolverRules}`,
      ],
    },
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
});
