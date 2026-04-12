import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: ['**/*.spec.ts'],

  // Give each test plenty of time — it spawns ndn-fwd and waits for startup.
  timeout: 40_000,
  expect: { timeout: 10_000 },

  // Serve fixture-page/ via a trivial HTTP server before any test runs.
  webServer: {
    command: 'node serve.mjs',
    port: 3001,
    reuseExistingServer: !process.env.CI,
    stdout: 'pipe',
    stderr: 'pipe',
  },

  use: {
    baseURL: 'http://127.0.0.1:3001',
    // Chromium only — no Firefox/WebKit needed for WebSocket transport testing.
    ...devices['Desktop Chrome'],
  },

  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],

  // Upload playwright-report/ on failure (referenced in the CI workflow).
  reporter: process.env.CI
    ? [['github'], ['html', { outputFolder: 'playwright-report', open: 'never' }]]
    : [['html', { outputFolder: 'playwright-report', open: 'on-failure' }]],
});
