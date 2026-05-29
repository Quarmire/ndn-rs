/**
 * Witness — ndn-dashboard-next browser-safe attach flow.
 *
 * This spec is opt-in because it needs a live Dioxus web build:
 *
 *   dx serve --package ndn-dashboard-next --platform web \
 *     --features web --no-default-features --port 8124
 *   DASHBOARD_NEXT_URL=http://127.0.0.1:8124 \
 *     npx playwright test dashboard_next_attach_witness.spec.ts
 *
 * It proves the browser deployment target can attach to the in-page engine
 * without a dashboard-only HTTP proxy, render the browser-safe target manager,
 * and expose capability probe evidence in Settings.
 */

import { test, expect } from '@playwright/test';

const DASHBOARD_NEXT_URL = process.env.DASHBOARD_NEXT_URL;

test.beforeAll(async () => {
  if (!DASHBOARD_NEXT_URL) {
    test.skip(true, 'DASHBOARD_NEXT_URL not set; start dx serve for ndn-dashboard-next first');
    return;
  }
  try {
    const res = await fetch(DASHBOARD_NEXT_URL, { signal: AbortSignal.timeout(2500) });
    if (!res.ok) {
      test.skip(true, `ndn-dashboard-next not reachable at ${DASHBOARD_NEXT_URL} (HTTP ${res.status})`);
    }
  } catch (e) {
    test.skip(true, `ndn-dashboard-next not reachable at ${DASHBOARD_NEXT_URL} (${(e as Error).message})`);
  }
});

test('browser in-page engine attach renders probe-backed capabilities', async ({ page }) => {
  await page.goto(DASHBOARD_NEXT_URL!);
  await page.evaluate(() => localStorage.clear());
  await page.reload();

  await expect(page.locator('[data-testid="dashboard-next-root"]')).toBeVisible();
  await page.locator('[data-testid="nav-settings"]').click();
  await expect(page.locator('[data-testid="workspace-settings"]')).toBeVisible();

  await expect(page.getByRole('list', { name: 'Saved attach targets' })).toContainText(
    'browser in-page engine',
  );
  await expect(page.getByText('bridge required')).toBeVisible();

  await page.getByRole('button', { name: /Select browser in-page engine attach target/ }).click();
  await page.getByRole('button', { name: 'Probe selected attach target' }).click();

  await expect(page.getByText('browser engine sandbox')).toBeVisible();
  await expect(page.getByRole('table', { name: 'Forwarder capability matrix' })).toContainText(
    '/localhost/nfd/status/general',
  );
  await expect(page.getByRole('table', { name: 'Forwarder capability matrix' })).toContainText(
    '/localhost/nfd/ndnrs/capabilities',
  );
  await expect(page.getByRole('table', { name: 'Forwarder capability matrix' })).toContainText(
    'ok',
  );
  await expect(page.getByText('observe degraded')).toBeVisible();
});
