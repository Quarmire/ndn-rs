/**
 * PWA smoke witness for ndn-dashboard-next.
 *
 * Requires a served browser build:
 *   DASHBOARD_NEXT_URL=http://127.0.0.1:8124 npx playwright test dashboard_next_pwa_smoke.spec.ts
 */

import { test, expect } from '@playwright/test';

const DASHBOARD_NEXT_URL = process.env.DASHBOARD_NEXT_URL;

test.beforeAll(async () => {
  if (!DASHBOARD_NEXT_URL) {
    test.skip(true, 'DASHBOARD_NEXT_URL not set');
  }
});

test('dashboard-next serves PWA manifest and mobile workspaces', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(DASHBOARD_NEXT_URL!);
  await expect(page.locator('[data-testid="dashboard-next-root"]')).toBeVisible();

  const manifestHref = await page.locator('link[rel="manifest"]').getAttribute('href');
  expect(manifestHref).toBeTruthy();

  for (const workspace of ['observe', 'trust', 'engine', 'tools', 'settings']) {
    await page.locator(`[data-testid="bottom-nav-${workspace}"]`).click();
    await expect(page.locator(`[data-testid="workspace-${workspace}"]`)).toBeVisible();
  }
});
