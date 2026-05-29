/**
 * Witness — ndn-dashboard-next Engine read-only compatibility.
 *
 * Opt-in like the other dashboard-next browser witnesses:
 *
 *   dx serve --package ndn-dashboard-next --platform web \
 *     --features web --no-default-features --port 8124
 *   DASHBOARD_NEXT_URL=http://127.0.0.1:8124 \
 *     npx playwright test dashboard_next_engine_compat.spec.ts
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

test('Engine renders NFD as read-only compatible data', async ({ page }) => {
  await page.goto(DASHBOARD_NEXT_URL!);
  await page.locator('[data-testid="nav-settings"]').click();
  await page.getByRole('button', { name: 'Switch to NFD mock profile' }).click();
  await page.locator('[data-testid="nav-engine"]').click();

  await expect(page.locator('[data-testid="workspace-engine"]')).toBeVisible();
  await expect(page.getByText('read-only')).toBeVisible();
  await expect(page.getByText('NFD')).toBeVisible();
  await expect(page.getByText('fib/list + rib/list')).toBeVisible();
  await expect(page.getByText('stale 45s')).toBeVisible();
  await expect(page.getByText('/ndn/testbed')).toBeVisible();
});

test('Engine renders YaNFD without native-only controls', async ({ page }) => {
  await page.goto(DASHBOARD_NEXT_URL!);
  await page.locator('[data-testid="nav-settings"]').click();
  await page.getByRole('button', { name: 'Switch to YaNFD mock profile' }).click();
  await page.locator('[data-testid="nav-engine"]').click();

  await expect(page.locator('[data-testid="workspace-engine"]')).toBeVisible();
  await expect(page.getByText('read-only')).toBeVisible();
  await expect(page.getByText('YaNFD')).toBeVisible();
  await expect(page.getByText('strategy-choice/list')).toBeVisible();
  await expect(page.getByText('CS, PIT, Traffic')).toBeVisible();
});
