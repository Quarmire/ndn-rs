/**
 * Witness — ndn-dashboard-next Tools workbench controls.
 *
 * Opt-in like the other dashboard-next browser witnesses:
 *
 *   dx serve --package ndn-dashboard-next --platform web \
 *     --features web --no-default-features --port 8124
 *   DASHBOARD_NEXT_URL=http://127.0.0.1:8124 \
 *     npx playwright test dashboard_next_tools_workbench.spec.ts
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

for (const viewport of [
  { name: 'desktop', width: 1366, height: 850 },
  { name: 'phone', width: 390, height: 844 },
]) {
  test(`Tools workbench exposes full tool slice on ${viewport.name}`, async ({ page }) => {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.goto(DASHBOARD_NEXT_URL!);

    const nav = viewport.width <= 980
      ? page.locator('[data-testid="bottom-nav-tools"]')
      : page.locator('[data-testid="nav-tools"]');
    await nav.click();

    await expect(page.locator('[data-testid="workspace-tools"]')).toBeVisible();
    if (viewport.width > 980) {
      await expect(page.getByRole('button', { name: 'Collapse workspace navigation' })).toBeVisible();
    } else {
      await expect(page.locator('[data-testid="dashboard-next-root"]')).toBeVisible();
    }
    await expect(page.getByRole('tab', { name: 'Ping' })).toBeVisible();
    await expect(page.getByRole('tab', { name: 'Iperf' })).toBeVisible();
    await expect(page.getByRole('tab', { name: 'Peek' })).toBeVisible();
    await expect(page.getByRole('tab', { name: 'Put' })).toBeVisible();
    await expect(page.getByRole('tab', { name: 'Diagnostics' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Run ping workflow' })).toBeVisible();

    await page.getByRole('tab', { name: 'Iperf' }).click();
    await expect(page.getByRole('button', { name: 'Run iperf workflow' })).toBeVisible();
    await expect(page.getByText('Duration s')).toBeVisible();
    await expect(page.getByText('CC')).toBeVisible();

    await page.getByRole('tab', { name: 'Peek' }).click();
    await expect(page.getByRole('button', { name: 'Run peek workflow' })).toBeVisible();
    await expect(page.getByText('Pipeline')).toBeVisible();

    await page.getByRole('tab', { name: 'Put' }).click();
    await expect(page.getByRole('button', { name: 'Run put workflow' })).toBeVisible();
    await expect(page.getByText('Payload')).toBeVisible();
    await expect(page.getByText('Freshness ms')).toBeVisible();

    await page.getByRole('tab', { name: 'Diagnostics' }).click();
    await expect(page.getByRole('button', { name: 'Lookup trace' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Run route diagnostic' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Run face diagnostic' })).toBeVisible();
    await expect(page.getByText('server /ping')).toBeVisible();
    await expect(page.getByRole('button', { name: /Download selected tool results/ })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Collapse tool detail panel' })).toBeVisible();
  });
}

for (const viewport of [
  { name: 'desktop', width: 1366, height: 850 },
  { name: 'phone', width: 390, height: 844 },
]) {
  test(`Trust workspace exposes identity slice on ${viewport.name}`, async ({ page }) => {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.goto(DASHBOARD_NEXT_URL!);

    const nav = viewport.width <= 980
      ? page.locator('[data-testid="bottom-nav-trust"]')
      : page.locator('[data-testid="nav-trust"]');
    await nav.click();

    await expect(page.locator('[data-testid="workspace-trust"]')).toBeVisible();
    await expect(page.getByText('Identity and custody')).toBeVisible();
    await expect(page.getByText('Anchors and schema')).toBeVisible();
    await expect(page.getByText('Approvals and enrollment')).toBeVisible();
    await expect(page.getByText('Validation and schema review')).toBeVisible();
    await expect(page.getByText('SafeBag import preview')).toBeVisible();
  });
}
