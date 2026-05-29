/**
 * Visual harness — ndn-dashboard-next responsive shell.
 *
 * This spec is opt-in because it needs a live Dioxus web build:
 *
 *   dx serve --package ndn-dashboard-next --platform web \
 *     --features web --no-default-features --port 8124
 *   DASHBOARD_NEXT_URL=http://127.0.0.1:8124 \
 *     npx playwright test dashboard_next_responsive.spec.ts
 *
 * The witness captures desktop/tablet/phone screenshots and verifies every
 * top-level workspace remains reachable without horizontal page overflow.
 */

import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

const DASHBOARD_NEXT_URL = process.env.DASHBOARD_NEXT_URL;
const TRANSCRIPT_DIR = path.resolve(__dirname, '..', 'audit', 'transcripts', 'dashboard-next');

const viewports = [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'tablet', width: 900, height: 1100 },
  { name: 'phone', width: 390, height: 844 },
];

const workspaces = ['observe', 'trust', 'engine', 'tools', 'settings'];

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

for (const viewport of viewports) {
  test(`dashboard-next responsive shell: ${viewport.name}`, async ({ page }) => {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.goto(DASHBOARD_NEXT_URL!);
    await expect(page.locator('[data-testid="dashboard-next-root"]')).toBeVisible();

    for (const workspace of workspaces) {
      const nav = viewport.width <= 980
        ? page.locator(`[data-testid="bottom-nav-${workspace}"]`)
        : page.locator(`[data-testid="nav-${workspace}"]`);
      await nav.click();
      await expect(page.locator(`[data-testid="workspace-${workspace}"]`)).toBeVisible();
    }

    const overflow = await page.evaluate(() => {
      const doc = document.documentElement;
      return doc.scrollWidth - doc.clientWidth;
    });
    expect(overflow).toBeLessThanOrEqual(2);

    fs.mkdirSync(TRANSCRIPT_DIR, { recursive: true });
    await page.screenshot({
      path: path.join(TRANSCRIPT_DIR, `${viewport.name}.png`),
      fullPage: true,
    });
  });
}
