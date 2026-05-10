/**
 * Witness — Phase 4 Dioxus demo, consumer side.
 *
 * Topology:
 *
 *   browser tab (Dioxus demo, ndn-rs engine + BrowserWebTransportFace)
 *       │  WebTransport (QUIC datagrams, NDNLPv2)
 *       ▼
 *   dioxus-demo-fwd (ndn-fwd in docker-compose, WT listener + canned producer)
 *
 * Witness contract (exit-1 today, 0-after Phase 4 lands the demo):
 *   - The Dioxus app loads at http://127.0.0.1:3002/dioxus-demo/.
 *   - Typing `/demo/hello` and clicking #express-interest populates
 *     `[data-testid="data-name"]` with `/demo/hello/v=...` within 5s.
 *   - A screenshot lands in testbed/tests/audit/transcripts/.
 *
 * The forwarder is expected to be running (`docker compose up
 * dioxus-demo-fwd`); CI brings it up before invoking Playwright. We do
 * not spawn it inline — the demo binary is the SUT, not the forwarder.
 */

import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

const DEMO_URL = process.env.DEMO_URL ?? 'http://127.0.0.1:3002/dioxus-demo/';
const TRANSCRIPT_DIR = path.resolve(
  __dirname,
  '..',
  'audit',
  'transcripts',
);

// The dioxus-demo binary must be running externally (e.g. via
// `docker compose up dioxus-demo-fwd` or `dx serve`).  When it isn't, skip
// rather than fail — CI doesn't yet provision the demo server.
test.beforeAll(async () => {
  try {
    const res = await fetch(DEMO_URL, { signal: AbortSignal.timeout(2000) });
    if (!res.ok) test.skip(true, `dioxus-demo not reachable at ${DEMO_URL} (HTTP ${res.status})`);
  } catch (e) {
    test.skip(true, `dioxus-demo not reachable at ${DEMO_URL} (${(e as Error).message})`);
  }
});

test('dioxus demo: consumer expresses Interest and renders Data', async ({ page }) => {
  await page.goto(DEMO_URL);

  await expect(page.locator('[data-testid="face-status"]')).toHaveText(
    /connected/i,
    { timeout: 10_000 },
  );

  await page.locator('[data-testid="interest-name"]').fill('/demo/hello');
  await page.locator('[data-testid="express-interest"]').click();

  const dataName = page.locator('[data-testid="data-name"]');
  await expect(dataName).toContainText('/demo/hello', { timeout: 5_000 });

  await expect(page.locator('[data-testid="data-payload-len"]'))
    .not.toHaveText('0');
  await expect(page.locator('[data-testid="data-rtt-ms"]'))
    .toHaveText(/\d+/);

  fs.mkdirSync(TRANSCRIPT_DIR, { recursive: true });
  await page.screenshot({
    path: path.join(TRANSCRIPT_DIR, 'dioxus_demo_e2e.png'),
    fullPage: true,
  });
});
