/**
 * Witness — Phase 4 Dioxus demo, producer side (load-bearing).
 *
 * The browser tab hosts the producer: the Dioxus app registers a prefix
 * (`/demo/<random>/counter`) and serves a monotonically-increasing
 * counter. A native ndn-rs consumer (`ndn-tools peek`) connects to the
 * same forwarder over UDP and fetches from the browser-served prefix.
 *
 * This is the "browser is producing, not just consuming" proof. The
 * Interest/Data path is:
 *
 *   ndn-tools peek (host)  ──UDP──▶  dioxus-demo-fwd  ──WT──▶  browser
 *                          ◀──UDP──                  ◀──WT──
 *
 * Witness contract (exit-1 today, 0-after):
 *   - Demo app loads, producer panel reports a registered prefix.
 *   - `ndn-tools peek <prefix>/counter` exits 0 with payload bytes.
 *   - Two consecutive peeks return monotonically-increasing counters.
 *
 * Prereqs (CI workflow): `docker compose up dioxus-demo-fwd`, a running
 * `dx serve` (or static build) for the demo, and `ndn-tools` on PATH.
 */

import { test, expect } from '@playwright/test';
import { execFileSync } from 'child_process';
import * as path from 'path';

const DEMO_URL = process.env.DEMO_URL ?? 'http://127.0.0.1:3002/dioxus-demo/';
const NDN_TOOLS = process.env.NDN_TOOLS_BIN
  ?? path.resolve(__dirname, '../../..', 'target/release/ndn-tools');
const FWD_FACE_URI = process.env.FWD_FACE_URI ?? 'udp://127.0.0.1:6363';

function peek(name: string): Buffer {
  return execFileSync(
    NDN_TOOLS,
    ['peek', '--face-uri', FWD_FACE_URI, name],
    { timeout: 5_000 },
  );
}

// Skip when the demo server isn't reachable — CI doesn't yet provision it.
test.beforeAll(async () => {
  try {
    const res = await fetch(DEMO_URL, { signal: AbortSignal.timeout(2000) });
    if (!res.ok) test.skip(true, `dioxus-demo not reachable at ${DEMO_URL} (HTTP ${res.status})`);
  } catch (e) {
    test.skip(true, `dioxus-demo not reachable at ${DEMO_URL} (${(e as Error).message})`);
  }
});

test('dioxus demo: browser produces, native ndn-tools peek fetches', async ({ page }) => {
  await page.goto(DEMO_URL);

  await expect(page.locator('[data-testid="face-status"]')).toHaveText(
    /connected/i,
    { timeout: 10_000 },
  );

  const prefixLocator = page.locator('[data-testid="producer-prefix"]');
  await expect(prefixLocator).toHaveText(/^\/demo\/[a-z0-9]+$/, { timeout: 10_000 });
  const prefix = (await prefixLocator.textContent())!.trim();

  // Wait for the Interest registration to propagate to the forwarder FIB.
  await page.waitForTimeout(500);

  const first = peek(`${prefix}/counter`);
  const second = peek(`${prefix}/counter`);

  const n1 = parseInt(first.toString('utf8').trim(), 10);
  const n2 = parseInt(second.toString('utf8').trim(), 10);

  expect(Number.isFinite(n1)).toBe(true);
  expect(n2).toBeGreaterThan(n1);
});
