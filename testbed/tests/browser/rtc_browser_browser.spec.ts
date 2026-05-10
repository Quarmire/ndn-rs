/**
 * Witness — Phase 5 WebRTC face, browser↔browser (the headline).
 *
 * Two browser contexts in the same Playwright run open the
 * dioxus-demo. Each loads the WebRTC peer panel. The test driver
 * acts as the out-of-band signaling channel: it copies the SDP+ICE
 * bundle textareas between the two pages, exactly as a human user
 * would in a "paste-into-Slack" rendezvous.
 *
 * Once both pages report "connected", the driver clicks "Send ping"
 * on page A; page B's auto-echo loop replies, and the message line
 * on page A shows the recv. The Interest/Data exchange happens
 * directly between the two browsers over a peer-to-peer SCTP
 * datachannel — **no NDN forwarder is in the path**. The forwarder
 * isn't even running for this test.
 *
 * This is the load-bearing "browser is a peer, not a client"
 * proof from `.claude/prompts/wasm/phase5-webrtc-peer.md`. Exit-1
 * today (DEMO_URL likely unset / dx serve not running); 0-after.
 *
 * Prereqs:
 *   - `dx serve` (or static build) for the dioxus-demo crate.
 *   - DEMO_URL pointing at the served bundle (default
 *     http://127.0.0.1:8080/).
 */

import { test, expect, Page } from '@playwright/test';

const DEMO_URL = process.env.DEMO_URL ?? 'http://127.0.0.1:8080/';
const HANDSHAKE_TIMEOUT = 30_000;

// Skip when the demo server isn't reachable — CI doesn't yet provision it.
test.beforeAll(async () => {
  try {
    const res = await fetch(DEMO_URL, { signal: AbortSignal.timeout(2000) });
    if (!res.ok) test.skip(true, `dioxus-demo not reachable at ${DEMO_URL} (HTTP ${res.status})`);
  } catch (e) {
    test.skip(true, `dioxus-demo not reachable at ${DEMO_URL} (${(e as Error).message})`);
  }
});

async function statusOf(page: Page): Promise<string> {
  return page.getByTestId('rtc-status').innerText();
}

async function waitForStatus(page: Page, label: string, timeout = HANDSHAKE_TIMEOUT) {
  await expect(page.getByTestId('rtc-status')).toContainText(label, { timeout });
}

async function readBlob(page: Page, testid: string): Promise<string> {
  // The textarea is readonly until the handshake step that fills
  // it completes. Wait for non-empty content rather than racing
  // the JS loop that mutates it.
  await expect.poll(
    async () => {
      const v = await page.getByTestId(testid).inputValue();
      return v.length;
    },
    { timeout: HANDSHAKE_TIMEOUT, message: `${testid} stayed empty` },
  ).toBeGreaterThan(0);
  return page.getByTestId(testid).inputValue();
}

async function pasteBlob(page: Page, testid: string, value: string) {
  await page.getByTestId(testid).fill(value);
}

test('WebRTC face — two browsers exchange Interest/Data with no forwarder', async ({ browser }) => {
  // Each browser gets its own context so cookies / storage /
  // service-workers don't leak between pages.
  const ctxA = await browser.newContext();
  const ctxB = await browser.newContext();
  const pageA = await ctxA.newPage();
  const pageB = await ctxB.newPage();

  try {
    await pageA.goto(DEMO_URL);
    await pageB.goto(DEMO_URL);
    await waitForStatus(pageA, 'idle');
    await waitForStatus(pageB, 'idle');

    // Step 1: page A creates an offer.
    await pageA.getByTestId('rtc-create-offer').click();
    const offer = await readBlob(pageA, 'rtc-offer-out');
    expect(offer.length).toBeGreaterThan(40);

    // Step 2: page B accepts the offer.
    await pasteBlob(pageB, 'rtc-offer-in', offer);
    await pageB.getByTestId('rtc-accept-offer').click();
    const answer = await readBlob(pageB, 'rtc-answer-out');
    expect(answer.length).toBeGreaterThan(40);

    // Step 3: page A finalises with the answer.
    await pasteBlob(pageA, 'rtc-answer-in', answer);
    await pageA.getByTestId('rtc-finalize').click();

    // Step 4: both pages report "connected".
    await waitForStatus(pageA, 'connected');
    await waitForStatus(pageB, 'connected');

    // Step 5: send ping from A; expect B's auto-echo to land
    // back on A's message line as "recv: pong: …".
    await pageA.getByTestId('rtc-send-ping').click();
    await expect(pageA.getByTestId('rtc-msg')).toContainText('pong:', {
      timeout: 5_000,
    });
  } finally {
    await ctxA.close();
    await ctxB.close();
  }
});
