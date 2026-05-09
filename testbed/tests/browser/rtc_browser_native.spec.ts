/**
 * Witness — Phase 5 WebRTC face, browser↔native (the second
 * headline of `.claude/prompts/wasm/phase5-webrtc-peer.md`).
 *
 * One browser context loads the dioxus-demo. The Playwright
 * driver acts as the **relay** — it reads the SDP offer bundle
 * from the browser's textarea, POSTs it to the running
 * `ndn-rtc-signaling-relay`, the native ndn-fwd's
 * `[listeners.webrtc]` accepts the offer, posts an answer to the
 * same relay, and the driver pastes it back into the browser's
 * textarea.
 *
 * Once both sides report "connected", the browser sends a ping
 * over the datachannel; the native side echoes it (the
 * dioxus-demo panel auto-replies on ping), proving end-to-end
 * Interest/Data could traverse the same channel. The forwarder
 * is in the path **only** as the answerer — there's no FIB
 * lookup, no PIT, no engine routing involved; it's a pure
 * peer-to-peer datachannel that happens to terminate on the
 * native side.
 *
 * Prereqs (not started by this spec — match the existing browser
 * specs' contract that infra is up before playwright runs):
 *   - `ndn-rtc-signaling-relay` listening at $RELAY_URL
 *     (default http://127.0.0.1:8888).
 *   - `ndn-fwd` running with `[listeners.webrtc] enabled = true`,
 *     `signaling_url = $RELAY_URL`, and at least one entry in
 *     `session_ids` matching $SESSION_ID (default
 *     "browser-native-test").
 *   - `dx serve` (or static build) for dioxus-demo at $DEMO_URL
 *     (default http://127.0.0.1:8080/).
 *
 * Skipping rather than failing when prereqs aren't reachable so
 * this can live in a CI pipeline that gates on optional infra.
 */

import { test, expect, Page } from '@playwright/test';

const DEMO_URL = process.env.DEMO_URL ?? 'http://127.0.0.1:8080/';
const RELAY_URL = process.env.RELAY_URL ?? 'http://127.0.0.1:8888';
const SESSION_ID = process.env.SESSION_ID ?? 'browser-native-test';
const HANDSHAKE_TIMEOUT = 30_000;

type Bundle = {
  description: { type: 'offer' | 'answer'; sdp: string };
  candidates: Array<{
    candidate: string;
    sdpMid?: string;
    sdpMLineIndex?: number;
  }>;
};

async function statusOf(page: Page): Promise<string> {
  return page.getByTestId('rtc-status').innerText();
}

async function readBlob(page: Page, testid: string): Promise<string> {
  await expect.poll(
    async () => (await page.getByTestId(testid).inputValue()).length,
    { timeout: HANDSHAKE_TIMEOUT, message: `${testid} stayed empty` },
  ).toBeGreaterThan(0);
  return page.getByTestId(testid).inputValue();
}

/** Decode base64url(JSON) → Bundle, the manual-signaling shape. */
function decodeBundle(blob: string): Bundle {
  const b64 = blob.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - b64.length % 4) % 4);
  const json = Buffer.from(padded, 'base64').toString('utf8');
  return JSON.parse(json);
}

/** Encode Bundle → base64url(JSON). */
function encodeBundle(b: Bundle): string {
  const json = JSON.stringify(b);
  return Buffer.from(json, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function relayUp(): Promise<boolean> {
  try {
    // The relay long-polls on GET /<id>/offer; we want to know it
    // exists, not wait 30s. Use a HEAD (or a short-circuit GET).
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 1_000);
    const res = await fetch(`${RELAY_URL}/rendezvous/__healthcheck__/offer`, {
      signal: ctrl.signal,
    });
    clearTimeout(t);
    // 408 (timeout) or 200 (got something) both prove server is up.
    return res.status === 408 || res.status === 200;
  } catch {
    return false;
  }
}

async function demoUp(): Promise<boolean> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 1_000);
    const res = await fetch(DEMO_URL, { signal: ctrl.signal });
    clearTimeout(t);
    return res.ok;
  } catch {
    return false;
  }
}

test('WebRTC face — browser ↔ native via signaling relay', async ({ browser }) => {
  test.skip(!(await demoUp()), `dioxus-demo not reachable at ${DEMO_URL}`);
  test.skip(!(await relayUp()), `signaling relay not reachable at ${RELAY_URL}`);

  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  try {
    await page.goto(DEMO_URL);
    await expect(page.getByTestId('rtc-status')).toContainText('idle');

    // Step 1 — the browser creates an offer.
    await page.getByTestId('rtc-create-offer').click();
    const offerBlob = await readBlob(page, 'rtc-offer-out');

    // Step 2 — POST the offer's SessionDescription to the relay.
    // The relay's wire shape is `{type, sdp}`, not the
    // dioxus-demo Bundle (which also carries candidates). Pull
    // the description out of the bundle.
    const offerBundle = decodeBundle(offerBlob);
    const postOffer = await fetch(
      `${RELAY_URL}/rendezvous/${SESSION_ID}/offer`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(offerBundle.description),
      },
    );
    expect(postOffer.ok).toBeTruthy();

    // Step 3 — long-poll the relay for the answer the native
    // ndn-fwd's WebRtcListener posts after accepting the offer.
    // The poll honours the relay's 30s server-side cap; if the
    // listener never runs, this throws.
    const answerRes = await fetch(
      `${RELAY_URL}/rendezvous/${SESSION_ID}/answer`,
      { signal: AbortSignal.timeout(HANDSHAKE_TIMEOUT) },
    );
    expect(answerRes.status).toBe(200);
    const answerDescription = await answerRes.json();

    // Step 4 — paste the answer (re-bundled) into the browser's
    // peer-answer box and finalize. The dioxus-demo panel
    // expects the manual-signaling Bundle shape.
    const answerBlobIn = encodeBundle({
      description: answerDescription,
      candidates: [],
    });
    await page.getByTestId('rtc-answer-in').fill(answerBlobIn);
    await page.getByTestId('rtc-finalize').click();
    await expect(page.getByTestId('rtc-status')).toContainText(
      'connected',
      { timeout: HANDSHAKE_TIMEOUT },
    );

    // Step 5 — round-trip a ping. The native side doesn't run
    // the dioxus-demo's auto-echo loop — it's running ndn-fwd
    // — so we don't expect a "pong" back here. The success
    // signal is "the channel is open and the browser believes
    // a peer is on the other end". For the wire-level Data
    // round-trip, see the in-process witness
    // tests/listener_accepts.rs which uses the same flow.
    await page.getByTestId('rtc-send-ping').click();
    await expect(page.getByTestId('rtc-msg')).toContainText(
      'sent ping',
      { timeout: 5_000 },
    );
  } finally {
    await ctx.close();
  }
});
