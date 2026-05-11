/**
 * Witness — WebRTC ↔ SharedWorker tab-side bridge.
 *
 * Reifies the worker-bridge pattern (W3C blocks `RTCPeerConnection`
 * inside `WorkerGlobalScope`, so a tab carries the WebRTC peer and
 * pumps bytes into the SharedWorker through a `WorkerPortFace`).
 *
 * Topology:
 *
 *   ┌─────────────────────────┐                ┌─────────────────────────┐
 *   │ peer-tab                │                │ bridge-tab              │
 *   │   TransitPeer           │ ◀─ WebRTC ─▶  │   TransitBridge        │
 *   │   /transit-bridge-test/ │  datachannel  │   ↕ pump                │
 *   │     counter Interest    │                │   SharedWorkerProxy     │
 *   └─────────────────────────┘                │   (face into worker)    │
 *                                              └────────────┬────────────┘
 *                                                           │ MessagePort
 *                                                           ▼
 *                                              ┌─────────────────────────┐
 *                                              │ per-origin SharedWorker │
 *                                              │   ForwarderEngine       │
 *                                              │   FIB: /cache-test →    │
 *                                              │   AppFace (producer)    │
 *                                              └─────────────────────────┘
 *
 * Witness contract:
 *   1. Open peer-tab + bridge-tab.
 *   2. Peer create_offer → bridge accept_offer → peer set_answer +
 *      bridge start (parallel finalize).
 *   3. Peer expresses `/cache-test/counter` over the WebRTC face;
 *      bytes flow rtc-pump → WorkerPortFace → engine pipeline →
 *      FIB(/cache-test) → AppFace → producer → reverse path back.
 *   4. Decode the returned content and assert it parses as the
 *      producer's counter payload ("1" on first call).
 *
 * Pinned to Chromium per playwright.config.ts; skipped in CI
 * because GHA's headless Chromium can't complete the SCTP
 * handshake reliably (same caveat as transit_browser_as_forwarder).
 */

import { test, expect } from '@playwright/test';

const PEER_URL = '/transit-peer.html';
const BRIDGE_URL = '/transit-bridge.html';
const READY_TIMEOUT = 15_000;

test.describe('WebRTC ↔ SharedWorker bridge', () => {
  test.skip(!!process.env.CI, 'WebRTC SCTP handshake unreliable on headless GHA');

  test('peer reaches SharedWorker producer via tab-side bridge', async ({ browser }) => {
    const ctxBridge = await browser.newContext();
    const ctxPeer = await browser.newContext();
    const bridgePage = await ctxBridge.newPage();
    const peerPage = await ctxPeer.newPage();
    bridgePage.on('console', (m) => console.log('[bridge]', m.type(), m.text()));
    peerPage.on('console', (m) => console.log('[peer]', m.type(), m.text()));

    try {
      await bridgePage.goto(BRIDGE_URL);
      await peerPage.goto(PEER_URL);
      await bridgePage.waitForFunction(
        () => (window as any).__bridgeReady === true,
        null,
        { timeout: READY_TIMEOUT },
      );
      await peerPage.waitForFunction(
        () => (window as any).__peerReady === true,
        null,
        { timeout: READY_TIMEOUT },
      );

      // 1. Peer creates the SDP offer.
      const offer = await peerPage.evaluate(async () => {
        return await (window as any).__peer.create_offer();
      });
      expect(offer.length).toBeGreaterThan(40);

      // 2. Bridge accepts and returns the SDP answer.
      const answer = await bridgePage.evaluate(async (offerJson: string) => {
        return await (window as any).__bridge.accept_offer(offerJson);
      }, offer);
      expect(answer.length).toBeGreaterThan(40);

      // 3. Parallel finalize on both sides.
      await Promise.all([
        peerPage.evaluate(async (answerJson: string) => {
          await (window as any).__peer.set_answer(answerJson);
        }, answer),
        bridgePage.evaluate(async () => {
          await (window as any).__bridge.start();
        }),
      ]);

      // 4. Peer expresses /cache-test/counter through the bridge to
      //    the SharedWorker's local producer.
      const payload = await peerPage.evaluate(async () => {
        const arr: Uint8Array = await (window as any).__peer.express(
          '/cache-test/counter',
          5000,
        );
        return new TextDecoder().decode(arr);
      });

      console.log('[witness] payload through bridge:', payload);
      // Producer counter mints "1" on first call.
      expect(payload).toBe('1');
    } finally {
      await ctxBridge.close();
      await ctxPeer.close();
    }
  });
});
