/**
 * Phase 6 witness — WebRTC peer reuse across tabs (placeholder).
 *
 * Open two tabs from origin A; tab 1 establishes a WebRTC peering with
 * origin B (via the existing phase-5 signaling relay path); tab 2
 * expresses an Interest reachable only via origin B; assert it is
 * served via the SAME peer connection, not a freshly negotiated one.
 *
 * Currently SKIPPED — the worker entrypoint (`worker_main`) does not
 * yet construct a `WebRtcFace` or accept a peering handshake. Wiring
 * that requires:
 *   - extending `worker_main` with a peering API (callable from the
 *     tab via a control message or a side channel),
 *   - threading the `WebRtcFace` into `Engine::add_face`,
 *   - extending the JS bootstrap to drive the offer/answer exchange
 *     against the existing `ndn-rtc-signaling-relay`.
 *
 * Tracked in `course-of-action-2026-05-09.md` item #3 as remaining
 * scope before phase 6 flips fully landed.
 */

import { test } from '@playwright/test';

test.describe('Phase 6 — SharedWorker WebRTC peer reuse', () => {
  test.skip('tab 2 reuses tab 1\'s WebRTC peer through the shared worker', async () => {
    // See doc-comment above for what wiring is needed.
  });
});
