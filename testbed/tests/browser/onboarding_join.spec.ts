/**
 * Critical-path #4 — onboarding-link witness.
 *
 * Two assertions form the witness:
 *
 *   1. **Token claim** — tab opens `https://<host>/?join=<token>`
 *      where `<token>` is in the host ndn-fwd's `[demo_ca].tokens`
 *      list. JoinClient.join() resolves to a JoinedIdentityInfo
 *      with `restored == false` and a cert name under the host's
 *      namespace.
 *   2. **Reload restore** — same tab reloads (no `?join=` this
 *      time). JoinClient.try_restore() resolves to
 *      `JoinedIdentityInfo { restored: true }` with the same cert
 *      name. The user is fully signed in without an NDNCERT
 *      round-trip; signer-seed persistence (commit landed
 *      2026-05-10) makes this work.
 *
 * ## Status: SKIPPED pending WT fixture infrastructure
 *
 * This spec is the witness *scaffolding*. To run it for real, the
 * following needs to be running locally:
 *
 *   - ndn-fwd built (`cargo build --release -p ndn-fwd`).
 *   - A self-signed cert for `127.0.0.1` (or `localhost`) with its
 *     SHA-256 SPKI hash recorded — needed for the
 *     `?cert=<hash>` query string the browser uses to dial
 *     WebTransport with non-CA-chained certs.
 *   - ndn-fwd config with:
 *
 *     ```toml
 *     [listeners.webtransport]
 *     enabled = true
 *     listen  = "127.0.0.1:4443"
 *     [listeners.webtransport.cert_source]
 *     type     = "self_signed_dev"
 *     subject  = "localhost"
 *     [demo_ca]
 *     enabled = true
 *     prefix  = "/demo/CA"
 *     identity = "/demo/CA"
 *     tokens  = ["TEST_TOKEN_FOR_PLAYWRIGHT"]
 *     ```
 *
 *   - The `shared_engine` wasm bundle built into
 *     `fixture-page/sw-pkg/` (the existing
 *     `build-shared-engine.sh` does this).
 *   - This spec's `test.skip` flipped to `test`.
 *
 * The supporting fixture page (`onboarding-join.html`) and the
 * driving JS are committed alongside the spec so the only manual
 * step is bringing up ndn-fwd.
 *
 * The decision to ship the spec as `test.skip` rather than wire
 * the WT-listener-with-self-signed-cert spawn into Playwright's
 * webServer was deliberate: phase-4's `dioxus_demo_e2e.spec.ts`
 * established the convention that ndn-fwd is brought up
 * out-of-band (typically docker-compose), not inline; the
 * onboarding witness inherits that.
 */

import { test, expect } from '@playwright/test';

const HOST_URL = 'https://127.0.0.1:4443';
const CA_PREFIX = '/demo/CA';
const IDENTITY_PREFIX = '/demo/users';
const TOKEN = process.env.JOIN_TOKEN ?? 'TEST_TOKEN_FOR_PLAYWRIGHT';

test.describe('Critical-path #4 — onboarding-link join + reload-restore', () => {
  test.skip(
    'tab claims invite token, then reload restores from IdbPib',
    async ({ browser }) => {
      const ctx = await browser.newContext();
      const page = await ctx.newPage();
      page.on('console', (m) => console.log('[tab]', m.type(), m.text()));

      try {
        // ── First visit: claim the token. ─────────────────────────
        await page.goto(`/onboarding-join.html#join=${TOKEN}`);
        await page.waitForFunction(() => (window as any).__joinReady === true, null, {
          timeout: 15_000,
        });

        const firstResult = await page.evaluate(
          async (env: { host: string; ca: string; idp: string; token: string }) => {
            const j = (window as any).__join;
            const info = await j.join(env.host, env.ca, env.idp, env.token);
            return { cert_name: info.cert_name, restored: info.restored };
          },
          { host: HOST_URL, ca: CA_PREFIX, idp: IDENTITY_PREFIX, token: TOKEN },
        );

        expect(firstResult.restored).toBe(false);
        expect(firstResult.cert_name.length).toBeGreaterThan(0);
        expect(firstResult.cert_name.startsWith(IDENTITY_PREFIX)).toBe(true);

        // ── Second visit: same context (so IndexedDB persists). ──
        // Navigate without the `#join=` fragment; expect
        // try_restore to short-circuit.
        await page.goto('/onboarding-join.html');
        await page.waitForFunction(() => (window as any).__joinReady === true, null, {
          timeout: 15_000,
        });

        const second = await page.evaluate(async () => {
          const j = (window as any).__join;
          const info = await j.try_restore();
          return info ? { cert_name: info.cert_name, restored: info.restored } : null;
        });

        expect(second).not.toBeNull();
        expect(second!.restored).toBe(true);
        expect(second!.cert_name).toBe(firstResult.cert_name);
      } finally {
        await ctx.close();
      }
    },
  );
});
