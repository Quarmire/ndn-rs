/**
 * Critical-path #4 — onboarding-link witness.
 *
 * Proves the token-join loop end to end against a real embedded NDNCERT CA:
 *
 *   1. **Token claim** — a tab loads the wasm `JoinClient` and calls
 *      `join(host, ca, idp, token)` where `token` is in the spawned
 *      ndn-fwd's `[demo_ca].tokens`. It opens a WebTransport face to the
 *      forwarder, runs NDNCERT NEW + CHALLENGE(token) + cert-fetch, and
 *      resolves to a `JoinedIdentityInfo { restored:false }` with a cert
 *      name under the requested identity prefix.
 *   2. **Reload restore** — the same browser context reloads without a
 *      `#join=` fragment; `try_restore()` resolves to
 *      `{ restored:true }` with the same cert name, from IdbPib — no
 *      NDNCERT round-trip.
 *
 * The forwarder is spawned here (like `webtransport.spec.ts`): its
 * self-signed dev cert SHA-256 is scraped from the startup log and pinned
 * via the `?cert=<hash>` query the wasm WebTransport face parses
 * (`serverCertificateHashes`). The test skips cleanly if the release
 * `ndn-fwd` binary is absent or never logs a cert hash.
 *
 * Prereqs to run:
 *   - `cargo build --release -p ndn-fwd`  (webtransport is a default feature)
 *   - `./build-shared-engine.sh`          (writes fixture-page/sw-pkg/)
 */

import { test, expect } from '@playwright/test';
import { spawn, ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const REPO_ROOT = path.resolve(__dirname, '../../..');
const NDN_FWD_BIN =
  process.env.NDN_FWD_BIN ?? path.join(REPO_ROOT, 'target', 'release', 'ndn-fwd');
const WASM_BUNDLE = path.join(__dirname, 'fixture-page', 'sw-pkg', 'shared_engine_bg.wasm');

const WT_PORT = 4443;
// The CA's identity prefix. `[demo_ca].prefix` is the identity; NdncertCa
// appends `/CA` itself and serves `/demo/CA/{INFO,NEW,CHALLENGE}`. The enroll
// client likewise appends `/CA/NEW`, so both sides land on `/demo/CA/NEW`.
// (Configuring `/demo/CA` would make the CA serve `/demo/CA/CA/NEW` and reject
// the client's `/demo/CA/NEW` as an unrecognised Interest.)
const CA_PREFIX = '/demo';
const IDENTITY_PREFIX = '/demo/users';
const TOKEN = process.env.JOIN_TOKEN ?? 'TEST_TOKEN_FOR_PLAYWRIGHT';

// Embedded NDNCERT CA gated by a token challenge, reachable over WebTransport.
const FWD_CONFIG = `
[security]
profile = "disabled"

[security.mgmt]
require_signed_commands = false

[listeners.webtransport]
enabled = true
listen = "127.0.0.1:${WT_PORT}"
cert_source = { type = "self_signed_dev", hostnames = ["localhost", "127.0.0.1"] }

[demo_ca]
enabled = true
prefix = "${CA_PREFIX}"
identity = "${CA_PREFIX}"
tokens = ["${TOKEN}"]

[logging]
level = "info"
`;

let fwdProc: ChildProcess | null = null;
let certHashHex = '';
const fwdConfigPath = path.join(os.tmpdir(), 'ndn-fwd-onboarding-join-test.toml');

/** Wait for the forwarder to log its leaf cert SHA-256 (hex). */
function waitForCertHash(proc: ChildProcess): Promise<string> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('cert_sha256 not logged')), 8000);
    const onData = (d: Buffer) => {
      const m = /cert_sha256[=:]?\s*"?([0-9a-fA-F]{64})/.exec(d.toString());
      if (m) {
        clearTimeout(timer);
        resolve(m[1]);
      }
    };
    proc.stdout?.on('data', onData);
    proc.stderr?.on('data', onData);
  });
}

test.beforeAll(async () => {
  if (!fs.existsSync(NDN_FWD_BIN)) {
    return; // tests below skip when the binary is absent
  }
  fs.writeFileSync(fwdConfigPath, FWD_CONFIG);
  fwdProc = spawn(NDN_FWD_BIN, ['-c', fwdConfigPath], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (process.env.VERBOSE) {
    fwdProc.stdout?.on('data', (d: Buffer) => process.stdout.write(`[ndn-fwd] ${d}`));
    fwdProc.stderr?.on('data', (d: Buffer) => process.stderr.write(`[ndn-fwd] ${d}`));
  }
  try {
    certHashHex = await waitForCertHash(fwdProc);
  } catch {
    /* leave empty → tests skip */
  }
  await new Promise<void>((r) => setTimeout(r, 500));
});

test.afterAll(async () => {
  fwdProc?.kill('SIGTERM');
  fwdProc = null;
  fs.rmSync(fwdConfigPath, { force: true });
});

// STATUS 2026-06-01: PASSES end to end (NEW → CHALLENGE(token) → cert-fetch →
// SafeBag → reload-restore). Getting here surfaced four real bugs, now fixed:
//   - `AlalFeature::new` raw `Instant::now()` panicked in-browser;
//   - `ndn-mgmt` notification raw `tokio::spawn` panicked in-browser;
//   - `WasmEngineBuilder` never wired builder-added faces' I/O (no sender);
//   - `FaceTable` id allocator collided with the fixed-id upstream face.
// Runs when ndn-fwd (release) and the wasm bundle are built; skips cleanly
// otherwise (CI brings ndn-fwd up out-of-band, per the dioxus_demo convention).
test.describe('Critical-path #4 — onboarding-link join + reload-restore', () => {
  test('tab claims invite token, then reload restores from IdbPib', async ({ browser }) => {
    test.skip(!fs.existsSync(NDN_FWD_BIN), `ndn-fwd binary not found at ${NDN_FWD_BIN}`);
    test.skip(!fs.existsSync(WASM_BUNDLE), 'wasm bundle not built — run ./build-shared-engine.sh');
    test.skip(!certHashHex, 'forwarder did not log a cert hash');

    const HOST_URL = `https://127.0.0.1:${WT_PORT}/ndn?cert=${certHashHex}`;

    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    page.on('console', (m) => console.log('[tab]', m.type(), m.text()));

    try {
      // ── First visit: claim the token. ───────────────────────────────
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

      // ── Second visit: same context (IndexedDB persists). ────────────
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
  });
});
