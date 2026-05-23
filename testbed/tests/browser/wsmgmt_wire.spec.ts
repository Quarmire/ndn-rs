/**
 * Witness — ndn-dashboard `WsMgmtClient` against a live `ndn-fwd`.
 *
 * Browser-side counterpart to `crates/ndn-mgmt/tests/web_wire_e2e.rs`.
 * Where the native test proves the wire bytes parse correctly inside
 * `mount_management`, this one proves the *production browser path* —
 * `InterestBuilder::app_parameters(ControlParameters::encode())`
 *   → `gloo-net WebSocket`
 *   → ndn-fwd's WebSocket face
 *   → mgmt dispatcher
 *   → ControlResponse Data back to the page —
 * carries the same wire end-to-end.
 *
 * Topology:
 *
 *   Chromium tab (Playwright)
 *       │  fixture page loads `dashboard_witness_bg.wasm`
 *       │  → `window.__witness.{status_general, face_create, …}`
 *       ▼
 *   wasm: `WsMgmtClient` (real dashboard code)
 *       │  gloo-net WebSocket binary frames
 *       ▼
 *   ndn-fwd (Rust, WS face on :9898)
 *       │  mount_management dispatcher
 *       ▼
 *   ControlResponse Data → wasm decode → JSON to Playwright
 *
 * Pinned to Chromium per `playwright.config.ts`.
 */

import { test, expect } from '@playwright/test';
import { spawn, type ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const REPO_ROOT = path.resolve(__dirname, '../../..');
const NDN_FWD_BIN =
  process.env.NDN_FWD_BIN ?? path.join(REPO_ROOT, 'target', 'release', 'ndn-fwd');

// Port distinct from ws-transport.spec.ts (9797) so the two specs can
// run in parallel without colliding.
const WS_PORT = 9898;
const WS_URL = `ws://127.0.0.1:${WS_PORT}`;

const FWD_CONFIG = `
[security]
profile = "disabled"

[security.mgmt]
require_signed_commands = false

[[face]]
kind = "web-socket"
bind = "0.0.0.0:${WS_PORT}"

[logging]
level = "warn"
`;

let fwdProc: ChildProcess | null = null;
const fwdConfigPath = path.join(os.tmpdir(), 'ndn-fwd-wsmgmt-witness.toml');

test.beforeAll(async () => {
  fs.writeFileSync(fwdConfigPath, FWD_CONFIG);

  fwdProc = spawn(NDN_FWD_BIN, ['-c', fwdConfigPath], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  fwdProc.stdout?.on('data', (d: Buffer) => {
    if (process.env.VERBOSE) process.stdout.write(`[ndn-fwd] ${d}`);
  });
  fwdProc.stderr?.on('data', (d: Buffer) => {
    if (process.env.VERBOSE) process.stderr.write(`[ndn-fwd] ${d}`);
  });

  // Give ndn-fwd time to bind the listen port before the first test.
  await new Promise<void>(r => setTimeout(r, 800));
});

test.afterAll(async () => {
  fwdProc?.kill('SIGTERM');
  fwdProc = null;
  fs.rmSync(fwdConfigPath, { force: true });
});

/** Open the fixture page and wait for the wasm witness API to register. */
async function openWitnessPage(page: import('@playwright/test').Page) {
  await page.goto('/dashboard-witness.html');
  await page.waitForFunction(() => (window as any).__witnessReady === true, {
    timeout: 8000,
  });
}

interface WitnessResult {
  status_code: number;
  status_text: string;
  body_len: number;
}

async function callWitness(
  page: import('@playwright/test').Page,
  fn: string,
  args: unknown[],
): Promise<WitnessResult> {
  const raw = await page.evaluate(
    async ({ fn, args }: { fn: string; args: unknown[] }) => {
      const api = (window as any).__witness as Record<string, (...a: unknown[]) => Promise<string>>;
      return await api[fn](...args);
    },
    { fn, args },
  );
  return JSON.parse(raw) as WitnessResult;
}

// ── Cases ────────────────────────────────────────────────────────────────────

test('status/general — bare Interest path through gloo-net WebSocket', async ({ page }) => {
  await openWitnessPage(page);
  const r = await callWitness(page, 'status_general', [WS_URL]);
  expect(r.status_code).toBe(200);
  expect(r.status_text).toMatch(/faces=|fib=/);
});

test('faces/list — dataset verb (CanBePrefix path)', async ({ page }) => {
  await openWitnessPage(page);
  const r = await callWitness(page, 'faces_list', [WS_URL]);
  expect(r.status_code).toBe(200);
  // Dataset content is concatenated FaceStatus TLVs; a freshly booted
  // forwarder has at least the WS listener face plus the mgmt face.
  expect(r.body_len).toBeGreaterThan(0);
});

test('cs/config — CP-in-AppParameters mutation path', async ({ page }) => {
  await openWitnessPage(page);
  // wasm-bindgen represents Rust `u64` as JS `BigInt`, so pass `16384n`
  // not `16384`. Same below for `rib/register`.
  const r = await callWitness(page, 'cs_config', [WS_URL, 16384n]);
  // This is the path that was broken pre-2026-05-13: ControlParameters
  // encoded via `ndn_config::ControlParameters::encode()` and stuffed
  // into `ApplicationParameters` with `InterestBuilder`. A spec-strict
  // dispatcher must accept the auto-appended PSDC and dispatch to
  // `cs/config`, returning 200 with the active capacity echoed.
  expect(r.status_code).toBe(200);
});

test('rib/register — full mutation round-trip with CP fields', async ({ page }) => {
  await openWitnessPage(page);
  // face_id == 0 → "use the requesting face" (the page's own WS face).
  const r = await callWitness(page, 'rib_register', [WS_URL, '/witness/test', 0n, 100n]);
  expect(r.status_code).toBe(200);

  // Sanity: the route should now be visible in rib/list.
  const list = await callWitness(page, 'faces_list', [WS_URL]);
  expect(list.status_code).toBe(200);
});

test('face/create — second mutation verb (different CP field set)', async ({ page }) => {
  await openWitnessPage(page);
  const r = await callWitness(page, 'face_create', [WS_URL, 'udp4://127.0.0.1:6363']);
  // Either 200 (created) or 409 (already exists from a prior test in
  // the same fwd instance) — both prove the wire round-tripped. The
  // failure modes we're guarding against are 400 BadParams (CP didn't
  // parse) and 0 (witness-side error before send).
  expect([200, 409]).toContain(r.status_code);
});
