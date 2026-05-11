/**
 * Witness — NFD-compatible management against the in-browser
 * `ForwarderEngine`.
 *
 * Topology:
 *
 *   browser tab (SharedClient driver, Playwright)
 *       │  SharedWorkerProxyFace → MessagePort
 *       ▼
 *   per-origin SharedWorker (`shared-worker.js`)
 *       │  worker_main → Engine::new
 *       ▼
 *   wasm `ForwarderEngine`
 *       └─ mount_management(): InProcFace + `/localhost/nfd` FIB entry
 *          ndn_mgmt::run_ndn_mgmt_handler dispatches /localhost/nfd/...
 *
 * Witness contract:
 *   1. Open a tab; wait for `__sharedReady`.
 *   2. Express Interest `/localhost/nfd/status/general`.
 *   3. Decode the returned Data content as an NFD ControlResponse TLV.
 *   4. Assert StatusCode == 200 and StatusText starts with "faces=".
 *
 * Failure modes the witness catches:
 *   - mgmt face not wired (no FIB route → NoRoute / timeout)
 *   - dispatcher not running (Interest hits face but no response)
 *   - dispatcher returns wrong shape (decoder fails) or non-200
 *
 * Pinned to Chromium per `playwright.config.ts` projects.
 */

import { test, expect } from '@playwright/test';

const TAB_URL = '/shared-worker-tab.html';

// ─── Minimal NDN TLV decoder (just what this witness needs) ──────────────────

interface Tlv {
  type: number;
  value: Uint8Array;
}

function readVarInt(buf: Uint8Array, off: number): { value: number; next: number } {
  const b0 = buf[off];
  if (b0 < 0xfd) return { value: b0, next: off + 1 };
  if (b0 === 0xfd) {
    const v = (buf[off + 1] << 8) | buf[off + 2];
    return { value: v, next: off + 3 };
  }
  if (b0 === 0xfe) {
    const v =
      buf[off + 1] * 0x1000000 +
      ((buf[off + 2] << 16) | (buf[off + 3] << 8) | buf[off + 4]);
    return { value: v >>> 0, next: off + 5 };
  }
  throw new Error('64-bit varint unsupported in witness');
}

function decodeTlv(buf: Uint8Array, off = 0): { tlv: Tlv; next: number } {
  const { value: type, next: lenOff } = readVarInt(buf, off);
  const { value: len, next: valOff } = readVarInt(buf, lenOff);
  return { tlv: { type, value: buf.subarray(valOff, valOff + len) }, next: valOff + len };
}

function readChildren(buf: Uint8Array): Tlv[] {
  const out: Tlv[] = [];
  let off = 0;
  while (off < buf.length) {
    const { tlv, next } = decodeTlv(buf, off);
    out.push(tlv);
    off = next;
  }
  return out;
}

function readNni(buf: Uint8Array): number {
  let v = 0;
  for (const b of buf) v = v * 256 + b;
  return v;
}

// NFD ControlResponse TLV (ndn-cxx mgmt/control-response.cpp).
const CR_TYPE = 0x65;
const CR_STATUS_CODE = 0x66;
const CR_STATUS_TEXT = 0x67;

// NFD dataset entry envelopes — every status dataset entry is wrapped
// in a generic type-0x80 TLV (`FaceStatus`, `FibEntry`, `RibEntry`,
// `StrategyChoice` all share the same outer type).
const DATASET_ENTRY = 0x80;

async function expressContent(tab: any, name: string, timeoutMs = 3000): Promise<Uint8Array> {
  const content: number[] = await tab.evaluate(
    async ({ name, timeoutMs }: { name: string; timeoutMs: number }) => {
      const arr: Uint8Array = await (window as any).__sharedClient.express_interest(
        name,
        timeoutMs,
      );
      return Array.from(arr);
    },
    { name, timeoutMs },
  );
  return new Uint8Array(content);
}

test.describe('wasm engine — NFD management surface', () => {
  test.beforeEach(async ({ page }) => {
    page.on('console', (m) => console.log('[tab]', m.type(), m.text()));
    await page.goto(TAB_URL);
    await page.waitForFunction(() => (window as any).__sharedReady === true, null, {
      timeout: 15_000,
    });
  });

  test('status/general → 200 ControlResponse with faces/fib/pit/cs counters', async ({
    page,
  }) => {
    const bytes = await expressContent(page, '/localhost/nfd/status/general');
    expect(bytes.length, 'ControlResponse content must be non-empty').toBeGreaterThan(0);

    const { tlv: outer } = decodeTlv(bytes, 0);
    expect(outer.type, 'top-level type must be ControlResponse (0x65)').toBe(CR_TYPE);

    const children = readChildren(outer.value);
    const sc = children.find((c) => c.type === CR_STATUS_CODE);
    const st = children.find((c) => c.type === CR_STATUS_TEXT);
    expect(sc, 'StatusCode TLV must be present').toBeDefined();
    expect(st, 'StatusText TLV must be present').toBeDefined();

    expect(readNni(sc!.value), 'status/general must return 200 OK').toBe(200);

    const text = new TextDecoder().decode(st!.value);
    console.log('[witness] status/general text:', text);
    expect(text, 'StatusText must report faces= counter').toMatch(/^faces=\d+ /);
    expect(text, 'StatusText must include fib= counter').toMatch(/fib=\d+/);
    expect(text, 'StatusText must include pit= counter').toMatch(/pit=\d+/);
    expect(text, 'StatusText must include cs= counter').toMatch(/cs=\d+/);
  });

  test('faces/list dataset enumerates the engine\'s faces', async ({ page }) => {
    const bytes = await expressContent(page, '/localhost/nfd/faces/list');
    expect(bytes.length, 'faces/list dataset content must be non-empty').toBeGreaterThan(0);

    const entries = readChildren(bytes);
    expect(
      entries.length,
      'dataset must contain at least the mgmt face + the worker port face',
    ).toBeGreaterThanOrEqual(2);
    for (const e of entries) {
      expect(e.type, 'every faces/list entry must be FaceStatus (0x80)').toBe(DATASET_ENTRY);
    }
    console.log(`[witness] faces/list: ${entries.length} entries`);
  });

  test('fib/list dataset includes the management prefix', async ({ page }) => {
    const bytes = await expressContent(page, '/localhost/nfd/fib/list');
    expect(bytes.length, 'fib/list dataset content must be non-empty').toBeGreaterThan(0);

    const entries = readChildren(bytes);
    expect(entries.length, 'FIB must have at least /localhost/nfd + /localhop/nfd').toBeGreaterThanOrEqual(2);
    for (const e of entries) {
      expect(e.type, 'every fib/list entry must be FibEntry (0x80)').toBe(DATASET_ENTRY);
    }

    // The mgmt face must be reachable via `/localhost/nfd` somewhere
    // in the FIB — search for the ASCII literal in any entry.
    const haystack = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    expect(haystack, 'FIB must contain /localhost/nfd').toContain('localhost');
    expect(haystack, 'FIB must contain /localhop/nfd').toContain('localhop');
    console.log(`[witness] fib/list: ${entries.length} entries`);
  });

  test('rib/list dataset is well-formed (possibly empty)', async ({ page }) => {
    const bytes = await expressContent(page, '/localhost/nfd/rib/list');
    // An empty RIB still produces a valid dataset Data with empty content.
    // Either way, every entry present must be a RibEntry (0x80).
    const entries = readChildren(bytes);
    for (const e of entries) {
      expect(e.type, 'every rib/list entry must be RibEntry (0x80)').toBe(DATASET_ENTRY);
    }
    console.log(`[witness] rib/list: ${entries.length} entries`);
  });

  test('strategy-choice/list dataset enumerates installed strategies', async ({ page }) => {
    const bytes = await expressContent(page, '/localhost/nfd/strategy-choice/list');
    expect(bytes.length, 'strategy-choice/list dataset content must be non-empty').toBeGreaterThan(0);

    const entries = readChildren(bytes);
    expect(entries.length, 'strategy-choice/list must have at least the root default').toBeGreaterThanOrEqual(1);
    for (const e of entries) {
      expect(e.type, 'every strategy-choice entry must be 0x80').toBe(DATASET_ENTRY);
    }
    console.log(`[witness] strategy-choice/list: ${entries.length} entries`);
  });

  test('extended modules are auth-gated (no anchors → 403)', async ({ page }) => {
    // ndn-rs-only modules (routing/discovery/service/security/neighbors)
    // unconditionally require signed commands per audit E.03 — see
    // `is_extended_module` in ndn-mgmt. With no validator wired on the
    // demo's wasm engine the auth gate returns 403 before the wasm
    // NOT_IMPLEMENTED arm is reached. Witnessing 403 confirms the
    // fail-secure policy is intact in the browser dispatcher.
    const bytes = await expressContent(page, '/localhost/nfd/routing/list');
    const { tlv: outer } = decodeTlv(bytes, 0);
    expect(outer.type, 'auth-rejected response is still a ControlResponse').toBe(CR_TYPE);
    const children = readChildren(outer.value);
    const sc = children.find((c) => c.type === CR_STATUS_CODE);
    expect(sc, 'StatusCode TLV must be present').toBeDefined();
    expect(readNni(sc!.value), 'unsigned extended-module command must be 403 UNAUTHORIZED').toBe(403);
  });
});
