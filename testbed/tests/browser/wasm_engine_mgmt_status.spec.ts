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

test('wasm engine answers /localhost/nfd/status/general with a 200 ControlResponse', async ({
  browser,
}) => {
  const ctx = await browser.newContext();
  const tab = await ctx.newPage();
  tab.on('console', (m) => console.log('[tab]', m.type(), m.text()));

  await tab.goto(TAB_URL);
  await tab.waitForFunction(() => (window as any).__sharedReady === true, null, {
    timeout: 15_000,
  });

  // Express the management Interest and pull back the Data content bytes.
  // SharedClient.express_interest resolves to the Data's `content` field —
  // for an NFD ControlResponse this is the encoded TLV (type 0x65).
  const content: number[] = await tab.evaluate(async () => {
    const arr: Uint8Array = await (window as any).__sharedClient.express_interest(
      '/localhost/nfd/status/general',
      3000,
    );
    return Array.from(arr);
  });
  const bytes = new Uint8Array(content);

  expect(bytes.length, 'ControlResponse content must be non-empty').toBeGreaterThan(0);

  // Outer envelope is type 0x65 (ControlResponse).
  const { tlv: outer } = decodeTlv(bytes, 0);
  expect(outer.type, 'top-level type must be ControlResponse (0x65)').toBe(CR_TYPE);

  // Pull StatusCode + StatusText out of the children.
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

  await ctx.close();
});
