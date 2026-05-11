/**
 * Native ↔ browser interop witness.
 *
 * Pins the parity claim from a third direction: a browser-tier
 * WebSocket client speaks the same NFD-mgmt wire protocol to a
 * native `ndn-fwd` that the in-page engine answers (witnessed by
 * `wasm_engine_mgmt_status.spec.ts`) and that `ndn-ctl` speaks over
 * a Unix socket (witnessed by `testbed/tests/audit/mgmt_native_parity.sh`).
 *
 * Three transports, one dispatcher, one wire shape.
 *
 *   browser tab (this test)
 *       │  binary WebSocket
 *       ▼
 *   ndn-fwd  (spawned subprocess, dev-mode config)
 *       │  in-proc face installed by mount_management
 *       ▼
 *   ndn-mgmt dispatcher
 *
 * Witness contract:
 *   1. Spawn ndn-fwd with `[[face]] kind = "websocket" bind = …`.
 *   2. Open a WebSocket from the browser tab.
 *   3. Send a TLV Interest for `/localhost/nfd/status/general`.
 *   4. Decode the Data; assert StatusCode == 200 + faces= counter
 *      pattern (same shape the wasm witness asserts).
 *
 * The witness skips (exit-0 in CI) when cargo / the target binary is
 * not available; locally `cargo build -p ndn-fwd` makes it green.
 */

import { test, expect } from '@playwright/test';
import { spawn, ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const NDN_FWD = path.join(REPO_ROOT, 'target', 'debug', 'ndn-fwd');
const WS_PORT = 19696;
const WS_URL = `ws://127.0.0.1:${WS_PORT}`;

let fwdProc: ChildProcess | null = null;
let workDir: string | null = null;

async function waitForListening(port: number, timeoutMs: number): Promise<boolean> {
  const start = Date.now();
  const net = await import('net');
  while (Date.now() - start < timeoutMs) {
    const ok = await new Promise<boolean>((resolve) => {
      const sock = net.connect({ host: '127.0.0.1', port }, () => {
        sock.end();
        resolve(true);
      });
      sock.on('error', () => resolve(false));
    });
    if (ok) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return false;
}

test.describe('native ↔ browser NFD-mgmt parity over WebSocket', () => {
  test.beforeAll(async () => {
    if (!fs.existsSync(NDN_FWD)) {
      test.skip(true, `ndn-fwd binary not built (run \`cargo build -p ndn-fwd\`)`);
    }

    workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ndn-fwd-interop-'));
    const sockPath = path.join(workDir, 'ndn-fwd.sock');
    const configPath = path.join(workDir, 'ndn-fwd.toml');
    fs.writeFileSync(
      configPath,
      `
[engine]
pipeline_threads = 1
cs_capacity_mb   = 4

[security]
profile = "disabled"

[security.mgmt]
require_signed_commands = false

[[face]]
kind = "web-socket"
bind = "127.0.0.1:${WS_PORT}"

[management]
face_socket = "${sockPath}"

[logging]
level = "warn"
`,
    );

    fwdProc = spawn(NDN_FWD, ['-c', configPath], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, RUST_LOG: 'warn' },
    });
    fwdProc.stdout?.on('data', (d) => process.stdout.write(`[fwd] ${d}`));
    fwdProc.stderr?.on('data', (d) => process.stderr.write(`[fwd] ${d}`));

    const ready = await waitForListening(WS_PORT, 5000);
    if (!ready) {
      throw new Error(`ndn-fwd did not start listening on ${WS_PORT}`);
    }
  });

  test.afterAll(async () => {
    if (fwdProc) {
      fwdProc.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 200));
      if (!fwdProc.killed) fwdProc.kill('SIGKILL');
    }
    if (workDir) fs.rmSync(workDir, { recursive: true, force: true });
  });

  test('browser WebSocket → ndn-fwd answers status/general with 200 ControlResponse', async ({
    page,
  }) => {
    await page.goto('/index.html');

    // Drive everything inside the page so the browser is the actual
    // WebSocket client.  Returns the Data wire as a number[] for
    // post-test decoding by the Node-side assertions.
    const wire: number[] = await page.evaluate(async (wsUrl) => {
      // ── Minimal TLV encoder for `/localhost/nfd/status/general` ─────
      function putVaru(buf: number[], v: number) {
        if (v < 253) {
          buf.push(v);
        } else if (v <= 0xffff) {
          buf.push(253, (v >> 8) & 0xff, v & 0xff);
        } else {
          buf.push(254, (v >>> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff);
        }
      }
      function encInterest(parts: string[]): Uint8Array {
        const nameBytes: number[] = [];
        for (const c of parts) {
          const b = new TextEncoder().encode(c);
          nameBytes.push(0x08);
          putVaru(nameBytes, b.length);
          for (const x of b) nameBytes.push(x);
        }
        const name: number[] = [];
        name.push(0x07);
        putVaru(name, nameBytes.length);
        for (const x of nameBytes) name.push(x);

        // CanBePrefix + MustBeFresh.
        const selectors = [0x21, 0x00, 0x12, 0x00];
        // Nonce (4 bytes random).
        const nonceBytes = new Uint8Array(4);
        crypto.getRandomValues(nonceBytes);
        const nonce = [0x0a, 0x04, ...nonceBytes];
        // InterestLifetime = 4000 ms.
        const lifetime = [0x0c, 0x02, 0x0f, 0xa0];

        const body = [...name, ...selectors, ...nonce, ...lifetime];
        const out: number[] = [];
        out.push(0x05);
        putVaru(out, body.length);
        for (const x of body) out.push(x);
        return new Uint8Array(out);
      }

      const interestWire = encInterest(['localhost', 'nfd', 'status', 'general']);

      return await new Promise<number[]>((resolve, reject) => {
        const ws = new WebSocket(wsUrl);
        ws.binaryType = 'arraybuffer';
        const timer = setTimeout(() => {
          ws.close();
          reject(new Error('timeout waiting for Data'));
        }, 5000);
        ws.onopen = () => ws.send(interestWire);
        ws.onmessage = (ev) => {
          clearTimeout(timer);
          ws.close();
          const data = ev.data as ArrayBuffer;
          resolve(Array.from(new Uint8Array(data)));
        };
        ws.onerror = (e) => {
          clearTimeout(timer);
          reject(new Error('WebSocket error'));
        };
      });
    }, WS_URL);

    expect(wire.length, 'Data wire must be non-empty').toBeGreaterThan(0);

    // ── Decode Data → Content → ControlResponse → status fields ──────
    const bytes = new Uint8Array(wire);
    function readVaru(b: Uint8Array, off: number): { v: number; next: number } {
      const b0 = b[off];
      if (b0 < 253) return { v: b0, next: off + 1 };
      if (b0 === 253) return { v: (b[off + 1] << 8) | b[off + 2], next: off + 3 };
      return {
        v: (b[off + 1] * 0x1000000 +
          ((b[off + 2] << 16) | (b[off + 3] << 8) | b[off + 4])) >>> 0,
        next: off + 5,
      };
    }
    function readTlv(b: Uint8Array, off: number) {
      const t = readVaru(b, off);
      const l = readVaru(b, t.next);
      return { type: t.v, valOff: l.next, end: l.next + l.v };
    }

    // The WebSocket face wraps Data in NDNLPv2 LpPacket (type 0x64) with
    // the fragment (type 0x50) holding the bare Data wire. Unwrap.
    let dataWire = bytes;
    if (bytes[0] === 0x64) {
      const lp = readTlv(bytes, 0);
      let lpOff = lp.valOff;
      while (lpOff < lp.end) {
        const t = readTlv(bytes, lpOff);
        if (t.type === 0x50) {
          dataWire = bytes.subarray(t.valOff, t.end);
          break;
        }
        lpOff = t.end;
      }
    }

    // Outer Data (0x06).
    const data = readTlv(dataWire, 0);
    expect(data.type, 'top-level type must be Data (0x06)').toBe(0x06);
    let content: Uint8Array | null = null;
    let sigInfo: Uint8Array | null = null;
    let off = data.valOff;
    while (off < data.end) {
      const t = readTlv(dataWire, off);
      if (t.type === 0x15) {
        content = dataWire.subarray(t.valOff, t.end);
      } else if (t.type === 0x16) {
        // SignatureInfo (NDN packet format § Data).
        sigInfo = dataWire.subarray(t.valOff, t.end);
      }
      off = t.end;
    }
    expect(content, 'Data must carry Content').not.toBeNull();

    // ── N.12 — mgmt response must carry a real SignatureInfo with a
    // non-DigestSha256 SignatureType.  ndn-fwd's load_security ran
    // SecurityManager::auto_init, generating an Ed25519 identity;
    // mount_management pulled that signer through MgmtHandles and
    // ndn_mgmt::build_mgmt_response_wire called DataBuilder::sign_sync.
    expect(sigInfo, 'Data must carry SignatureInfo').not.toBeNull();
    let sigType: number | null = null;
    let keyLocatorPresent = false;
    let soff = 0;
    while (soff < sigInfo!.length) {
      const t = readTlv(sigInfo!, soff);
      if (t.type === 0x1b) {
        // SignatureType (NNI).
        let v = 0;
        for (const b of sigInfo!.subarray(t.valOff, t.end)) v = v * 256 + b;
        sigType = v;
      } else if (t.type === 0x1c) {
        // KeyLocator.
        keyLocatorPresent = true;
      }
      soff = t.end;
    }
    expect(sigType, 'SignatureInfo must carry SignatureType').not.toBeNull();
    // 0 = DigestSha256 (the legacy fallback we're moving off of).
    // 1 = SignatureSha256WithRsa, 3 = SignatureSha256WithEcdsa,
    // 5 = SignatureEd25519, 6 = SignatureBlake3, 7 = SignatureSha256WithBlake3.
    expect(sigType, 'mgmt response must NOT use DigestSha256 (audit N.12)').not.toBe(0);
    expect(keyLocatorPresent, 'real signature must carry KeyLocator').toBe(true);
    console.log(
      `[witness] response signed with SignatureType=${sigType} (1=RSA / 3=ECDSA / 5=Ed25519)`,
    );

    // ControlResponse (0x65).
    const cr = readTlv(content!, 0);
    expect(cr.type, 'Content[0] must be ControlResponse (0x65)').toBe(0x65);
    let statusCode = 0;
    let statusText = '';
    let coff = cr.valOff;
    while (coff < cr.end) {
      const t = readTlv(content!, coff);
      const val = content!.subarray(t.valOff, t.end);
      if (t.type === 0x66) {
        let v = 0;
        for (const b of val) v = v * 256 + b;
        statusCode = v;
      } else if (t.type === 0x67) {
        statusText = new TextDecoder().decode(val);
      }
      coff = t.end;
    }

    console.log(
      `[witness] native ndn-fwd via browser WebSocket: status=${statusCode} text=${statusText}`,
    );
    expect(statusCode, 'ndn-fwd status/general must return 200').toBe(200);
    expect(statusText, 'StatusText must report faces= counter').toMatch(/^faces=\d+ /);
    expect(statusText, 'StatusText must include fib= counter').toMatch(/fib=\d+/);
    expect(statusText, 'StatusText must include pit= counter').toMatch(/pit=\d+/);
    expect(statusText, 'StatusText must include cs= counter').toMatch(/cs=\d+/);
  });
});
