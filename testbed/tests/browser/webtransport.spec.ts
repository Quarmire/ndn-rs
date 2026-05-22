/**
 * Browser WebTransport interop witness: NDNts `H3Transport` (in a real browser)
 * ↔ ndn-rs forwarder, over QUIC/HTTP3.
 *
 * Mirrors `ws-transport.spec.ts`: two browser pages each open an independent
 * WebTransport session to a locally-started `ndn-fwd`; one is an NDNts producer,
 * the other an NDNts consumer; ndn-fwd routes Interest/Data between the two WT
 * faces. Validates the datagram + NDNLPv2-fragmentation framing on both ends
 * (ndn-rs `ndn-face-webtransport` ↔ NDNts `H3Transport` + `LpService`).
 *
 *   browser page A (producer) ──WebTransport──▶ ndn-fwd (Rust, WT on :4443)
 *   browser page B (consumer) ──WebTransport──▶ ndn-fwd ─────────────────────┘
 *
 * Skips when infra is absent, matching the other browser specs' contract:
 *   1. `ndn-fwd` built with `--features webtransport` (NDN_FWD_BIN, default
 *      `target/release/ndn-fwd`). This spec spawns it.
 *   2. The NDNts browser bundle exposes `window.NDNts.H3Transport` — wired via
 *      `@ndn/quic-transport` in `src/ndnts-browser.ts` (run `node build.mjs`
 *      after a fresh `npm install`).
 *   3. Chrome reaches the self-signed listener via `serverCertificateHashes`,
 *      parsed from the forwarder's logged `cert_sha256` line.
 */

import { test, expect, type Browser, type Page } from '@playwright/test';
import { spawn, type ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const REPO_ROOT = path.resolve(__dirname, '../../..');
const NDN_FWD_BIN = process.env.NDN_FWD_BIN
  ?? path.join(REPO_ROOT, 'target', 'release', 'ndn-fwd');

const WT_PORT = 4443;
const WT_URL = `https://127.0.0.1:${WT_PORT}/ndn`;

// Self-signed dev cert: the browser pins it by SHA-256 via
// `serverCertificateHashes`; the forwarder logs the hash at startup.
const FWD_CONFIG = `
[security]
profile = "disabled"

[security.mgmt]
require_signed_commands = false

[listeners.webtransport]
enabled = true
listen = "127.0.0.1:${WT_PORT}"
cert_source = { type = "self_signed_dev", hostnames = ["localhost"] }

[logging]
level = "info"
`;

let fwdProc: ChildProcess | null = null;
let certHashHex = '';
const fwdConfigPath = path.join(os.tmpdir(), 'ndn-fwd-wt-browser-test.toml');

/** Wait for the forwarder to log its leaf cert SHA-256 (hex). */
function waitForCertHash(proc: ChildProcess): Promise<string> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('cert_sha256 not logged')), 5000);
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

/** Bundle exposes H3Transport only when built with @ndn/quic-transport. */
async function h3Available(page: Page): Promise<boolean> {
  await page.goto('/');
  await page.waitForFunction(() => typeof (window as any).NDNts !== 'undefined', { timeout: 8000 });
  return page.evaluate(() => typeof (window as any).NDNts?.H3Transport !== 'undefined');
}

/** Convert a 64-char hex string to the number[][] shape Playwright can pass in. */
function hashBytes(hex: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hex.length; i += 2) out.push(parseInt(hex.slice(i, i + 2), 16));
  return out;
}

test('NDNts H3Transport ↔ ndn-rs forwarder: producer → ndn-fwd → consumer', async ({ browser }: { browser: Browser }) => {
  test.skip(!fs.existsSync(NDN_FWD_BIN), `ndn-fwd binary not found at ${NDN_FWD_BIN} (build with --features webtransport)`);
  test.skip(!certHashHex, 'forwarder did not log a cert hash (is the webtransport feature compiled in?)');

  const ctxA = await browser.newContext();
  const probe = await ctxA.newPage();
  const haveH3 = await h3Available(probe);
  test.skip(!haveH3, 'NDNts bundle lacks H3Transport — run `node build.mjs` after `npm install` (see file header)');

  const ctxB = await browser.newContext();
  const producer = await ctxA.newPage();
  const consumer = await ctxB.newPage();
  const hashes = hashBytes(certHashHex);

  try {
    await Promise.all([
      producer.goto('/').then(() => producer.waitForFunction(() => (window as any).NDNts)),
      consumer.goto('/').then(() => consumer.waitForFunction(() => (window as any).NDNts)),
    ]);

    await producer.evaluate(async ({ url, prefix, payload, hashes }) => {
      const { H3Transport, produce, Data, Name, ribRegister } = (window as any).NDNts;
      await H3Transport.createFace({}, url, {
        serverCertificateHashes: [{ algorithm: 'sha-256', value: new Uint8Array(hashes) }],
      });
      await ribRegister(prefix);
      produce(new Name(prefix), async (interest: any) => {
        const data = new Data(interest.name);
        data.content = new TextEncoder().encode(payload);
        return data;
      });
    }, { url: WT_URL, prefix: '/wt-interop/hello', payload: 'hello-from-wt-producer', hashes });

    await producer.waitForTimeout(200);

    const content = await consumer.evaluate(async ({ url, name, hashes }) => {
      const { H3Transport, consume, Interest, Name } = (window as any).NDNts;
      await H3Transport.createFace({ addRoutes: ['/'] }, url, {
        serverCertificateHashes: [{ algorithm: 'sha-256', value: new Uint8Array(hashes) }],
      });
      const interest = new Interest(new Name(name), Interest.CanBePrefix, Interest.MustBeFresh);
      interest.lifetime = 8000;
      const data = await consume(interest);
      return data.content ? new TextDecoder().decode(data.content as Uint8Array) : '';
    }, { url: WT_URL, name: '/wt-interop/hello', hashes });

    expect(content).toBe('hello-from-wt-producer');
  } finally {
    await ctxA.close();
    await ctxB.close();
  }
});
