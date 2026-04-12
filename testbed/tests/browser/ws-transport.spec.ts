/**
 * Browser WebSocket interop tests: NDNts (in real browser) ↔ ndn-rs forwarder.
 *
 * Each test opens two browser pages that each establish an independent
 * WebSocket connection to a locally-started ndn-fwd instance.  One page acts
 * as NDNts producer, the other as NDNts consumer.  ndn-fwd routes Interest and
 * Data between the two WS faces — no external NDN tools are required.
 *
 * Topology:
 *
 *   browser page A (producer)
 *       │  WebSocket
 *       ▼
 *   ndn-fwd (Rust, WS on :9797)
 *       │  WebSocket
 *       ▼
 *   browser page B (consumer)
 *
 * Prerequisites (handled by CI workflow):
 *   - NDNts bundle built: `node build.mjs`
 *   - ndn-fwd binary path in NDN_FWD_BIN env var (defaults to ../../target/release/ndn-fwd)
 */

import { test, expect, type Browser, type Page } from '@playwright/test';
import { spawn, type ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

// ── Binary locations ──────────────────────────────────────────────────────────

// __dirname is available because Playwright compiles .ts files to CommonJS.
const REPO_ROOT = path.resolve(__dirname, '../../..');
const NDN_FWD_BIN = process.env.NDN_FWD_BIN
  ?? path.join(REPO_ROOT, 'target', 'release', 'ndn-fwd');

// Ports chosen to avoid clashing with any standard NDN port (6363/6364/9696).
const WS_PORT = 9797;

// ── ndn-fwd config ────────────────────────────────────────────────────────────

// WebSocket-only forwarder: no UDP/TCP faces needed since both sides are browsers.
// Note: omit [engine] entirely — cs_capacity_mb has no #[serde(default)] so the
// section would require it; without the section ndn-fwd uses built-in defaults.
const FWD_CONFIG = `
[security]
profile = "disabled"

[[face]]
kind = "web-socket"
bind = "0.0.0.0:${WS_PORT}"

[logging]
level = "warn"
`;

// ── Process lifecycle ─────────────────────────────────────────────────────────

let fwdProc: ChildProcess | null = null;
const fwdConfigPath = path.join(os.tmpdir(), 'ndn-fwd-browser-test.toml');

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
  fwdProc.on('exit', (code, signal) => {
    if (code !== null && code !== 0) {
      console.error(`[ndn-fwd] exited with code ${code} signal ${signal}`);
    }
  });

  // Give the forwarder time to bind the WebSocket listen port.
  await new Promise<void>(r => setTimeout(r, 800));
});

test.afterAll(async () => {
  fwdProc?.kill('SIGTERM');
  fwdProc = null;
  fs.rmSync(fwdConfigPath, { force: true });
});

// ── Helpers ───────────────────────────────────────────────────────────────────

const WS_URL = `ws://127.0.0.1:${WS_PORT}`;

/** Navigate to the fixture page and wait for the NDNts bundle to load. */
async function openPage(page: Page): Promise<void> {
  await page.goto('/');
  await page.waitForFunction(
    () => typeof (window as any).NDNts !== 'undefined',
    { timeout: 8000 },
  );
}

/**
 * Start an NDNts producer in the given browser page.
 * The producer registers `prefix` with ndn-fwd and replies with `payload`.
 * Returns when the RIB registration has had time to propagate.
 */
async function startProducer(page: Page, prefix: string, payload: string): Promise<void> {
  await page.evaluate(
    async ({ wsUrl, prefix, payload }: { wsUrl: string; prefix: string; payload: string }) => {
      const { WsTransport, produce, Data, Name, ribRegister } = (window as any).NDNts;

      // Connect to ndn-fwd.
      await WsTransport.createFace({}, wsUrl);

      // NDNts WsTransport sets advertiseFrom:false, so produce() never sends
      // rib/register automatically.  Send it manually before registering the handler.
      await ribRegister(prefix);

      produce(new Name(prefix), async (interest: any) => {
        const data = new Data(interest.name);
        data.content = new TextEncoder().encode(payload);
        return data;
      });
    },
    { wsUrl: WS_URL, prefix, payload },
  );

  // Allow FIB entry to propagate before the consumer fires.
  await page.waitForTimeout(200);
}

/**
 * Fetch `name` from the given browser page via NDNts WsTransport.
 * Returns the decoded Data content string.
 */
async function fetchData(page: Page, name: string): Promise<string> {
  return page.evaluate(
    async ({ wsUrl, name }: { wsUrl: string; name: string }) => {
      const { WsTransport, consume, Interest, Name } = (window as any).NDNts;

      // Consumer: add a default route so all Interests go via the WS face.
      await WsTransport.createFace({ addRoutes: ['/'] }, wsUrl);

      const interest = new Interest(new Name(name), Interest.CanBePrefix, Interest.MustBeFresh);
      interest.lifetime = 8000;
      const data = await consume(interest);
      return data.content
        ? new TextDecoder().decode(data.content as Uint8Array)
        : '';
    },
    { wsUrl: WS_URL, name },
  );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test.describe('NDNts WsTransport ↔ ndn-rs forwarder', () => {
  /**
   * Core test: a browser producer and a browser consumer talk through ndn-fwd.
   *
   *   page-A ──WS──► ndn-fwd ──WS──► page-B
   *   (producer)                     (consumer)
   *
   * Verifies that ndn-fwd correctly routes Interest and Data between two
   * independent WebSocket faces.
   */
  test('browser producer → ndn-fwd WS → browser consumer', async ({ browser }: { browser: Browser }) => {
    const ctxA = await browser.newContext();
    const ctxB = await browser.newContext();
    const pageA = await ctxA.newPage(); // producer
    const pageB = await ctxB.newPage(); // consumer

    try {
      await Promise.all([openPage(pageA), openPage(pageB)]);

      await startProducer(pageA, '/ws-interop/hello', 'hello-from-browser-producer');

      const content = await fetchData(pageB, '/ws-interop/hello');
      expect(content).toBe('hello-from-browser-producer');
    } finally {
      await ctxA.close();
      await ctxB.close();
    }
  });

  /**
   * PIT aggregation: two consumers fetch the same name simultaneously.
   * ndn-fwd should coalesce both Interests into one upstream Interest and
   * satisfy both from the single Data response.
   */
  test('PIT aggregation: two consumers fetch the same name', async ({ browser }: { browser: Browser }) => {
    const ctxP = await browser.newContext();
    const ctxC1 = await browser.newContext();
    const ctxC2 = await browser.newContext();
    const producer = await ctxP.newPage();
    const consumer1 = await ctxC1.newPage();
    const consumer2 = await ctxC2.newPage();

    try {
      await Promise.all([
        openPage(producer),
        openPage(consumer1),
        openPage(consumer2),
      ]);

      await startProducer(producer, '/ws-interop/agg', 'aggregated-payload');

      // Fire both fetches concurrently — ndn-fwd aggregates them into one PIT entry.
      const [r1, r2] = await Promise.all([
        fetchData(consumer1, '/ws-interop/agg'),
        fetchData(consumer2, '/ws-interop/agg'),
      ]);

      expect(r1).toBe('aggregated-payload');
      expect(r2).toBe('aggregated-payload');
    } finally {
      await ctxP.close();
      await ctxC1.close();
      await ctxC2.close();
    }
  });

  /**
   * Sequential pipeline: consumer fetches N distinct names in a loop.
   * Verifies that the WS face can handle multiple request-reply cycles.
   */
  test('sequential multi-fetch: 5 distinct names', async ({ browser }: { browser: Browser }) => {
    const ctxP = await browser.newContext();
    const ctxC = await browser.newContext();
    const producer = await ctxP.newPage();
    const consumer = await ctxC.newPage();

    try {
      await Promise.all([openPage(producer), openPage(consumer)]);

      // Producer serves any name under /ws-interop/seq — returns the last component.
      await producer.evaluate(
        async ({ wsUrl, prefix }: { wsUrl: string; prefix: string }) => {
          const { WsTransport, produce, Data, Name, ribRegister } = (window as any).NDNts;
          await WsTransport.createFace({}, wsUrl);
          await ribRegister(prefix);
          produce(new Name(prefix), async (interest: any) => {
            const name: any = interest.name;
            const last = name.at(-1)?.text ?? 'unknown';
            const data = new Data(interest.name);
            data.content = new TextEncoder().encode(`item-${last}`);
            return data;
          });
        },
        { wsUrl: WS_URL, prefix: '/ws-interop/seq' },
      );
      await producer.waitForTimeout(200);

      const results = await consumer.evaluate(
        async ({ wsUrl, prefix, n }: { wsUrl: string; prefix: string; n: number }) => {
          const { WsTransport, consume, Interest, Name } = (window as any).NDNts;
          await WsTransport.createFace({ addRoutes: ['/'] }, wsUrl);
          const out: string[] = [];
          for (let i = 0; i < n; i++) {
            const interest = new Interest(new Name(`${prefix}/${i}`));
            interest.lifetime = 8000;
            const data = await consume(interest);
            out.push(data.content ? new TextDecoder().decode(data.content as Uint8Array) : '');
          }
          return out;
        },
        { wsUrl: WS_URL, prefix: '/ws-interop/seq', n: 5 },
      );

      expect(results).toEqual(['item-0', 'item-1', 'item-2', 'item-3', 'item-4']);
    } finally {
      await ctxP.close();
      await ctxC.close();
    }
  });
});
