# Browser WebSocket Interop Testing

ndn-rs includes a browser-based integration test suite that verifies NDN packet
exchange between [NDNts](https://yoursunny.com/p/NDNts/) running inside a real
Chromium browser and the ndn-rs forwarder over WebSocket.

## Why browser tests?

The ndn-fwd WebSocket face is the primary transport for browser-based NDN
applications.  Unit and integration tests in Rust can verify the Rust side, but
they cannot exercise the browser's native `WebSocket` API and the JavaScript NDN
stack in the same way a real browser can.  Playwright automates a headless
Chromium instance, giving confidence that:

- NDNts `WsTransport` successfully connects to ndn-fwd's WS face.
- Interest forwarding works across two independent browser WS connections.
- PIT aggregation deduplicates concurrent browser Interests correctly.

## Test topology

```text
browser page A (NDNts producer)
    │  WebSocket (ws://localhost:9797)
    ▼
ndn-fwd  ← started as a subprocess by the test
    │  WebSocket (ws://localhost:9797)
    ▼
browser page B (NDNts consumer)
```

Both pages connect to the same ndn-fwd instance on different WebSocket
connections.  Page A registers a prefix via the NFD management protocol
(`rib/register`) and produces Data.  Page B fetches the Data by name.
ndn-fwd routes the Interest from B → A and the Data back from A → B.

## Running locally

Prerequisites: Rust toolchain, Node.js ≥ 20, a release build of ndn-fwd.

```bash
# Build ndn-fwd
cargo build --release --bin ndn-fwd

# Install Node deps and build the NDNts browser bundle
cd testbed/tests/browser
npm install
node build.mjs

# Install Playwright's Chromium browser
npx playwright install chromium

# Run the tests (ndn-fwd is started automatically)
npm test

# Watch test output in a real browser window
npm run test:headed
```

## NDNts bundle

`build.mjs` uses esbuild to bundle the following NDNts packages into
`fixture-page/ndnts.bundle.js` as a browser IIFE (`window.NDNts`):

| Package | Purpose |
|---------|---------|
| `@ndn/ws-transport` | WebSocket transport (`WsTransport.createFace`) |
| `@ndn/endpoint` | Consumer (`consume`) and Producer (`produce`) |
| `@ndn/packet` | `Interest`, `Data`, `Name` types |
| `@ndn/fw` | NDNts in-browser mini-forwarder (pulled in transitively) |

The bundle is gitignored and must be rebuilt after `npm install`.

## Test scenarios

| Test | What is verified |
|------|-----------------|
| `browser producer → ndn-fwd WS → browser consumer` | End-to-end Interest-Data exchange through two WS faces |
| `PIT aggregation: two consumers fetch the same name` | ndn-fwd coalesces concurrent Interests; one upstream request satisfies both |
| `sequential multi-fetch: 5 distinct names` | WS face handles multiple request-reply cycles reliably |

## CI

The workflow `.github/workflows/browser.yml` runs on:

- Push / PR touching the WebSocket face, ndn-fwd, or browser test code.
- Weekly cron (Monday 04:00 UTC) to catch NDNts upstream changes.
- Manual dispatch.

It builds `ndn-fwd --release`, installs Playwright, bundles NDNts, and runs
the Playwright tests.  The Playwright HTML report is uploaded as a CI artifact
on failure.

## Extending the tests

Add new scenarios to `ws-transport.spec.ts`.  Common patterns:

```typescript
// Open a fresh browser context per role to avoid shared JS state.
const ctx = await browser.newContext();
const page = await ctx.newPage();
await openPage(page);          // loads fixture page, waits for NDNts bundle

// Start a producer (sends rib/register, waits 600 ms for propagation).
await startProducer(page, '/my/prefix', 'my-content');

// Consume from another page.
const content = await fetchData(consumerPage, '/my/prefix');
expect(content).toBe('my-content');

await ctx.close();
```

To test TLS WebSocket (`wss://`), configure ndn-fwd with a
`[[face]] kind = "web-socket"` and a `tls` sub-table, and change `WS_URL` in
the spec to a `wss://` URL with `{ rejectUnauthorized: false }` in the
Playwright launch options.
