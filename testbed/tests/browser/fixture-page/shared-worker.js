// Phase 6 SharedWorker bootstrap.
//
// Three-step pattern to avoid the W3C SharedWorker connect-event race:
// the very first tab's `connect` fires after this script's first task
// completes — i.e. before any `await` inside `worker_main` has had a
// chance to install the Rust-side onconnect. We:
//
//   1. Install a synchronous onconnect that buffers ports.
//   2. Load wasm + call worker_main (which stashes the listener).
//   3. Drain the buffer via `accept_port_from_js` and replace
//      onconnect with a forwarder that calls the same function for
//      every subsequent connect event.

// Bridge worker console to tab side via BroadcastChannel so Playwright
// (which only captures tab console, not SharedWorker) can see worker
// diagnostics. Tab fixture subscribes to the same channel.
const __logBC = new BroadcastChannel('worker-log');
const __origLog = console.log.bind(console);
console.log = (...args) => {
  __origLog(...args);
  try { __logBC.postMessage({ level: 'log', text: args.map(String).join(' ') }); } catch {}
};
const __origErr = console.error.bind(console);
console.error = (...args) => {
  __origErr(...args);
  try { __logBC.postMessage({ level: 'error', text: args.map(String).join(' ') }); } catch {}
};

// Buffer ports synchronously without calling port.start() — start()
// before the Rust-side onmessage handler is installed would dispatch
// any already-queued tab→worker messages with no listener and the
// HTML spec drops them. The per-port pump's set_onmessage implicitly
// starts the port at the moment the listener is attached.
const __pendingPorts = [];
self.onconnect = (e) => {
  const port = e.ports[0];
  if (port) {
    __pendingPorts.push(port);
  }
};

importScripts('/sw-pkg/shared_engine.js');

// `self.name` is the second argument the tab passed to
// `new SharedWorker(url, name)` — we encode upstream + producers
// into it as URL-encoded query params so the bootstrap can read
// both without a separate config channel.
const params = self.name ? new URLSearchParams(self.name) : new URLSearchParams();
const UPSTREAM = params.get('upstream') ?? '';
const PRODUCERS = params.get('producers') ?? '/cache-test';

(async () => {
  await wasm_bindgen('/sw-pkg/shared_engine_bg.wasm');
  console.log('[bootstrap] wasm initialised; calling worker_main');
  await wasm_bindgen.worker_main(UPSTREAM, PRODUCERS);
  console.log('[bootstrap] worker_main returned; draining', __pendingPorts.length, 'pending port(s)');

  // Drain pre-buffer.
  for (const port of __pendingPorts) {
    wasm_bindgen.accept_port_from_js(port);
  }
  __pendingPorts.length = 0;

  // Replace onconnect with a forwarder for live connects.
  self.onconnect = (e) => {
    const port = e.ports[0];
    if (port) {
      wasm_bindgen.accept_port_from_js(port);
    }
  };
  console.log('[bootstrap] live forwarder installed');
})().catch((err) => {
  console.error('[bootstrap] fatal:', err);
});
