# Dashboard Next Deployment

`ndn-dashboard-next` is built as a static browser app and as a desktop app from
the same crate.

Browser build:

```sh
dx build --package ndn-dashboard-next --platform web --features web --no-default-features --release
```

Serve the generated web output from HTTPS for WebTransport, clipboard,
notifications, service-worker caching, and future custodian handoffs. Browser
attach transports must be NDN-compatible or explicitly documented browser-safe
bridges; a dashboard-only HTTP proxy is not the primary architecture.

Desktop build:

```sh
cargo build -p ndn-dashboard-next
```

Desktop local attach can use Unix management sockets and can stage generated
router config TOML. Browser config editing remains read-only until a safe write
transport exists.

PWA assets live in `crates/tooling/ndn-dashboard-next/public/`: manifest,
service worker, and a maskable SVG icon. The service worker caches only shell
assets and falls back to network for live NDN data.
