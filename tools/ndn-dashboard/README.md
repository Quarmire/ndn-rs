# ndn-dashboard

Dioxus desktop application for managing and monitoring an `ndn-router` instance.
Communicates with the router exclusively via the NDN management protocol (TLV
Interest/Data on `/localhost/nfd/`), using the same `ndn_ipc::MgmtClient` library
as `ndn-ctl`. UI state is driven by reactive Dioxus signals polled every 3 seconds.
Ships with a system-tray icon for background presence and start/stop controls.

## Views

| View | Description |
|------|-------------|
| Overview | Forwarder status, throughput sparklines, CS statistics |
| Routes | FIB management: add, remove, and inspect forwarding entries |
| Strategy | Per-prefix strategy assignment |
| Routing | DVR protocol status and runtime configuration |
| Fleet | Discovered neighbors, NDNCERT enrollment, discovery config |
| Security | Trust anchor and certificate management |
| Config | All router knobs by category with import/export |
| Tools | Embedded ping, iperf, peek, and put tools via `ndn-tools-core` |
| Logs | Live structured log stream from the router |

## Running

```sh
cargo build -p ndn-dashboard
./target/debug/ndn-dashboard
```

The router must already be running; the dashboard will indicate disconnected state
and retry automatically. Log level is controlled via `RUST_LOG`.
