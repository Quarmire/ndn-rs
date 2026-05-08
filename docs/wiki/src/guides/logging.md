# Logging and Observability

ndn-rs uses the [`tracing`](https://docs.rs/tracing) crate for structured, target-routed logging. Every event carries a `target:` string drawn from a 26-entry taxonomy, which lets operators select exactly the subsystems they care about without wading through unrelated output.

## Quick start

```bash
# Show only pipeline and PIT events at trace level.
RUST_LOG=fwd.pipeline=trace,fwd.pit=debug ndn-fwd -c router.toml

# Show all face-system events at debug, everything else at info.
RUST_LOG=info,face.system=debug ndn-fwd -c router.toml
```

The `RUST_LOG` syntax is the standard [`EnvFilter`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html) directive format: `target=level[,target=level,...]`.

## Log-target taxonomy

Print the full taxonomy at any time:

```
$ ndn-fwd --modules
fwd.pipeline
fwd.pit
fwd.cs
fwd.fib
fwd.strategy
face.tcp
face.udp
face.ws
face.lp
face.eth
face.system
mgmt.rib
mgmt.face
mgmt.fib
mgmt.cs
mgmt.strategy
mgmt.log
mgmt.security
mgmt.status
routing.dvr
routing.nlsr
sync.svs
sync.psync
security
engine
discovery
```

The same list is available at runtime via the management API:

```
$ ndn-tools interest /localhost/nfd/log/modules
```

### Target reference

| Target | Subsystem |
|---|---|
| `fwd.pipeline` | Per-packet pipeline stages (decode → CS → PIT → strategy) |
| `fwd.pit` | PIT insert / expire / satisfy events |
| `fwd.cs` | Content Store hit / miss / eviction |
| `fwd.fib` | FIB nexthop lookup, add, remove |
| `fwd.strategy` | Strategy decisions (best-route, multicast, …) |
| `face.tcp` | TCP unicast face send / receive |
| `face.udp` | UDP unicast and multicast face send / receive |
| `face.ws` | WebSocket face send / receive |
| `face.lp` | NDNLPv2 framing, fragmentation, reassembly |
| `face.eth` | Raw Ethernet face send / receive |
| `face.system` | Face lifecycle (bind, connect, BLE, serial, hotplug) |
| `mgmt.rib` | RIB register / unregister commands |
| `mgmt.face` | Face create / destroy commands |
| `mgmt.fib` | FIB add-nexthop / remove-nexthop commands |
| `mgmt.cs` | CS config / erase commands |
| `mgmt.strategy` | Strategy-choice set / unset commands |
| `mgmt.log` | Log set-filter / get-filter commands |
| `mgmt.security` | Security identity, key, schema, CA commands |
| `mgmt.status` | Status dataset and shutdown commands |
| `routing.dvr` | Distance-vector routing protocol events |
| `routing.nlsr` | NLSR link-state routing protocol events |
| `sync.svs` | StateVectorSync events |
| `sync.psync` | PSync events |
| `security` | Signature verification and trust-anchor events |
| `engine` | Engine lifecycle, config loading, fatal errors |
| `discovery` | Neighbor discovery and service discovery events |

## Changing the filter at runtime

The filter can be reloaded without restarting the forwarder:

```bash
ndn-tools command /localhost/nfd/log/set-filter \
  Uri fwd.pipeline=trace,mgmt.face=debug
```

Read the current filter:

```bash
ndn-tools interest /localhost/nfd/log/get-filter
```

## Structured fields

Events include machine-readable fields alongside the human message, making them easy to parse with tools like [`jq`](https://stedolan.github.io/jq/) when the formatter is set to JSON:

```bash
RUST_LOG=fwd.pipeline=trace RUST_LOG_FORMAT=json ndn-fwd -c router.toml \
  | jq 'select(.target == "fwd.pipeline")'
```

Typical pipeline event fields: `name` (NDN Name), `face` (FaceId), `nonce`, `len` (bytes).

## Log file

Configure a persistent log file in `router.toml`:

```toml
[logging]
level = "info"
file  = "/var/log/ndn-fwd/ndn-fwd.log"
```

File writes are non-blocking — log events never stall the forwarding pipeline.
