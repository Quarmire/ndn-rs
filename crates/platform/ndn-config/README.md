# ndn-config

Parses TOML-based forwarder configuration and implements the NFD-compatible management protocol for runtime control of faces, routes, and strategies. All management command names and dataset names follow the NFD specification so that standard NDN tools interoperate with the router.

## Key Types

| Type / Trait | Role |
|---|---|
| `ForwarderConfig` | Top-level TOML config (faces, routes, CS, security, logging) |
| `FaceConfig` / `FaceKind` | Per-face configuration (UDP, TCP, Ethernet, Unix, etc.) |
| `RouteConfig` | Static FIB route: prefix, face, cost |
| `EngineConfig` | Runtime engine knobs embedded in the TOML config |
| `ControlParameters` | Structured parameters for NFD management commands |
| `ControlResponse` | NFD-format management command response |
| `ParsedCommand` | Result of parsing an NFD command Interest name |
| `ConfigError` | Parse and validation errors |

## Usage

```rust
use ndn_config::ForwarderConfig;

let config: ForwarderConfig = toml::from_str(&std::fs::read_to_string("router.toml")?)?;

// Build an NFD-compatible command Interest name
use ndn_config::command_name;
let name = command_name("faces", "create");
```

Part of the [ndn-rs](../../README.md) workspace.
