# ndn-sync

NDN dataset synchronisation protocols: State Vector Sync (SVS) and Partial Sync
(PSync). Both protocols allow a group of nodes to converge on the same set of named
data objects without a central coordinator. The crate separates the pure data
structures (`SvsNode`, `PSyncNode`) from the network protocol layer that wires them
to actual Interest/Data exchange.

## Key types

| Type | Description |
|------|-------------|
| `SyncHandle` | High-level handle: receive updates, publish new names |
| `SyncUpdate` | Notification of a new name from a remote participant |
| `SyncError` | Error type for sync operations |
| `join_svs_group()` | Start an SVS session; returns `SyncHandle` |
| `SvsConfig` | SVS tuning: sync interval, group prefix, identity |
| `join_psync_group()` | Start a PSync session; returns `SyncHandle` |
| `PSyncConfig` | PSync tuning: IBF size, sync prefix, IBLT parameters |

## Usage

```toml
[dependencies]
ndn-sync = { version = "*" }
```

```rust
use ndn_sync::{SvsConfig, join_svs_group};

let (handle, mut updates) = join_svs_group(app_handle, SvsConfig {
    group_prefix: "/ndn/chat".parse()?,
    identity: "/ndn/chat/alice".parse()?,
    ..Default::default()
}).await?;

// Publish
handle.publish("/ndn/chat/alice/msg/1").await?;

// Receive
while let Some(update) = updates.recv().await {
    println!("new data: {}", update.name);
}
```
