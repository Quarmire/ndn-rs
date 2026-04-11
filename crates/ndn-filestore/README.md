# ndn-filestore

NDN File Transfer Protocol library — AirDrop-like file sharing over Named Data Networking. Files are hosted under a node's NDN namespace; receivers fetch content natively over NDN without any HTTP or IP-layer transport.

## Protocol Namespace Layout

```
/<node-prefix>/ndn-ft/v0/catalog              — segmented JSON catalog of hosted files
/<node-prefix>/ndn-ft/v0/file/<id>/meta       — file metadata (name, size, MIME type)
/<node-prefix>/ndn-ft/v0/file/<id>/<seg>      — binary file segment
/<node-prefix>/ndn-ft/v0/notify               — incoming transfer offer notifications
```

## Key Types

| Type | Role |
|------|------|
| `FileServer` | Hosts files under a node prefix; sends offers to remote nodes |
| `FileClient` | Listens for incoming offers; browses remote catalogs; downloads files |
| `FileId` | Opaque identifier for a hosted file |
| `FileMetadata` | Name, size, MIME type, and hash of a hosted file |
| `FileOffer` | Offer payload sent from sender to receiver |
| `HostOpts` | Options for `FileServer::host` (signing mode, encryption, chunking) |
| `SigningMode` | How segments are signed (`None`, `Sha256`, `Ed25519`) |
| `EncryptionMode` | Optional segment encryption |
| `TransferConfig` | Tuning parameters (pipeline depth, segment size, timeouts) |

## Feature Flags

None. All dependencies are unconditional.

## Usage

```rust
use ndn_filestore::{FileServer, FileClient, HostOpts};
use ndn_packet::Name;
use std::path::Path;

// Sender
let mut server = FileServer::connect("/tmp/ndn.sock", "/alice/node1").await?;
let id = server.host(Path::new("photo.jpg"), HostOpts::default()).await?;
let target: Name = "/bob/node1".parse()?;
let accepted = server.offer(&target, &id, None).await?;

// Receiver
let mut client = FileClient::connect("/tmp/ndn.sock", "/bob/node1").await?;
client.listen(Path::new("/downloads"), |offer| {
    println!("Incoming: {} ({} bytes)", offer.name, offer.size);
    true // accept
}).await?;
```

Part of the [ndn-rs](../../README.md) workspace.
