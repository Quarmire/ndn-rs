---
name: add-face
description: Scaffold a new Face implementation for ndn-rs
user_invocable: true
---

The user wants to create a new Face type for ndn-rs.

Steps:
1. Ask for: face name, transport mechanism, which crate it belongs in
2. Read `crates/ndn-transport/src/face.rs` for the Face trait definition and FaceKind enum
3. Read an existing face implementation as a template (e.g., `crates/ndn-face-net/src/udp.rs` for network faces, or `crates/ndn-face-local/src/app_face.rs` for local faces)
4. Create the new face file implementing the `Face` trait:
   - `id()` -> FaceId
   - `kind()` -> FaceKind (add new variant if needed)
   - `recv()` -> async, called from one task
   - `send()` -> async, must be &self safe for concurrent calls
   - `remote_uri()` and `local_uri()`
5. Add the FaceKind variant to the enum in `crates/ndn-transport/src/face.rs`
6. Update scope() if the face is local
7. Export from the crate's lib.rs
8. Add a basic test

The face name is provided as the argument (e.g., "quic", "mqtt", "can-bus").
