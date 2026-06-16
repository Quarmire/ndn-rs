# AF_XDP redirect program (`af-xdp` feature)

`AfXdpFace` (Linux kernel-bypass Ethernet I/O) needs a tiny XDP program attached
to the interface that `XDP_REDIRECT`s incoming frames into an `XskMap` keyed by
RX queue index — that's how frames reach the user-space XSK ring.

This program is fixed and trivial (~10 BPF instructions), so the compiled object
is **checked in** (`redirect.bpf.o`) and embedded into the crate via
`include_bytes!`. That makes the face self-contained: no eBPF build toolchain
(nightly + `bpf-linker`, or `clang`) is needed to *use* it. `AfXdpFace::new`
takes an explicit object path; `AfXdpFace::new_with_embedded_redirect` uses this
vendored object.

## Files
- `redirect.bpf.o` — the compiled program (`bpfel-unknown-none`), embedded by
  `src/l2/af_xdp.rs`. Exposes a `redirect` XDP program + an `XSKS` xskmap.
- `redirect-ebpf/` — the pure-Rust `aya-ebpf` source, kept for reproducibility.
  **Excluded from the workspace** (it only builds for the BPF target).

## Rebuilding `redirect.bpf.o`
Only needed if the program changes (it rarely should):

```sh
rustup toolchain install nightly --component rust-src
cargo install bpf-linker            # needs LLVM available
cd redirect-ebpf
cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core
cp target/bpfel-unknown-none/release/redirect ../redirect.bpf.o
```

A C/`clang` equivalent (`bpf_redirect_map(&XSKS, ctx->rx_queue_index, XDP_PASS)`)
produces an interchangeable object; see
`.claude/notes/afxdp-face-scope-2026-05-24.md`.
