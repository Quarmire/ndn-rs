# `.ndfv` — the conformance-vector format (F42)

One vector per file. Line-oriented `key: value`; `#` starts a comment; blank
lines ignored. Keys:

| key | value | meaning |
|---|---|---|
| `name:` | word | vector id (defaults to the file stem) |
| `bytes:` | hex, whitespace-tolerant | the primary byte string |
| `bytes2:` | hex | the second byte string (hash-distinct family) |
| `golden:` | 64-hex | expected SHA-256 of the canonical bytes |
| `file:` | relative path | script under test (compile families) |
| `dag:` | relative paths, space-separated | scripts compiled (in order) into the DAG / resolver before `file:`/`contract:` |
| `contract:` | relative path, or `@kernel-t0` | the `.ndfc` under test (verdict family); `@kernel-t0` uses the baked terminal contract (requires `kernel: trio`) |
| `admit:` | petnames, space-separated | the trust frontier (verdict family); absent = empty frontier |
| `kernel:` | `trio` | seed V₀.2 · IM₀ · T₀ from the LIVE encoder into the DAG/resolver first; registers petnames `v0`, `im0`, `t0` (usable in `admit:` and in scripts as `im0:block` etc.) |
| `expect:` | see below | exactly one expectation |

Expectations:

- `expect: roundtrip` — bytes decode (the decoder enforces decode∘encode
  byte-identity internally, R13). If `golden:` is present the document hash
  must match; `ndn-bench vectors --record` fills absent goldens (D-K8:
  goldens are recorded by the bench, never hand-computed — the byte-literal
  vectors in `wire/` carry SHA-256-of-given-bytes goldens, which are
  toolchain-independent).
- `expect: reject <Code>` — bytes reject with exactly that typed code
  (`Reject::code()` strings; e.g. `NonMinimalVarint`, `DuplicateMapKey`).
- `expect: hash-distinct` — `bytes:` and `bytes2:` both decode; their hashes
  differ (the W-14 family: the wire never normalizes).
- `expect: compile-ok` — `file:` compiles with zero lint **errors** (warns
  and infos are allowed and expected in some gates).
- `expect: compile-error [<L-rule>]` — the script fails compile or lint with
  that rule; with no rule given, any failure passes (parse errors carry no
  rule tag).
- `expect: verdict <intent> <Express|Approximate|Refuse|Unresolved|Mismatch>`
  — compile `dag:` + `contract:`, admit `admit:`, run the matcher, and check
  the verdict for that intent. `Mismatch` asserts **no Match was emitted**
  (the third silence, distinct from Refuse and Unresolved — D-K9).
- `expect: kernel-pinned` — `verify_fixed_point()` must return Verified:
  the live encoder's trio matches the pinned constants (R14). Fails if run
  UNPINNED — pin first.
- `expect: kernel-hash <V0.2|IM0|T0>` — the named trio hash must match the
  `golden:` line; `--record` fills it (D-K8: recorded by the bench).

The compile families also run the **L-07 two-run harness**: `dag:` scripts
pin petnames first, and if `file:` re-compiles a pinned stratum name to a
different hash without a `supersedes` line, that is an in-place edit —
`compile-error L-07` catches it; `compile-ok` fails on it.

Run: `cargo run -p ndn-bench -- vectors conformance/vectors [--record]`.
Unsupported expectations are **skipped and reported** — the ledger records
them; the count is never padded (the honesty rule).
