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
| `contract:` | relative path | the `.ndfc` under test (verdict family) |
| `admit:` | petnames, space-separated | the trust frontier (verdict family); absent = empty frontier |
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

Run: `cargo run -p ndn-bench -- vectors conformance/vectors [--record]`.
Unsupported expectations are **skipped and reported** — the ledger records
them; the count is never padded (the honesty rule).
