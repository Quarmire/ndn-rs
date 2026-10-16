# Trust-context publication (RDR)

A node that holds a trust context publishes it by name, so another device can
fetch it knowing only the namespace and the anchor's **fingerprint** (a
fingerprint-only `ndn-trust://anchor` envelope, or an invite). The fetch gives
no trust by itself: the fetched Data is adopted only through
`ndn_cert::adopt_with_tofu`, which checks its signature under the anchor the
fingerprint pins.

Contexts are public — anchors, schema, CA endpoints, revocations — so
publishing them leaks nothing a device of the namespace could not already show.

## Names and packets

Publication follows the RDR convention
([ndn-cxx RDR spec](https://named-data.net/doc/ndn-cxx/current/specs/rdr.html)):
one discovery Interest returns the versioned name, then the consumer fetches
that exact name.

| Interest | Answer | Signed by |
|---|---|---|
| `/<ns>/32=trust-context/32=metadata` (CanBePrefix, MustBeFresh) | metadata Data `/<ns>/32=trust-context/32=metadata/v=<N>/seg=0`; Content = the Name `/<ns>/32=trust-context/v=<N>` only; FreshnessPeriod 1 s | DigestSha256 |
| `/<ns>/32=trust-context/v=<N>` (exact) | the stored context Data, byte for byte as adopted | the namespace root (`/<ns>/KEY/…`), as signed at `init` |
| anything else under `/<ns>/32=trust-context` (another version, …) | Nack `NoRoute` | — |

The metadata Content carries no segment fields: a context is one Data packet.
`ndn_app::rdr::MetaData` encodes and decodes both this Name-only form and the
segmented-object form (with `FinalBlockID` and sizes).

### Why the metadata is not signed

The metadata is an unauthenticated pointer, on purpose:

- The adopter holds only a fingerprint and could not check a node signature.
- `fetch_context` accepts a pointer only of the form
  `/<asked ns>/32=trust-context/v=<N>`. A forged pointer can then only name a
  forged or foreign context (refused by the fingerprint pin), an older genuine
  version (refused by the keyring's anti-rollback once a newer one is held),
  or a name nobody serves (a fetch error). On first contact an older genuine
  version can be adopted; signing the pointer would not stop that, because an
  old signed metadata Data can be replayed just as well. The envelope's
  `version` field closes it: the adopter requires at least that version.
- A node-key signature would be dropped in transit. Every forwarder that holds
  the context validates Data from non-local faces against the generated
  schema, and no rule covers the metadata name
  (`ndn-fwd schema explain /<ns>/32=trust-context/32=metadata/v=1/seg=0 /<ns>/admin/<dev>/KEY/device`
  → `deny`). DigestSha256 is accepted everywhere as integrity-only.

## Fetching

```rust,ignore
use ndn_cert::{adopt_with_tofu, fetch_context, CaExchange};

# async fn adopt(exchange: &mut impl CaExchange, keyring: &ndn_security::Keyring,
#               fingerprint: [u8; 32]) -> anyhow::Result<()> {
let ns: ndn_packet::Name = "/home/bob".parse()?;
// Name-checked, not yet trusted.
let data = fetch_context(exchange, &ns).await?;
// The one place trust is decided: signature, pinned anchor, anti-rollback.
let ctx = adopt_with_tofu(keyring, &data, &ns, &fingerprint)?;
# Ok(()) }
```

`fetch_context` (in `crates/security/ndn-cert/src/onboarding.rs`) runs over any
`CaExchange` (one Interest in, one Data out — the same transport seam as
NDNCERT enrollment). It refuses, with a `FetchContextError` naming the reason:
a metadata reply outside the metadata name, metadata without a Name or with
malformed TLV, a pointer outside `/<ns>/32=trust-context/v=<N>`, and a context
reply whose name differs from the pointer. It never verifies a signature;
`adopt_with_tofu` does, once.

## Serving (`ndn-fwd`)

At startup the daemon reads every context in `<pib_path>/contexts/` (its own
namespace's context from `ndn-fwd init` and those added by `ndn-fwd adopt`),
re-verifies each against its own anchors, and serves the ones that pass from
one in-process face with one FIB entry `/<ns>/32=trust-context` per context.
That entry is more specific than a `[ca]` entry `/<ns>`, so both coexist.
A file that fails verification is logged and not published. The store keeps
one file — the newest adopted version — per namespace.

The store is read at startup. A context the running daemon adopts
(`ndn-fwd adopt`, see [Adopting a trust context](./context-adoption.md)) is added to
the published set at once, replacing an older version of its namespace.

```toml
[security]
serve_contexts = true   # default; false publishes nothing
```

Code: `binaries/ndn-fwd/src/context_publisher.rs` (ndn-fwd repository);
the store reader is `ndn_cert::read_stored_contexts`.

## Trying it

```sh
ndn-fwd init --namespace /home/bob --device laptop --pib /tmp/root/pib
# prints anchor_fp and the [security] lines; put them in root.toml, then
ndn-fwd --config root.toml
ndn-peek --face-socket <root device socket> --can-be-prefix -m /home/bob/32=trust-context/32=metadata
#   name: /home/bob/keyword=trust-context/keyword=metadata/v=1/seg=0  sig-type: DigestSha256
ndn-peek --face-socket <root device socket> -m /home/bob/32=trust-context/v=1
#   name: /home/bob/keyword=trust-context/v=1  sig-type: SignatureEd25519  key: /home/bob/KEY/root
```

## Fetching through a validating forwarder that holds nothing yet

A forwarder validates Data arriving on non-local faces. One that holds no
context for `/<ns>` cannot anchor the root-signed context Data, so on its own
it drops it (the DigestSha256 metadata passes). While an adoption runs, the
adopter registers an *expectation* with that forwarder's validator, which then
admits exactly the context signed by the anchor with the expected fingerprint
and drops any other — see [Adopting a trust context](./context-adoption.md).

## See also

- [Trust policies](./trust-policies.md) — contexts, schemas and the validator.
- [NDNCERT setup](../guides/ndncert-setup.md) — `ndn-fwd init` and enrollment.
