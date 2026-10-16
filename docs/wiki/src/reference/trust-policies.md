# Trust policies

The trust policy decides whether a signing key may sign a given name.
In ndn-rs the policy is a `TrustSchema`, and the `Validator` enforces it:
the validator checks the packet's `(data name, key name)` pair with
`TrustSchema::allows` (via the trust context that owns the name) and
walks the certificate chain to a trust anchor. A schema is a set of
`SchemaRule`s (OR'd) plus an optional LVS model; the pair passes if any
rule or the model allows it.

The implementation lives in `crates/security/ndn-security/src/`
(`trust_schema.rs`, `lvs.rs`, `validator/`). See
[Extend tier](../api/extend.md) and
[Identity and keys](../concepts/identity-and-keys.md).

## Built-in schemas

| Constructor | Accepts | Use |
|---|---|---|
| `TrustSchema::hierarchical()` | Data and signing key share their first name component. | Standard NDN trust shape. |
| `TrustSchema::accept_all()` | Any name pair; the anchor set is the only boundary. | Anchor-only deployments, tests. |
| `TrustSchema::from_lvs_binary(..)` | Light Versatile Schema rules (compiled LVS). | Pattern-based deployments. |
| `TrustSchema::new()` + `add_rule` | Your own `SchemaRule`s. | Custom policies. |

Every schema still requires a valid signature that chains to an anchor;
`accept_all` only drops the name check.

## Hierarchical example

Pin a `Validator` to turn a `Consumer` into a `VerifiedConsumer`, whose
`fetch` returns `SafeData` (a failed chain walk errors instead):

```rust,ignore
use ndn::prelude::*;
use ndn_security::{TrustSchema, Validator};

# async fn run() -> anyhow::Result<()> {
let validator = Validator::new(TrustSchema::hierarchical());
let mut consumer = Consumer::connect("/tmp/ndn-fwd.sock").await?
    .verifying(validator);
let _safe = consumer.fetch("/lab/alice/notes/2026-05-20").await?; // SafeData
# Ok(()) }
```

A `KeyChain` builds the same validator pre-loaded with its anchors:
`keychain.validator()`.

## LVS example

A textual Light Versatile Schema is compiled to LVS binary form by an
external compiler; `TrustSchema::from_lvs_binary` loads it. Schemas that
use LVS user functions are rejected unless you pass a registry via
`TrustSchema::from_lvs_binary_with_user_fns` (fail-closed):

```rust,ignore
use ndn_security::{TrustSchema, Validator};

# fn build() -> anyhow::Result<Validator> {
let bytes = std::fs::read("trust.tlv")?;       // compiled LVS model
let validator = Validator::new(TrustSchema::from_lvs_binary(&bytes)?);
# Ok(validator) }
```

## Writing a custom policy

Custom acceptance logic is a set of `SchemaRule`s. Each rule reads
`"<data pattern> => <key pattern>"`; `<var>` captures one component,
`<**var>` captures the rest, and a variable captured in both patterns
must bind to the same component:

```rust,ignore
use ndn_security::{SchemaRule, TrustSchema, Validator};

# fn build() -> anyhow::Result<Validator> {
let mut schema = TrustSchema::new();
// Lab data must be signed by the lab CA.
schema.add_rule(SchemaRule::parse("/lab/<**rest> => /lab/ca/KEY/<id>")?);
// Each sensor signs only its own readings.
schema.add_rule(SchemaRule::parse("/sensor/<node>/<**rest> => /sensor/<node>/KEY/<id>")?);
let validator = Validator::new(schema);
# Ok(validator) }
```

Rules are OR'd: there is no ordered first-match-deny mode (ndn-cxx
`validator.conf` semantics are not supported; LVS is the policy
language).

## Where the policy runs

| Location | What is checked |
|---|---|
| `KeyChain::sign` / `Producer::publish_object` | "May this key sign this name?" (pre-sign guard) |
| `VerifiedConsumer::fetch(name)` returning `SafeData` | "Is this signature trustworthy for this name?" (validator) |
| `Subscriber::recv` | Validator (per `SubscriberConfig`). |

## Trust contexts and onboarding

A node adopts a set of **trust contexts** (a `Keyring`). Each
`SignedTrustContext` binds a `namespace` to its own anchors and schema, and
the validator routes each packet to its namespace's context — no cross-talk.

```rust,ignore
use std::sync::Arc;
use ndn_security::{Certificate, SignedTrustContext, TrustSchema, Validator};

# fn wire(home_anchor: Certificate) -> anyhow::Result<()> {
let validator = Validator::new(TrustSchema::hierarchical());
let home = Arc::new(SignedTrustContext::hierarchical("/home/bob".parse()?));
home.add_anchor(home_anchor);
validator.adopt_context(home); // data under /home/bob validates against it
# Ok(()) }
```

Onboarding (`ndn-cert`) splits into *adopt-to-verify* (anchor + schema to
verify data; free, pinned by the anchor fingerprint in an `ndn-trust://anchor`
envelope) and
*enroll-to-be-verified* (a cert to produce, gated by NDNCERT challenges;
see [NDNCERT setup](../guides/ndncert-setup.md)).

## See also

- [Identity and keys](../concepts/identity-and-keys.md) — KeyChain and SigningInfo.
- [NDNCERT setup](../guides/ndncert-setup.md) — issuing the certs these policies validate.
- [Extend tier](../api/extend.md) — implementing custom policies.
- `crates/security/ndn-security/` — the implementation.
