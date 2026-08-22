# Trust policies

The trust policy decides whether a signing key may sign a given name.
ndn-rs splits this across two traits:

- `TrustPolicy` — an operator handle: which `Signer` to use on egress
  (`signer`), which `Validator` to apply on ingress (`validator`).
- `ValidationPolicy` — the composable acceptance check: given a `Data`,
  its key locator, and a chain-walk depth, return a `PolicyVerdict`
  (`Allow`, `NeedCert`, or `Deny`).

Implementations live in `crates/security/ndn-security/src/`. See
[Extend tier](../api/extend.md) and
[Identity and keys](../concepts/identity-and-keys.md).

## Built-in policies

| Policy | Source | Accepts | Use |
|---|---|---|---|
| `InsecureTrust` | `trust.rs` | `DigestSha256`; validator accepts anything. | Tests; never production. |
| `StaticTrust` | `trust.rs` | Fixed signer + hierarchical validator. | Closed groups, known signers. |
| `LvsTrust` | `trust.rs` + `lvs.rs` | Light Versatile Schema rules. | Pattern-based deployments. |
| `HierarchicalPolicy` | `validation_policy.rs` | Signing key's identity is a prefix of the data name. | Standard NDN trust shape. |
| `AcceptAllPolicy` | `validation_policy.rs` | Skip validation entirely. | Migration / degraded mode. |
| `ChainedPolicy` | `validation_policy.rs` | All members `Allow` (first `Deny`/`NeedCert` short-circuits). | Composition. |

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

## Static example

`StaticTrust` is a `TrustPolicy` with a fixed signer and a hierarchical
validator. Build from a `KeyChain` (carries its anchors) or a bare signer
via `StaticTrust::new(..)`:

```rust,ignore
use std::sync::Arc;
use ndn::{KeyChain, StaticTrust, TrustPolicy};

# fn build() -> anyhow::Result<StaticTrust> {
let keychain = Arc::new(KeyChain::ephemeral("/lab/alice")?);
let trust = StaticTrust::from_keychain(keychain)?;
# Ok(trust) }
```

## LVS example

A textual Light Versatile Schema is compiled to LVS binary form by an
external compiler; `LvsModel::decode` reads it and `LvsTrust` wraps it
with a signer (also `LvsTrust::from_keychain(model, keychain)`):

```rust,ignore
use std::sync::Arc;
use ndn::LvsTrust;
use ndn_security::LvsModel;

# fn build() -> anyhow::Result<LvsTrust> {
let bytes = std::fs::read("trust.tlv")?;       // compiled LVS model
let model = Arc::new(LvsModel::decode(&bytes)?);
let trust = LvsTrust::new(model, None);        // None ⇒ DigestSha256 egress
# Ok(trust) }
```

## Writing a custom policy

Custom acceptance logic implements `ValidationPolicy::check`, returning a
boxed future of `PolicyVerdict` (`Allow` / `Deny(TrustError)` / `NeedCert(Name)`):

```rust,ignore
use std::{future::Future, pin::Pin, sync::Arc};
use ndn_packet::{Data, Name};
use ndn_security::{ChainedPolicy, HierarchicalPolicy, PolicyVerdict, TrustError, ValidationPolicy};

pub struct MyPolicy;

impl ValidationPolicy for MyPolicy {
    fn check<'a>(
        &'a self,
        data: &'a Data,
        key_locator: &'a Name,
        _depth: usize,
    ) -> Pin<Box<dyn Future<Output = PolicyVerdict> + Send + 'a>> {
        Box::pin(async move {
            let ok = data.name.has_prefix(&"/lab".parse().unwrap())
                && key_locator.has_prefix(&"/lab/ca".parse().unwrap());
            if ok {
                PolicyVerdict::Allow
            } else {
                PolicyVerdict::Deny(TrustError::SchemaMismatch)
            }
        })
    }
}

// ChainedPolicy: members run in order; first Deny/NeedCert short-circuits.
let mut chain = ChainedPolicy::new(vec![Arc::new(MyPolicy) as Arc<dyn ValidationPolicy>]);
chain.push(Arc::new(HierarchicalPolicy::new()));
```

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
verify data; free, pinned by a `BootstrapTicket` fingerprint) and
*enroll-to-be-verified* (a cert to produce, gated by NDNCERT challenges;
see [NDNCERT setup](../guides/ndncert-setup.md)).

## See also

- [Identity and keys](../concepts/identity-and-keys.md) — KeyChain and SigningInfo.
- [NDNCERT setup](../guides/ndncert-setup.md) — issuing the certs these policies validate.
- [Extend tier](../api/extend.md) — implementing custom policies.
- `crates/security/ndn-security/` — the implementation.
