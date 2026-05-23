# Trust policies

The trust policy decides whether a signing key is allowed to sign a
given name. ndn-rs splits this across two traits:

- `TrustPolicy` — atomic verdict for one (key, name) pair.
- `ValidationPolicy` — composition of `TrustPolicy`s with chaining
  and override rules.

Implementations live in `crates/ndn-security/src/`. The
Develop-tier re-exports are listed below.

For the trait surface see
[Extend tier → TrustPolicy / ValidationPolicy](../api/extend.md).
For the `KeyChain`-side flow see
[Identity and keys](../concepts/identity-and-keys.md).

## Built-in policies

| Policy | Source | Accepts | Use |
|---|---|---|---|
| `InsecureTrust` | `trust.rs` | Any signature. | Tests; never production. |
| `StaticTrust` | `trust.rs` | Allowlist of key-locator names. | Closed groups, known signers. |
| `LvsTrust` | `trust.rs` + `lvs/` | Light Versatile Schema rules. | Pattern-based deployments. |
| `HierarchicalPolicy` | `validation_policy.rs` | Parent-name key signs child-name data. | Standard NDN trust shape. |
| `AcceptAllPolicy` | `validation_policy.rs` | Skip validation entirely. | Migration / degraded mode. |
| `ChainedPolicy` | `validation_policy.rs` | First policy that returns a verdict wins. | Composition. |

## Hierarchical example

```rust,ignore
use ndn::prelude::*;
use ndn::{HierarchicalPolicy, ValidationPolicy, Consumer};

# async fn run() -> anyhow::Result<()> {
let policy = HierarchicalPolicy::anchor("/lab/ca")
    .max_depth(4);
let mut consumer = Consumer::connect("/tmp/ndn-fwd.sock").await?
    .with_validation(policy);
let _data = consumer.fetch("/lab/alice/notes/2026-05-20").await?;
# Ok(()) }
```

The validator walks the cert chain from the `Data`'s signature info
up to a cert whose name is a prefix of `/lab/ca`. If the chain
exceeds `max_depth` or breaks anywhere, the verdict is rejection.

## Static example

```rust,ignore
use ndn::{StaticTrust, ValidationPolicy};

# fn build() -> StaticTrust {
StaticTrust::new()
    .allow_for_prefix("/lab/alice/", "/lab/alice/KEY/.../v=1")
    .allow_for_prefix("/lab/bob/",   "/lab/bob/KEY/.../v=3")
# }
```

`StaticTrust` matches a key-name suffix against an allowlist
keyed by name prefix. No chain walking.

## LVS example

Light Versatile Schema rules read more like a config:

```text
#consumerSchema:
    /lab/{user}/notes/{*} <= /lab/{user}/KEY/<key-id>
    /lab/{user}/KEY/<key-id> <= /lab/ca/KEY/<key-id>
```

Compiled into an `LvsTrust`:

```rust,ignore
use ndn::LvsTrust;

# fn build() -> anyhow::Result<LvsTrust> {
let schema = std::fs::read_to_string("trust.lvs")?;
let trust = LvsTrust::from_schema(&schema)?;
# Ok(trust) }
```

The LVS rule shape is in `crates/ndn-security/src/lvs/`.

## Writing a custom policy

Implement `TrustPolicy`:

```rust,ignore
use ndn_security::trust::{TrustPolicy, TrustVerdict};
use ndn_packet::Name;

pub struct MyPolicy;

impl TrustPolicy for MyPolicy {
    fn check(&self, data_name: &Name, key_locator: &Name) -> TrustVerdict {
        if data_name.starts_with("/lab") && key_locator.starts_with("/lab/ca") {
            TrustVerdict::Accept
        } else {
            TrustVerdict::Reject("not under /lab".into())
        }
    }
}
```

Compose into the validator:

```rust,ignore
use ndn::{ValidationPolicy, ChainedPolicy};

let validation = ChainedPolicy::new()
    .then(MyPolicy)
    .then(HierarchicalPolicy::anchor("/lab/ca"));
```

## Where the policy runs

| Location | What is checked |
|---|---|
| `KeyChain::sign(data, info)` | "Is this key permitted to sign this name?" (pre-sign guard) |
| `Consumer::fetch(name)` returning `Data` | "Is this signature trustworthy for this name?" (validator) |
| `Producer::publish_object` | Pre-sign guard via the supplied `KeyChain`. |
| `Subscriber::next` | Validator (per `SubscriberConfig`). |

## See also

- [Identity and keys](../concepts/identity-and-keys.md) — KeyChain
  and SigningInfo.
- [NDNCERT setup](../guides/ndncert-setup.md) — issuing the certs
  these policies validate against.
- [Extend tier](../api/extend.md) — implementing custom policies.
- `crates/ndn-security/` — the implementation.
