//! Composable trust-policy primitives.
//!
//! Each [`ValidationPolicy`] answers: given this Data packet's
//! `KeyLocator` and a chain-walk depth, should validation Allow, Deny,
//! or fetch a missing cert? [`ChainedPolicy`] sequences policies with
//! first-Deny short-circuit.
//!
//! Built-ins: [`AcceptAllPolicy`] (always allow; test/debug),
//! [`HierarchicalPolicy`] (data name under the signing identity's
//! prefix; default for [`KeyChain::validator`](crate::KeyChain::validator)),
//! [`LvsPolicy`] (matches against an [`LvsModel`]).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use ndn_packet::{Data, Name};

use crate::TrustError;
use crate::lvs::LvsModel;
use crate::trust_schema::TrustSchema;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum PolicyVerdict {
    /// Pass this hop; verify the signature and continue the chain walk.
    Allow,
    /// Need the named cert before deciding; the driver fetches it (or
    /// surfaces `Pending`) and re-runs the policy.
    NeedCert(Name),
    /// Reject with the bundled error; drivers must surface verbatim.
    Deny(TrustError),
}

impl PolicyVerdict {
    pub fn is_deny(&self) -> bool {
        matches!(self, PolicyVerdict::Deny(_))
    }

    pub fn is_allow(&self) -> bool {
        matches!(self, PolicyVerdict::Allow)
    }
}

/// Object-safe by construction (no generics, no RPIT).
pub trait ValidationPolicy: Send + Sync + 'static {
    /// Evaluate against `data`'s `key_locator` at chain `depth`.
    /// Returning [`PolicyVerdict::NeedCert`] asks the driver to fetch a
    /// missing intermediate cert and re-run.
    fn check<'a>(
        &'a self,
        data: &'a Data,
        key_locator: &'a Name,
        depth: usize,
    ) -> Pin<Box<dyn Future<Output = PolicyVerdict> + Send + 'a>>;
}

/// Always allows.
pub struct AcceptAllPolicy;

impl ValidationPolicy for AcceptAllPolicy {
    fn check<'a>(
        &'a self,
        _data: &'a Data,
        _key_locator: &'a Name,
        _depth: usize,
    ) -> Pin<Box<dyn Future<Output = PolicyVerdict> + Send + 'a>> {
        Box::pin(async move { PolicyVerdict::Allow })
    }
}

/// Data name must be a sub-name of the signing key's identity prefix;
/// backed by [`TrustSchema::hierarchical`].
pub struct HierarchicalPolicy {
    schema: TrustSchema,
}

impl HierarchicalPolicy {
    pub fn new() -> Self {
        Self {
            schema: TrustSchema::hierarchical(),
        }
    }

    pub fn from_schema(schema: TrustSchema) -> Self {
        Self { schema }
    }
}

impl Default for HierarchicalPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidationPolicy for HierarchicalPolicy {
    fn check<'a>(
        &'a self,
        data: &'a Data,
        key_locator: &'a Name,
        _depth: usize,
    ) -> Pin<Box<dyn Future<Output = PolicyVerdict> + Send + 'a>> {
        Box::pin(async move {
            if self.schema.allows(&data.name, key_locator) {
                PolicyVerdict::Allow
            } else {
                PolicyVerdict::Deny(TrustError::SchemaMismatch)
            }
        })
    }
}

/// `data` and `key_locator` must satisfy some rule in the bundled
/// [`LvsModel`].
pub struct LvsPolicy {
    schema: Arc<LvsModel>,
}

impl LvsPolicy {
    pub fn new(schema: Arc<LvsModel>) -> Self {
        Self { schema }
    }

    pub fn schema(&self) -> &Arc<LvsModel> {
        &self.schema
    }
}

impl ValidationPolicy for LvsPolicy {
    fn check<'a>(
        &'a self,
        data: &'a Data,
        key_locator: &'a Name,
        _depth: usize,
    ) -> Pin<Box<dyn Future<Output = PolicyVerdict> + Send + 'a>> {
        Box::pin(async move {
            if self.schema.check(&data.name, key_locator) {
                PolicyVerdict::Allow
            } else {
                PolicyVerdict::Deny(TrustError::SchemaMismatch)
            }
        })
    }
}

/// Evaluate a sequence of policies with first-Deny short-circuit:
/// `Deny` ends the chain, `NeedCert` propagates to the driver, `Allow`
/// advances to the next policy. The chain Allows iff every member does.
pub struct ChainedPolicy {
    policies: Vec<Arc<dyn ValidationPolicy>>,
}

impl ChainedPolicy {
    pub fn new(policies: Vec<Arc<dyn ValidationPolicy>>) -> Self {
        Self { policies }
    }

    pub fn push(&mut self, policy: Arc<dyn ValidationPolicy>) {
        self.policies.push(policy);
    }

    pub fn policies(&self) -> &[Arc<dyn ValidationPolicy>] {
        &self.policies
    }
}

impl ValidationPolicy for ChainedPolicy {
    fn check<'a>(
        &'a self,
        data: &'a Data,
        key_locator: &'a Name,
        depth: usize,
    ) -> Pin<Box<dyn Future<Output = PolicyVerdict> + Send + 'a>> {
        Box::pin(async move {
            for policy in &self.policies {
                let verdict = policy.check(data, key_locator, depth).await;
                match verdict {
                    PolicyVerdict::Deny(err) => return PolicyVerdict::Deny(err),
                    PolicyVerdict::NeedCert(name) => return PolicyVerdict::NeedCert(name),
                    PolicyVerdict::Allow => continue,
                }
            }
            PolicyVerdict::Allow
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::encode::DataBuilder;

    fn make_data(name: &str) -> Data {
        let wire = DataBuilder::new(name, b"body").sign_digest_sha256();
        Data::decode(wire).unwrap()
    }

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn accept_all_always_allows() {
        let p = AcceptAllPolicy;
        let data = make_data("/anywhere/data");
        let kl = name("/totally/unrelated/key");
        assert!(p.check(&data, &kl, 0).await.is_allow());
    }

    /// Data name's first component must match the key locator's.
    #[tokio::test]
    async fn hierarchical_allows_same_namespace() {
        let p = HierarchicalPolicy::new();
        let data = make_data("/com/example/data");
        let kl = name("/com/example/KEY/k1");
        assert!(p.check(&data, &kl, 0).await.is_allow());
    }

    #[tokio::test]
    async fn hierarchical_denies_cross_namespace() {
        let p = HierarchicalPolicy::new();
        let data = make_data("/com/example/data");
        let kl = name("/org/unrelated/KEY/k1");
        assert!(p.check(&data, &kl, 0).await.is_deny());
    }

    /// `ChainedPolicy` is first-Deny: a Data that passes one policy but
    /// fails another is denied.
    #[tokio::test]
    async fn chained_first_deny_short_circuits() {
        let hier = Arc::new(HierarchicalPolicy::new()) as Arc<dyn ValidationPolicy>;

        struct DenyComExample;
        impl ValidationPolicy for DenyComExample {
            fn check<'a>(
                &'a self,
                data: &'a Data,
                _key_locator: &'a Name,
                _depth: usize,
            ) -> Pin<Box<dyn Future<Output = PolicyVerdict> + Send + 'a>> {
                Box::pin(async move {
                    if data.name.to_string().starts_with("/com/example") {
                        PolicyVerdict::Deny(TrustError::SchemaMismatch)
                    } else {
                        PolicyVerdict::Allow
                    }
                })
            }
        }
        let deny = Arc::new(DenyComExample) as Arc<dyn ValidationPolicy>;

        let chain = ChainedPolicy::new(vec![Arc::clone(&hier), Arc::clone(&deny)]);
        let data = make_data("/com/example/data");
        let kl = name("/com/example/KEY/k1");
        assert!(chain.check(&data, &kl, 0).await.is_deny());

        let chain = ChainedPolicy::new(vec![Arc::clone(&deny), Arc::clone(&hier)]);
        assert!(chain.check(&data, &kl, 0).await.is_deny());

        let chain = ChainedPolicy::new(vec![hier]);
        let data = make_data("/org/other/data");
        let kl = name("/org/other/KEY/k1");
        assert!(chain.check(&data, &kl, 0).await.is_allow());
    }

    /// Empty `ChainedPolicy` allows by default.
    #[tokio::test]
    async fn chained_empty_allows() {
        let chain = ChainedPolicy::new(vec![]);
        let data = make_data("/anywhere");
        let kl = name("/somewhere");
        assert!(chain.check(&data, &kl, 0).await.is_allow());
    }

    /// `NeedCert` propagates through `ChainedPolicy` to the driver.
    #[tokio::test]
    async fn chained_propagates_need_cert() {
        struct NeedCertPolicy(Name);
        impl ValidationPolicy for NeedCertPolicy {
            fn check<'a>(
                &'a self,
                _data: &'a Data,
                _key_locator: &'a Name,
                _depth: usize,
            ) -> Pin<Box<dyn Future<Output = PolicyVerdict> + Send + 'a>> {
                let n = self.0.clone();
                Box::pin(async move { PolicyVerdict::NeedCert(n) })
            }
        }
        let chain = ChainedPolicy::new(vec![
            Arc::new(AcceptAllPolicy),
            Arc::new(NeedCertPolicy(name("/needed/cert"))),
            Arc::new(AcceptAllPolicy),
        ]);
        let data = make_data("/d");
        let kl = name("/k");
        let v = chain.check(&data, &kl, 0).await;
        assert!(matches!(v, PolicyVerdict::NeedCert(n) if n.to_string() == "/needed/cert"));
    }
}
