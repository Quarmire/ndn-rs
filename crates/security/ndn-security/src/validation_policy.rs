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

/// Checker used by a configuration-style validation rule.
#[derive(Clone, Debug)]
pub enum ConfigChecker {
    /// Data and key must satisfy the standard hierarchical relationship.
    Hierarchical,
    /// KeyLocator must be under the configured prefix.
    KeyLocatorPrefix(Box<Name>),
}

impl ConfigChecker {
    pub fn key_locator_prefix(prefix: Name) -> Self {
        Self::KeyLocatorPrefix(Box::new(prefix))
    }

    fn check(&self, data: &Data, key_locator: &Name) -> PolicyVerdict {
        match self {
            ConfigChecker::Hierarchical => {
                if TrustSchema::hierarchical().allows(&data.name, key_locator) {
                    PolicyVerdict::Allow
                } else {
                    PolicyVerdict::Deny(TrustError::SchemaMismatch)
                }
            }
            ConfigChecker::KeyLocatorPrefix(prefix) => {
                if key_locator.has_prefix(prefix.as_ref()) {
                    PolicyVerdict::Allow
                } else {
                    PolicyVerdict::Deny(TrustError::SchemaMismatch)
                }
            }
        }
    }
}

/// One ordered rule in a configuration-style validator.
#[derive(Clone, Debug)]
pub struct ConfigRule {
    pub data_prefix: Name,
    pub checker: ConfigChecker,
}

impl ConfigRule {
    pub fn new(data_prefix: Name, checker: ConfigChecker) -> Self {
        Self {
            data_prefix,
            checker,
        }
    }

    fn matches(&self, data: &Data) -> bool {
        data.name.has_prefix(&self.data_prefix)
    }
}

/// Minimal ndn-cxx `ValidatorConfig` behavior model.
///
/// Rules are evaluated in order. The first rule whose filter matches the
/// packet name decides the verdict; no later rule can rescue it. If no rule
/// matches, the packet is invalid.
pub struct ConfigPolicy {
    rules: Vec<ConfigRule>,
}

impl ConfigPolicy {
    pub fn new(rules: Vec<ConfigRule>) -> Self {
        Self { rules }
    }

    pub fn rules(&self) -> &[ConfigRule] {
        &self.rules
    }
}

impl ValidationPolicy for ConfigPolicy {
    fn check<'a>(
        &'a self,
        data: &'a Data,
        key_locator: &'a Name,
        _depth: usize,
    ) -> Pin<Box<dyn Future<Output = PolicyVerdict> + Send + 'a>> {
        Box::pin(async move {
            for rule in &self.rules {
                if rule.matches(data) {
                    return rule.checker.check(data, key_locator);
                }
            }
            PolicyVerdict::Deny(TrustError::SchemaMismatch)
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

    fn c16_user_fn_lvs_model() -> LvsModel {
        use crate::lvs::{LVS_VERSION, type_number as tn};
        use bytes::BytesMut;
        use ndn_tlv::TlvWriter;

        fn write_tlv(buf: &mut BytesMut, t: u64, v: &[u8]) {
            let mut w = TlvWriter::new();
            w.write_tlv(t, v);
            buf.extend_from_slice(&w.finish());
        }
        fn uint_tlv(buf: &mut BytesMut, t: u64, v: u64) {
            let be = if v <= u8::MAX as u64 {
                vec![v as u8]
            } else {
                (v as u32).to_be_bytes().to_vec()
            };
            write_tlv(buf, t, &be);
        }
        fn component_value(buf: &mut BytesMut, value: &[u8]) {
            let mut nc = Vec::with_capacity(value.len() + 2);
            nc.push(0x08u8);
            nc.push(value.len() as u8);
            nc.extend_from_slice(value);
            write_tlv(buf, tn::COMPONENT_VALUE, &nc);
        }

        let mut out = BytesMut::new();
        uint_tlv(&mut out, tn::VERSION, LVS_VERSION);
        uint_tlv(&mut out, tn::NODE_ID, 0);
        uint_tlv(&mut out, tn::NAMED_PATTERN_NUM, 1);

        {
            let mut node = BytesMut::new();
            uint_tlv(&mut node, tn::NODE_ID, 0);
            let mut pe = BytesMut::new();
            uint_tlv(&mut pe, tn::NODE_ID, 1);
            uint_tlv(&mut pe, tn::PATTERN_TAG, 1);
            let mut cons = BytesMut::new();
            let mut opt = BytesMut::new();
            let mut call = BytesMut::new();
            write_tlv(&mut call, tn::USER_FN_ID, b"$regex");
            let mut arg = BytesMut::new();
            component_value(&mut arg, b"^[0-9]+$");
            write_tlv(&mut call, tn::FN_ARGS, &arg);
            write_tlv(&mut opt, tn::USER_FN_CALL, &call);
            write_tlv(&mut cons, tn::CONS_OPTION, &opt);
            write_tlv(&mut pe, tn::CONSTRAINT, &cons);
            write_tlv(&mut node, tn::PATTERN_EDGE, &pe);
            write_tlv(&mut out, tn::NODE, &node);
        }

        {
            let mut node = BytesMut::new();
            uint_tlv(&mut node, tn::NODE_ID, 1);
            uint_tlv(&mut node, tn::PARENT_ID, 0);
            uint_tlv(&mut node, tn::KEY_NODE_ID, 1);
            write_tlv(&mut out, tn::NODE, &node);
        }

        LvsModel::decode(&out).expect("user-fn fixture decodes")
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

    #[tokio::test]
    async fn c16_lvs_policy_denies_user_function_model() {
        let model = Arc::new(c16_user_fn_lvs_model());
        assert!(
            model.uses_user_functions(),
            "fixture must exercise a user-function constraint"
        );
        let policy = LvsPolicy::new(model);
        let data = make_data("/123");
        let key = name("/123");
        assert!(
            policy.check(&data, &key, 0).await.is_deny(),
            "unsupported LVS user functions must fail closed in policy evaluation"
        );
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

    #[tokio::test]
    async fn validator_config_no_matching_rule_denies() {
        let policy = ConfigPolicy::new(vec![ConfigRule::new(
            name("/configured"),
            ConfigChecker::Hierarchical,
        )]);
        let data = make_data("/unconfigured/data");
        let kl = name("/unconfigured/KEY/k1");
        assert!(
            policy.check(&data, &kl, 0).await.is_deny(),
            "configuration validator must reject packets matching no rule"
        );
    }

    #[tokio::test]
    async fn validator_config_hierarchical_checker() {
        let policy = ConfigPolicy::new(vec![ConfigRule::new(
            name("/lab"),
            ConfigChecker::Hierarchical,
        )]);
        let data = make_data("/lab/alice/data");
        assert!(
            policy
                .check(&data, &name("/lab/KEY/k1"), 0)
                .await
                .is_allow()
        );
        assert!(
            policy
                .check(&data, &name("/other/KEY/k1"), 0)
                .await
                .is_deny(),
            "hierarchical checker must reject cross-namespace signers"
        );
    }

    #[tokio::test]
    async fn validator_config_first_matching_rule_wins() {
        let policy = ConfigPolicy::new(vec![
            ConfigRule::new(
                name("/app"),
                ConfigChecker::key_locator_prefix(name("/denied/KEY")),
            ),
            ConfigRule::new(
                name("/app"),
                ConfigChecker::key_locator_prefix(name("/allowed/KEY")),
            ),
        ]);
        let data = make_data("/app/data");
        assert!(
            policy
                .check(&data, &name("/allowed/KEY/k1"), 0)
                .await
                .is_deny(),
            "later matching rules must not rescue a failed first match"
        );
    }
}
