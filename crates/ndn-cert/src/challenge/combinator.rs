//! Composite challenges. The requester picks one sub per CHALLENGE round
//! via a `subchallenge` parameter (`"0"`, `"1"`, ...).
//!
//! * [`AllOf`] — every sub must pass (e.g. token AND email).
//! * [`AnyOf`] — first sub to pass wins (e.g. token OR possession).
//! * [`NofM`] — any `n` of the subs must pass (e.g. 2 of {token, email,
//!   device-approval}).
//!
//! Each satisfied sub contributes its own attestation leaf, so the issued
//! cert records exactly which sub-challenges were met (and their evidence),
//! tagged with the composite's [`Combinator`] shape.

use std::{future::Future, pin::Pin};

use crate::{
    attestation::{AttestationSet, ChallengeAttestation, Combinator},
    challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState, leaves_or_default},
    error::CertError,
    protocol::CertRequest,
};

fn read_completed(state: &ChallengeState) -> Vec<bool> {
    state
        .data
        .get("completed")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(|b| b.as_bool().unwrap_or(false)).collect())
        .unwrap_or_default()
}

/// Read the attestation leaves accumulated from subs satisfied in prior
/// rounds. Malformed/absent state yields an empty list.
fn read_leaves(state: &ChallengeState) -> Vec<ChallengeAttestation> {
    state
        .data
        .get("leaves")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default()
}

fn write_progress(state: &mut ChallengeState, completed: &[bool], leaves: &[ChallengeAttestation]) {
    let completed_arr: Vec<serde_json::Value> = completed
        .iter()
        .map(|b| serde_json::Value::Bool(*b))
        .collect();
    let obj = match state.data.as_object_mut() {
        Some(obj) => obj,
        None => {
            state.data = serde_json::json!({});
            state.data.as_object_mut().expect("just set to object")
        }
    };
    obj.insert(
        "completed".to_string(),
        serde_json::Value::Array(completed_arr),
    );
    obj.insert(
        "leaves".to_string(),
        serde_json::to_value(leaves).unwrap_or(serde_json::Value::Null),
    );
}

fn pick_subchallenge_index(
    parameters: &serde_json::Map<String, serde_json::Value>,
    n: usize,
) -> Result<usize, ChallengeOutcome> {
    let raw = match parameters.get("subchallenge") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        _ => {
            return Err(ChallengeOutcome::Denied(format!(
                "missing or non-stringy 'subchallenge' parameter (expected one of 0..{n})"
            )));
        }
    };
    let idx: usize = raw.parse().map_err(|_| {
        ChallengeOutcome::Denied(format!("subchallenge parameter {raw:?} is not an integer"))
    })?;
    if idx >= n {
        return Err(ChallengeOutcome::Denied(format!(
            "subchallenge index {idx} out of range (0..{n})"
        )));
    }
    Ok(idx)
}

/// One CHALLENGE round of a threshold composite (`AllOf` is `required ==
/// total`; `NofM` is `required < total`). Tracks per-sub completion and the
/// satisfied subs' attestation leaves across rounds; on reaching `required`
/// satisfied subs it approves with a `combinator`-tagged [`AttestationSet`].
async fn threshold_round(
    subs: &[Box<dyn ChallengeHandler>],
    state: &ChallengeState,
    parameters: &serde_json::Map<String, serde_json::Value>,
    required: usize,
    label: &str,
    combinator: Combinator,
) -> Result<ChallengeOutcome, CertError> {
    let mut completed = read_completed(state);
    if completed.len() != subs.len() {
        completed = vec![false; subs.len()];
    }
    let mut leaves = read_leaves(state);

    let idx = match pick_subchallenge_index(parameters, subs.len()) {
        Ok(i) => i,
        Err(o) => return Ok(o),
    };
    let sub = &subs[idx];
    let sub_state = ChallengeState {
        challenge_type: sub.challenge_type().to_string(),
        data: serde_json::Value::Null,
    };

    match sub.verify(&sub_state, parameters).await? {
        ChallengeOutcome::Approved { attestation } => {
            if !completed[idx] {
                completed[idx] = true;
                leaves.extend(leaves_or_default(attestation, sub.challenge_type()));
            }
            let satisfied = completed.iter().filter(|b| **b).count();
            if satisfied >= required {
                Ok(ChallengeOutcome::Approved {
                    attestation: Some(AttestationSet::new(combinator, leaves)),
                })
            } else {
                let remaining = required - satisfied;
                let mut next_state = ChallengeState {
                    challenge_type: label.to_string(),
                    data: serde_json::json!({}),
                };
                write_progress(&mut next_state, &completed, &leaves);
                Ok(ChallengeOutcome::Pending {
                    status_message: format!(
                        "Sub-challenge {idx} approved; {remaining} more required"
                    ),
                    remaining_tries: 30,
                    remaining_time_secs: 600,
                    next_state,
                })
            }
        }
        ChallengeOutcome::Denied(r) => Ok(ChallengeOutcome::Denied(format!(
            "{label} sub-challenge {idx} denied: {r}"
        ))),
        ChallengeOutcome::Pending {
            status_message,
            remaining_tries,
            remaining_time_secs,
            next_state: _,
        } => {
            let mut next_state = ChallengeState {
                challenge_type: label.to_string(),
                data: serde_json::json!({}),
            };
            write_progress(&mut next_state, &completed, &leaves);
            Ok(ChallengeOutcome::Pending {
                status_message: format!("sub {idx}: {status_message}"),
                remaining_tries,
                remaining_time_secs,
                next_state,
            })
        }
    }
}

/// All subs must succeed; subs may be completed in any order.
pub struct AllOf {
    subs: Vec<Box<dyn ChallengeHandler>>,
}

impl AllOf {
    pub fn new(subs: Vec<Box<dyn ChallengeHandler>>) -> Self {
        assert!(
            !subs.is_empty(),
            "AllOf must have at least one sub-challenge"
        );
        Self { subs }
    }

    pub fn len(&self) -> usize {
        self.subs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.subs.is_empty()
    }
}

impl ChallengeHandler for AllOf {
    fn challenge_type(&self) -> &'static str {
        "all-of"
    }

    fn begin<'a>(
        &'a self,
        _req: &'a CertRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeState, CertError>> + Send + 'a>> {
        Box::pin(async move {
            let completed: Vec<bool> = vec![false; self.subs.len()];
            Ok(ChallengeState {
                challenge_type: "all-of".to_string(),
                data: serde_json::json!({ "completed": completed }),
            })
        })
    }

    fn verify<'a>(
        &'a self,
        state: &'a ChallengeState,
        parameters: &'a serde_json::Map<String, serde_json::Value>,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeOutcome, CertError>> + Send + 'a>> {
        Box::pin(threshold_round(
            &self.subs,
            state,
            parameters,
            self.subs.len(),
            "all-of",
            Combinator::AllOf,
        ))
    }
}

/// Any `n` of the subs must succeed (`1 <= n <= subs.len()`).
pub struct NofM {
    n: usize,
    subs: Vec<Box<dyn ChallengeHandler>>,
}

impl NofM {
    /// `n` must be in `1..=subs.len()`.
    pub fn new(n: usize, subs: Vec<Box<dyn ChallengeHandler>>) -> Self {
        assert!(!subs.is_empty(), "NofM must have at least one sub-challenge");
        assert!(
            n >= 1 && n <= subs.len(),
            "NofM threshold {n} out of range 1..={}",
            subs.len()
        );
        Self { n, subs }
    }

    pub fn threshold(&self) -> usize {
        self.n
    }

    pub fn len(&self) -> usize {
        self.subs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.subs.is_empty()
    }
}

impl ChallengeHandler for NofM {
    fn challenge_type(&self) -> &'static str {
        "nofm"
    }

    fn begin<'a>(
        &'a self,
        _req: &'a CertRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeState, CertError>> + Send + 'a>> {
        Box::pin(async move {
            let completed: Vec<bool> = vec![false; self.subs.len()];
            Ok(ChallengeState {
                challenge_type: "nofm".to_string(),
                data: serde_json::json!({ "completed": completed }),
            })
        })
    }

    fn verify<'a>(
        &'a self,
        state: &'a ChallengeState,
        parameters: &'a serde_json::Map<String, serde_json::Value>,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeOutcome, CertError>> + Send + 'a>> {
        Box::pin(threshold_round(
            &self.subs,
            state,
            parameters,
            self.n,
            "nofm",
            Combinator::NofM {
                required: self.n,
                total: self.subs.len(),
            },
        ))
    }
}

/// Succeeds as soon as one sub succeeds.
pub struct AnyOf {
    subs: Vec<Box<dyn ChallengeHandler>>,
}

impl AnyOf {
    pub fn new(subs: Vec<Box<dyn ChallengeHandler>>) -> Self {
        assert!(
            !subs.is_empty(),
            "AnyOf must have at least one sub-challenge"
        );
        Self { subs }
    }

    pub fn len(&self) -> usize {
        self.subs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.subs.is_empty()
    }
}

impl ChallengeHandler for AnyOf {
    fn challenge_type(&self) -> &'static str {
        "any-of"
    }

    fn begin<'a>(
        &'a self,
        _req: &'a CertRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeState, CertError>> + Send + 'a>> {
        Box::pin(async move {
            Ok(ChallengeState {
                challenge_type: "any-of".to_string(),
                data: serde_json::Value::Null,
            })
        })
    }

    fn verify<'a>(
        &'a self,
        _state: &'a ChallengeState,
        parameters: &'a serde_json::Map<String, serde_json::Value>,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeOutcome, CertError>> + Send + 'a>> {
        Box::pin(async move {
            let idx = match pick_subchallenge_index(parameters, self.subs.len()) {
                Ok(i) => i,
                Err(o) => return Ok(o),
            };
            let sub = &self.subs[idx];
            let sub_state = ChallengeState {
                challenge_type: sub.challenge_type().to_string(),
                data: serde_json::Value::Null,
            };
            match sub.verify(&sub_state, parameters).await? {
                // The winning sub's own attestation becomes the AnyOf leaf —
                // captured here, where we still know which sub satisfied.
                ChallengeOutcome::Approved { attestation } => {
                    let leaves = leaves_or_default(attestation, sub.challenge_type());
                    Ok(ChallengeOutcome::Approved {
                        attestation: Some(AttestationSet::new(Combinator::AnyOf, leaves)),
                    })
                }
                ChallengeOutcome::Denied(r) => Ok(ChallengeOutcome::Denied(format!(
                    "AnyOf sub-challenge {idx} denied: {r}"
                ))),
                ChallengeOutcome::Pending {
                    status_message,
                    remaining_tries,
                    remaining_time_secs,
                    next_state,
                } => Ok(ChallengeOutcome::Pending {
                    status_message: format!("sub {idx}: {status_message}"),
                    remaining_tries,
                    remaining_time_secs,
                    next_state,
                }),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::CertRequest;

    struct CannedChallenge {
        ty: &'static str,
        approve: bool,
        deny_reason: Option<String>,
        evidence: Option<(String, serde_json::Value)>,
    }

    impl ChallengeHandler for CannedChallenge {
        fn challenge_type(&self) -> &'static str {
            self.ty
        }
        fn begin<'a>(
            &'a self,
            _req: &'a CertRequest,
        ) -> Pin<Box<dyn Future<Output = Result<ChallengeState, CertError>> + Send + 'a>> {
            Box::pin(async move {
                Ok(ChallengeState {
                    challenge_type: self.ty.to_string(),
                    data: serde_json::Value::Null,
                })
            })
        }
        fn verify<'a>(
            &'a self,
            _state: &'a ChallengeState,
            _parameters: &'a serde_json::Map<String, serde_json::Value>,
        ) -> Pin<Box<dyn Future<Output = Result<ChallengeOutcome, CertError>> + Send + 'a>>
        {
            let outcome = if let Some(reason) = &self.deny_reason {
                ChallengeOutcome::Denied(reason.clone())
            } else if self.approve {
                let attestation = self.evidence.as_ref().map(|(k, v)| {
                    AttestationSet::single(
                        ChallengeAttestation::of_kind(self.ty).with_evidence(k.clone(), v.clone()),
                    )
                });
                ChallengeOutcome::Approved { attestation }
            } else {
                ChallengeOutcome::Denied("not configured to approve".to_string())
            };
            Box::pin(async move { Ok(outcome) })
        }
    }

    fn approved(ty: &'static str) -> Box<dyn ChallengeHandler> {
        Box::new(CannedChallenge {
            ty,
            approve: true,
            deny_reason: None,
            evidence: None,
        })
    }

    fn approved_with(
        ty: &'static str,
        key: &str,
        value: serde_json::Value,
    ) -> Box<dyn ChallengeHandler> {
        Box::new(CannedChallenge {
            ty,
            approve: true,
            deny_reason: None,
            evidence: Some((key.to_string(), value)),
        })
    }

    fn denied(ty: &'static str, reason: &'static str) -> Box<dyn ChallengeHandler> {
        Box::new(CannedChallenge {
            ty,
            approve: false,
            deny_reason: Some(reason.to_owned()),
            evidence: None,
        })
    }

    fn dummy_request() -> CertRequest {
        CertRequest {
            name: "/lab/alice".to_owned(),
            public_key: String::new(),
            not_before: 0,
            not_after: 0,
        }
    }

    fn params(s: &str) -> serde_json::Map<String, serde_json::Value> {
        let mut m = serde_json::Map::new();
        m.insert(
            "subchallenge".to_string(),
            serde_json::Value::String(s.to_owned()),
        );
        m
    }

    /// Drive an approved outcome to its attestation set, panicking otherwise.
    fn approved_set(o: ChallengeOutcome) -> AttestationSet {
        match o {
            ChallengeOutcome::Approved { attestation } => {
                attestation.expect("composite must carry an attestation")
            }
            other => panic!("expected Approved, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn all_of_requires_every_sub() {
        let c = AllOf::new(vec![approved("a"), approved("b")]);
        let state = c.begin(&dummy_request()).await.unwrap();
        let first = c.verify(&state, &params("0")).await.unwrap();
        let state_after_first = match first {
            ChallengeOutcome::Pending { next_state, .. } => next_state,
            other => panic!("expected Pending, got {other:?}"),
        };
        let second = c.verify(&state_after_first, &params("1")).await.unwrap();
        assert!(matches!(second, ChallengeOutcome::Approved { .. }));
    }

    #[tokio::test]
    async fn all_of_accumulates_per_sub_leaves() {
        let c = AllOf::new(vec![
            approved_with("token", "token_id", serde_json::json!("t-1")),
            approved_with("email", "addr", serde_json::json!("a@b.c")),
        ]);
        let state = c.begin(&dummy_request()).await.unwrap();
        let next = match c.verify(&state, &params("0")).await.unwrap() {
            ChallengeOutcome::Pending { next_state, .. } => next_state,
            other => panic!("expected Pending, got {other:?}"),
        };
        let set = approved_set(c.verify(&next, &params("1")).await.unwrap());
        assert_eq!(set.combinator, Combinator::AllOf);
        assert_eq!(set.leaves.len(), 2);
        assert_eq!(set.leaves[0].kind, "token");
        assert_eq!(set.leaves[0].evidence.get("token_id").unwrap(), "t-1");
        assert_eq!(set.leaves[1].kind, "email");
        assert_eq!(set.leaves[1].evidence.get("addr").unwrap(), "a@b.c");
    }

    #[tokio::test]
    async fn all_of_propagates_denial() {
        let c = AllOf::new(vec![approved("a"), denied("b", "no good")]);
        let state = c.begin(&dummy_request()).await.unwrap();
        let res = c.verify(&state, &params("1")).await.unwrap();
        match res {
            ChallengeOutcome::Denied(r) => assert!(r.contains("no good")),
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn all_of_rejects_out_of_range_subchallenge() {
        let c = AllOf::new(vec![approved("a")]);
        let state = c.begin(&dummy_request()).await.unwrap();
        let res = c.verify(&state, &params("5")).await.unwrap();
        assert!(matches!(res, ChallengeOutcome::Denied(_)));
    }

    #[tokio::test]
    async fn any_of_short_circuits_on_first_approval() {
        let c = AnyOf::new(vec![denied("a", "nope"), approved("b")]);
        let state = c.begin(&dummy_request()).await.unwrap();
        let res = c.verify(&state, &params("1")).await.unwrap();
        let set = approved_set(res);
        assert_eq!(set.combinator, Combinator::AnyOf);
        assert_eq!(set.leaves.len(), 1);
        assert_eq!(set.leaves[0].kind, "b");
    }

    #[tokio::test]
    async fn any_of_denies_when_chosen_sub_denies() {
        let c = AnyOf::new(vec![denied("a", "nope"), approved("b")]);
        let state = c.begin(&dummy_request()).await.unwrap();
        let res = c.verify(&state, &params("0")).await.unwrap();
        match res {
            ChallengeOutcome::Denied(r) => assert!(r.contains("nope")),
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn any_of_rejects_missing_subchallenge_parameter() {
        let c = AnyOf::new(vec![approved("a")]);
        let state = c.begin(&dummy_request()).await.unwrap();
        let res = c.verify(&state, &serde_json::Map::new()).await.unwrap();
        assert!(matches!(res, ChallengeOutcome::Denied(_)));
    }

    #[tokio::test]
    async fn nofm_approves_after_n_subs() {
        // 2 of 3; satisfy subs 0 and 2.
        let c = NofM::new(2, vec![approved("a"), approved("b"), approved("c")]);
        let state = c.begin(&dummy_request()).await.unwrap();
        let next = match c.verify(&state, &params("0")).await.unwrap() {
            ChallengeOutcome::Pending { next_state, .. } => next_state,
            other => panic!("expected Pending after 1 of 2, got {other:?}"),
        };
        let set = approved_set(c.verify(&next, &params("2")).await.unwrap());
        assert_eq!(set.combinator, Combinator::NofM { required: 2, total: 3 });
        assert_eq!(set.leaves.len(), 2, "exactly the satisfied subs");
        assert_eq!(set.leaves[0].kind, "a");
        assert_eq!(set.leaves[1].kind, "c");
    }

    #[tokio::test]
    async fn nofm_one_round_when_threshold_is_one() {
        let c = NofM::new(1, vec![approved("a"), approved("b")]);
        let state = c.begin(&dummy_request()).await.unwrap();
        let set = approved_set(c.verify(&state, &params("1")).await.unwrap());
        assert_eq!(set.combinator, Combinator::NofM { required: 1, total: 2 });
        assert_eq!(set.leaves.len(), 1);
        assert_eq!(set.leaves[0].kind, "b");
    }

    #[test]
    fn challenge_type_strings_are_stable() {
        let all = AllOf::new(vec![approved("a")]);
        let any = AnyOf::new(vec![approved("a")]);
        let nofm = NofM::new(1, vec![approved("a")]);
        assert_eq!(all.challenge_type(), "all-of");
        assert_eq!(any.challenge_type(), "any-of");
        assert_eq!(nofm.challenge_type(), "nofm");
        assert_eq!(all.len(), 1);
        assert_eq!(any.len(), 1);
        assert_eq!(nofm.threshold(), 1);
    }

    #[test]
    #[should_panic(expected = "at least one")]
    fn all_of_rejects_empty_sub_list() {
        let _ = AllOf::new(vec![]);
    }

    #[test]
    #[should_panic(expected = "at least one")]
    fn any_of_rejects_empty_sub_list() {
        let _ = AnyOf::new(vec![]);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn nofm_rejects_threshold_above_total() {
        let _ = NofM::new(3, vec![approved("a"), approved("b")]);
    }
}
