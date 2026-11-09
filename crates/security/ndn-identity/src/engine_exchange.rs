//! A [`CaExchange`] over an engine's in-process app consumer: the transport
//! the engine-bound onboarding calls ([`crate::adopt`], [`crate::invite`])
//! use, so their Interests are forwarded by the engine's FIB like any app's.

use std::time::Duration;

use bytes::Bytes;
use ndn_app::{AppError, Consumer, EngineAppExt, ForwarderEngine};
use ndn_cert::{CaExchange, CertError};
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, Interest, NackReason, Refusal};
use tokio_util::sync::{CancellationToken, DropGuard};

/// How many times in all [`EngineExchange::fetching`] asks for one signed
/// packet, counting asks answered by a copy the engine refused as
/// [`Refusal::BadSignature`] (forged or altered on the way: the faulty
/// network of the data-layer spec §18.1 alters 5% of packets).
const FETCH_TRIES: u32 = 8;

/// How many asks of one signed packet nothing at all answers end
/// [`EngineExchange::fetching`]'s fetch with no answer (trust-context spec
/// §8.1). Inside each ask the Interest is expressed again every
/// [`REEXPRESS_GAP`] while its lifetime lasts, so on the faulty network of
/// the data-layer spec §18.1 an ask goes unanswered under one time in
/// twenty and three asks under one in ten thousand; a path down costs
/// three Interest lifetimes (some 15 s).
const NO_ANSWER_ASKS: u32 = 3;

/// The wait before an unanswered plain fetch is expressed again inside its
/// ask: longer than a forwarder's retransmission suppression holds back a
/// fresh-nonce Interest from the same face (NFD caps it at 250 ms), and
/// than a round trip over the faulty network of the data-layer spec §18.1
/// (400 ms of delay each way). An earlier Interest stays pending, so a
/// late answer to it counts as well.
const REEXPRESS_GAP: Duration = Duration::from_secs(1);

/// The least of an ask's lifetime that must be left for one more
/// expression inside it.
const REEXPRESS_MIN_LEFT: Duration = Duration::from_millis(250);

/// The consumer face lives as long as this value (its face is torn down on
/// drop).
pub(crate) struct EngineExchange {
    consumer: Consumer,
    _face: DropGuard,
    /// How many times a plain fetch is asked ([`Self::fetching`]); 1 for an
    /// exchange that may carry commands.
    tries: u32,
}

impl EngineExchange {
    /// An exchange that asks each Interest once: a request to a CA is a
    /// command, never repeated behind its caller's back.
    pub(crate) fn new(engine: &ForwarderEngine) -> Self {
        let cancel = CancellationToken::new();
        Self {
            consumer: engine.app_consumer(cancel.clone()),
            _face: cancel.drop_guard(),
            tries: 1,
        }
    }

    /// An exchange for fetching signed packets by name (a trust context's
    /// versions and its metadata): a plain Interest — no parameters, no
    /// signature — is expressed again with a fresh nonce every
    /// [`REEXPRESS_GAP`] while its lifetime lasts (one ask), so a lost
    /// packet costs a gap, not a lifetime. An ask nothing answered is asked
    /// again, up to [`NO_ANSWER_ASKS`] of them, and an ask answered by a
    /// copy this engine refused as [`Refusal::BadSignature`] (forged or
    /// altered on the way: it says nothing of the name) at once, up to
    /// [`FETCH_TRIES`] asks in all. Asking again for a signed packet is
    /// idempotent; a copy that does not verify is never taken.
    pub(crate) fn fetching(engine: &ForwarderEngine) -> Self {
        Self {
            tries: FETCH_TRIES,
            ..Self::new(engine)
        }
    }
}

/// Whether `interest` may be asked again behind its caller's back: a plain
/// fetch by name, carrying no parameters and no signature.
fn plain(interest: &Interest) -> bool {
    interest.app_parameters().is_none() && interest.sig_info().is_none()
}

/// The plain `interest` expressed again: the same Interest, built anew so it
/// carries a fresh nonce and no forwarder takes it for the one that looped.
/// Its lifetime is the ask's ([`Consumer::fetch_reexpressing`]).
fn asked_again(interest: &Interest) -> InterestBuilder {
    let mut b = InterestBuilder::new((*interest.name).clone());
    let selectors = interest.selectors();
    if selectors.can_be_prefix {
        b = b.can_be_prefix();
    }
    if selectors.must_be_fresh {
        b = b.must_be_fresh();
    }
    if let Some(h) = interest.hop_limit() {
        b = b.hop_limit(h);
    }
    if let Some(hints) = interest.forwarding_hint() {
        b = b.forwarding_hint(hints.iter().map(|h| (**h).clone()).collect());
    }
    b
}

impl CaExchange for EngineExchange {
    /// Waits as long as the Interest lives (its InterestLifetime, at least
    /// the consumer's default timeout): a held Interest (a request's status)
    /// is answered late on purpose. A [`fetching`](EngineExchange::fetching)
    /// exchange expresses a plain Interest again inside its lifetime and
    /// asks again while nothing answers or what answers is a copy that does
    /// not verify, within its bounds.
    async fn express(&mut self, interest: Bytes) -> Result<Data, CertError> {
        let decoded = Interest::decode(interest.clone()).ok();
        let name = decoded
            .as_ref()
            .map(|i| i.name.to_string())
            .unwrap_or_default();
        let timeout = decoded
            .as_ref()
            .and_then(|i| i.lifetime())
            .map_or(ndn_app::DEFAULT_TIMEOUT, |l| {
                l.max(ndn_app::DEFAULT_TIMEOUT)
            });
        // Only a fetching exchange asks a plain Interest again, each time
        // with a new nonce.
        let again = decoded.as_ref().filter(|i| self.tries > 1 && plain(i));
        let (mut tried, mut unanswered) = (0, 0);
        loop {
            tried += 1;
            let got = match again {
                Some(i) => self
                    .consumer
                    .fetch_reexpressing(
                        || asked_again(i),
                        timeout,
                        REEXPRESS_MIN_LEFT,
                        std::iter::repeat(REEXPRESS_GAP),
                    )
                    .await
                    .map(|(data, _)| data),
                None => self.consumer.fetch_wire(interest.clone(), timeout).await,
            };
            match got {
                Ok(data) => return Ok(data),
                Err(AppError::Timeout)
                    if again.is_some() && tried < self.tries && unanswered + 1 < NO_ANSWER_ASKS =>
                {
                    unanswered += 1;
                }
                Err(AppError::Refused {
                    reason: Refusal::BadSignature,
                }) if again.is_some() && tried < self.tries => {}
                Err(e) => {
                    return Err(match e {
                        AppError::Refused { reason } => CertError::Refused { name, reason },
                        AppError::Nacked {
                            reason: Some(NackReason::NoRoute),
                        } => {
                            CertError::Transport(format!("this forwarder has no route for {name}"))
                        }
                        AppError::Nacked {
                            reason: Some(NackReason::Congestion),
                        } => CertError::Transport(format!(
                            "{name} was Nacked (Congestion): the CA, or a forwarder on the way, \
                             takes no more such Interests now; ask again later"
                        )),
                        AppError::Timeout => CertError::Transport(format!(
                            "no answer to {name} within {:.1} s{}",
                            timeout.as_secs_f32(),
                            if again.is_some() {
                                format!(
                                    ", asked {tried} times, each expressed again every {} s",
                                    REEXPRESS_GAP.as_secs()
                                )
                            } else {
                                String::new()
                            }
                        )),
                        e => CertError::Transport(format!("{name}: {e}")),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    use ndn_app::{EngineBuilder, ShutdownHandle};
    use ndn_engine::EngineConfig;
    use ndn_face::local::InProcFace;
    use ndn_packet::Name;
    use ndn_packet::encode::DataBuilder;
    use ndn_security::SecurityProfile;
    use ndn_transport::FaceKind;

    /// An engine routing `/ns` out a non-local face whose far end answers
    /// the `nth` Interest it receives (from 0) when `answers(nth)`; how
    /// many it received.
    async fn upstream(
        answers: fn(u32) -> bool,
    ) -> (
        ForwarderEngine,
        ShutdownHandle,
        Arc<AtomicU32>,
        CancellationToken,
    ) {
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .security_profile(SecurityProfile::Disabled)
            .build()
            .await
            .unwrap();
        let cancel = CancellationToken::new();
        let id = engine.faces().alloc_id();
        let (face, handle) = InProcFace::new_kind(id, 256, FaceKind::Udp);
        engine.add_face(face, cancel.child_token());
        engine
            .fib()
            .add_nexthop(&"/ns".parse::<Name>().unwrap(), id, 0);
        let asked = Arc::new(AtomicU32::new(0));
        let count = Arc::clone(&asked);
        tokio::spawn(async move {
            while let Some(wire) = handle.recv().await {
                // A non-local face may carry the Interest in an LP frame.
                let wire = if ndn_packet::lp::is_lp_packet(&wire) {
                    ndn_packet::lp::LpPacket::decode(wire)
                        .ok()
                        .and_then(|lp| lp.fragment)
                } else {
                    Some(wire)
                };
                let Some(Ok(interest)) = wire.map(Interest::decode) else {
                    continue;
                };
                if answers(count.fetch_add(1, Ordering::Relaxed)) {
                    let data =
                        DataBuilder::new((*interest.name).clone(), b"v").sign_digest_sha256();
                    let _ = handle.send(data).await;
                }
            }
        });
        (engine, shutdown, asked, cancel)
    }

    fn plain_fetch() -> Bytes {
        InterestBuilder::new("/ns/x".parse::<Name>().unwrap()).build()
    }

    #[tokio::test]
    async fn a_fetch_nothing_answers_ends_after_its_asks_with_no_answer() {
        let (engine, shutdown, asked, cancel) = upstream(|_| false).await;
        let mut exchange = EngineExchange::fetching(&engine);
        let began = Instant::now();
        let got = exchange.express(plain_fetch()).await;
        let took = began.elapsed();
        assert!(matches!(got, Err(CertError::Transport(_))), "{got:?}");
        let ask = ndn_app::DEFAULT_TIMEOUT + Duration::from_secs(1);
        assert!(
            took < ask * NO_ANSWER_ASKS,
            "a path nothing answers on costs {NO_ANSWER_ASKS} asks, not more: {took:?}"
        );
        assert!(
            asked.load(Ordering::Relaxed) > NO_ANSWER_ASKS,
            "each ask is expressed again inside its lifetime"
        );
        drop(exchange);
        cancel.cancel();
        shutdown.shutdown().await;
    }

    #[tokio::test]
    async fn a_fetch_whose_first_interests_are_lost_is_answered_inside_one_lifetime() {
        let (engine, shutdown, _, cancel) = upstream(|nth| nth >= 2).await;
        let mut exchange = EngineExchange::fetching(&engine);
        let began = Instant::now();
        let got = exchange.express(plain_fetch()).await;
        let took = began.elapsed();
        assert!(got.is_ok(), "{got:?}");
        assert!(
            took < ndn_app::DEFAULT_TIMEOUT,
            "a lost Interest costs a re-expression gap, not a lifetime: {took:?}"
        );
        drop(exchange);
        cancel.cancel();
        shutdown.shutdown().await;
    }
}
