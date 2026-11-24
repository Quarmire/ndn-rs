//! What the joiner's tests add to the kit (`test_kit.rs`): a face a test can look into,
//! filter, hold back and tamper with. A device's node face passes through a [`Gate`]
//! ([`Setup::wrapping`](crate::test_kit::Setup::wrapping)): every Interest the device
//! sends is recorded and may be dropped, held or refused a route, and every Data it
//! receives is recorded and may be rewritten.
//!
//! Owner: InviteJoin.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{AppError, Connection};
use ndn_foundation_types::{Name, tlv_type};
use ndn_heap::Config;
use ndn_packet::Interest;
use tokio::sync::Notify;

/// The heap layer's tuning of the joiner's cases: a short first look and settle, and an
/// Interest lifetime a dropped Interest is waited out in half a second.
pub(crate) fn kit_config() -> Config {
    let mut c = Config::new();
    c.first_look = Duration::from_millis(50);
    c.settle = Duration::from_millis(50);
    c.lifetime = Duration::from_millis(500);
    c
}

/// Whether `name` has a keyword component `word`.
fn has_keyword(name: &Name, word: &[u8]) -> bool {
    name.components()
        .iter()
        .any(|c| c.typ == tlv_type::KEYWORD && c.value.as_ref() == word)
}

/// Whether `name` is of the data layer's entries: a log entry, or one held for a relay.
pub(crate) fn is_log(name: &Name) -> bool {
    has_keyword(name, b"log") || has_keyword(name, b"held")
}

/// Whether `name` is of an epoch key's pull: a grant, or a device's seal key.
pub(crate) fn is_key(name: &Name) -> bool {
    has_keyword(name, b"grant") || has_keyword(name, b"seal")
}

/// Whether `name` is of the entries or keys of a space.
pub(crate) fn is_log_or_key(name: &Name) -> bool {
    is_log(name) || is_key(name)
}

/// What a face sent: an Interest's name and the relays of its ForwardingHint.
pub(crate) type Sent = (Name, Vec<Name>);

/// A function over a packet received: the packet the device is given, or `None` for
/// nothing.
pub(crate) type Tamper = Arc<dyn Fn(Bytes) -> Option<Bytes> + Send + Sync>;

/// Whether a name (with the relays of its ForwardingHint) is carried.
pub(crate) type Route = Arc<dyn Fn(&Name, &[Name]) -> bool + Send + Sync>;

/// A name predicate.
type Names = Arc<dyn Fn(&Name) -> bool + Send + Sync>;

#[derive(Default)]
struct State {
    sent: Vec<Sent>,
    refused: Vec<Name>,
    received: Vec<Bytes>,
    drop: Option<Names>,
    hold: Option<Names>,
    route: Option<Route>,
    tamper: Option<Tamper>,
}

/// What a device's face is made to do: see the module's words.
pub(crate) struct Gate {
    state: std::sync::Mutex<State>,
    released: AtomicBool,
    release: Notify,
    held: AtomicUsize,
    held_one: Notify,
}

impl Gate {
    /// A gate that records and carries everything.
    pub(crate) fn new() -> Arc<Gate> {
        Arc::new(Gate {
            state: std::sync::Mutex::new(State::default()),
            released: AtomicBool::new(false),
            release: Notify::new(),
            held: AtomicUsize::new(0),
            held_one: Notify::new(),
        })
    }

    /// `face` behind this gate.
    pub(crate) fn wrap(self: &Arc<Self>, face: Arc<dyn Connection>) -> Arc<dyn Connection> {
        Arc::new(Gated {
            gate: Arc::clone(self),
            face,
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    /// Drop every Interest whose name `f` says so: it is never sent, and its asker waits
    /// out its lifetime.
    pub(crate) fn drop_names(&self, f: impl Fn(&Name) -> bool + Send + Sync + 'static) {
        self.state().drop = Some(Arc::new(f));
    }

    /// Hold every Interest whose name `f` says so, until [`release`](Self::release).
    pub(crate) fn hold_names(&self, f: impl Fn(&Name) -> bool + Send + Sync + 'static) {
        self.state().hold = Some(Arc::new(f));
    }

    /// Carry only the Interests `f` says so (a name and the relays its ForwardingHint
    /// names); the others are recorded as [`refused`](Self::refused) and not sent.
    pub(crate) fn route(&self, f: impl Fn(&Name, &[Name]) -> bool + Send + Sync + 'static) {
        self.state().route = Some(Arc::new(f));
    }

    /// Replace every Data received by what `f` makes of its wire.
    pub(crate) fn tamper(&self, f: impl Fn(Bytes) -> Option<Bytes> + Send + Sync + 'static) {
        self.state().tamper = Some(Arc::new(f));
    }

    /// Let go what is held, and hold nothing more.
    pub(crate) fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        self.release.notify_waiters();
    }

    /// Return once an Interest is held.
    pub(crate) async fn wait_held(&self) {
        loop {
            let held = self.held_one.notified();
            if self.held.load(Ordering::SeqCst) > 0 {
                return;
            }
            held.await;
        }
    }

    /// Every Interest sent so far, in order.
    pub(crate) fn sent(&self) -> Vec<Sent> {
        self.state().sent.clone()
    }

    /// The names sent that `f` says so.
    pub(crate) fn sent_where(&self, f: impl Fn(&Name) -> bool) -> Vec<Name> {
        self.state()
            .sent
            .iter()
            .map(|(n, _)| n.clone())
            .filter(|n| f(n))
            .collect()
    }

    /// The Interests a [`route`](Self::route) did not carry.
    pub(crate) fn refused(&self) -> Vec<Name> {
        self.state().refused.clone()
    }

    /// Every Data received so far, as it arrived.
    pub(crate) fn received(&self) -> Vec<Bytes> {
        self.state().received.clone()
    }
}

/// A face behind a [`Gate`].
struct Gated {
    gate: Arc<Gate>,
    face: Arc<dyn Connection>,
}

#[async_trait::async_trait]
impl Connection for Gated {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        let Ok(interest) = Interest::decode(wire.clone()) else {
            // What the device answers the others' Interests with.
            return self.face.send(wire).await;
        };
        let name: Name = (*interest.name).clone();
        let hints: Vec<Name> = interest
            .forwarding_hint()
            .map(|h| h.iter().map(|n| (**n).clone()).collect())
            .unwrap_or_default();
        let (dropped, held, routed) = {
            let mut st = self.gate.state();
            st.sent.push((name.clone(), hints.clone()));
            let dropped = st.drop.as_ref().is_some_and(|f| f(&name));
            let held = st.hold.as_ref().is_some_and(|f| f(&name));
            let routed = st.route.as_ref().is_none_or(|f| f(&name, &hints));
            if !routed {
                st.refused.push(name.clone());
            }
            (dropped, held, routed)
        };
        if dropped || !routed {
            return Ok(());
        }
        if held && !self.gate.released.load(Ordering::SeqCst) {
            self.gate.held.fetch_add(1, Ordering::SeqCst);
            self.gate.held_one.notify_waiters();
            loop {
                let released = self.gate.release.notified();
                if self.gate.released.load(Ordering::SeqCst) {
                    break;
                }
                released.await;
            }
        }
        // The relay a hint names is the case's to model (the route above decides whether
        // it carries); the forwarder here has none, so what is carried goes on by its
        // name, as a forwarder sends an Interest on once its hint reached a producer
        // region.
        let wire = ndn_packet::interest::strip_forwarding_hint(&wire).unwrap_or(wire);
        self.face.send(wire).await
    }

    async fn recv(&self) -> Option<Bytes> {
        loop {
            let wire = self.face.recv().await?;
            if Interest::decode(wire.clone()).is_ok() {
                return Some(wire);
            }
            let tamper = {
                let mut st = self.gate.state();
                st.received.push(wire.clone());
                st.tamper.clone()
            };
            match tamper {
                None => return Some(wire),
                Some(f) => {
                    if let Some(w) = f(wire) {
                        return Some(w);
                    }
                }
            }
        }
    }

    async fn register_prefix(&self, prefix: &Name) -> Result<(), AppError> {
        self.face.register_prefix(prefix).await
    }
}

/// The members entry the answer a gate's device received named as the one that admitted
/// it (`ADMITTED`), if it received an acceptance.
pub(crate) fn admitted_in(gate: &Gate) -> Option<ndn_heap::EntryId> {
    gate.received().into_iter().find_map(|wire| {
        let data = ndn_packet::Data::decode(wire).ok()?;
        crate::wire::parse_intro_name(&data.name)?;
        let answer = crate::wire::AnswerBody::decode(data.content()?.clone()).ok()?;
        match answer.outcome {
            crate::wire::Outcome::Accepted { admitted, .. } => admitted,
            crate::wire::Outcome::Refused(_) => None,
        }
    })
}

/// `built` as `who` signs it with its own key, whatever the name (a tamperer's signature:
/// the node itself signs only the names of its own device).
pub(crate) fn sign_as(
    who: &crate::test_kit::Device,
    built: ndn_packet::encode::DataBuilder,
) -> Option<Bytes> {
    let identity = who.keys.signing_identity_for(&who.name).ok()?;
    let key = identity.signer.key_name().clone();
    Some(
        built.sign_sync(identity.signer.sig_type(), Some(&key), |region| {
            identity.signer.sign_sync(region).unwrap_or_default()
        }),
    )
}
