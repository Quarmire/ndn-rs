//! Members' namespaces adopted for their folders (spec §6.3). A device
//! adopts by name — version 1 fetched and checked as the genesis the name
//! hashes, the newest reached from it — every self-certifying namespace
//! (`/user/<0xA1: …>`) that an owner-signed members record in force here
//! lists as a writer, or keeps by a removal cut, and that its node does not
//! hold. It judges with it exactly that namespace's packets about the
//! subjects (folders, collections) whose records list it: log entries of
//! collections under them, and the summary nodes on the way to them. The
//! adoption is the host's ([`crate::intro::Introducer::adopt_scoped`]) and goes into no
//! keyring the node judges by; the device judges through a view of its
//! validator ([`Validator::scoped_view`]) that no other path sees. A held
//! context of the namespace is used as is, and never replaced.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use ndn_packet::Name;
use ndn_security::self_certifying::personal_namespace_of;
use ndn_security::{ScopedContext, Validator};

use super::{Inner, Rejudge, refuses_more};
use crate::collection::Members;
use crate::rt::{self, Instant};
use crate::wire::{
    namespace_of, parse_entry_name, parse_head_name, parse_log_name, parse_piece_name,
    parse_summary_name,
};

/// The first pause before a namespace the host could not adopt is asked
/// again; it doubles on each refusal, up to [`SCOPE_PAUSE_MAX`].
const SCOPE_PAUSE: Duration = Duration::from_secs(2);

/// The longest pause between two asks for one namespace.
const SCOPE_PAUSE_MAX: Duration = Duration::from_secs(64);

/// The most namespaces the host adopts at once for this device: a record
/// listing many writers, or unreachable ones, costs at most this many
/// adoptions in flight (each bounded by the walk's limits), the others
/// waiting their turn.
pub(super) const SCOPE_ASKS: usize = 4;

/// What a packet is about, for the scope that judges it: its subject (the
/// collection of a log entry, a head or a piece; the node of a summary) and
/// whether, as a summary node, it may also lie on the way to a scope.
pub(super) struct About {
    subject: Name,
    toward: bool,
}

/// What the packet named `name` is about, if it is a packet a scope may
/// judge: a log entry of a collection (its pieces, its block entries), a
/// one-key head, or a summary root, node or page. Nothing else — a
/// snapshot, a seal key, a grant — is about a folder.
pub(super) fn about(name: &Name) -> Option<About> {
    let of_entry = |entry: &Name| {
        parse_log_name(entry)?.subject.map(|subject| About {
            subject,
            toward: false,
        })
    };
    if let Some(s) = parse_summary_name(name) {
        return Some(About {
            subject: s.subject,
            toward: true,
        });
    }
    if let Some((_, collection, _)) = parse_head_name(name) {
        return Some(About {
            subject: collection,
            toward: false,
        });
    }
    if let Some(a) = of_entry(name) {
        return Some(a);
    }
    if let Some(p) = parse_piece_name(name) {
        return of_entry(&p.version);
    }
    parse_entry_name(name).and_then(|(version, _)| of_entry(&version))
}

/// A person's namespace a record in force lists, as adopted here.
enum Adopted {
    /// The host is adopting it.
    Asking,
    /// Adopted: the context, and the view of the device's validator that
    /// judges by it.
    Held {
        ctx: ScopedContext,
        judge: Arc<Validator>,
    },
    /// The host could not adopt it (it said why, logged): when to ask
    /// again, and the pause that led there.
    Refused { again: Instant, pause: Duration },
}

/// The persons' namespaces the records in force list, and what is adopted
/// of them (spec §6.3).
#[derive(Default)]
pub(super) struct Scopes {
    /// Per person's namespace, the subjects whose own record in force lists
    /// a writer prefix, or a cut, in it.
    listed: BTreeMap<Name, BTreeSet<Name>>,
    adopted: HashMap<Name, Adopted>,
    /// Held namespaces a new record listed since their last adoption: they
    /// are refreshed (by continuity from the version held).
    stale: BTreeSet<Name>,
    /// Held namespaces being refreshed (judging goes on with what is held).
    refreshing: BTreeSet<Name>,
}

impl Scopes {
    /// The subject `s`'s own record in force is now `own` (`None`: it has
    /// none): note the persons' namespaces it lists, by its writer prefixes
    /// and the prefixes of its cuts. A namespace it lists that is adopted
    /// already is refreshed: a new record is where a writer's newer version
    /// (a recovery, a revocation) is looked for.
    pub(super) fn note(&mut self, s: &Name, own: Option<&Members>) {
        for subjects in self.listed.values_mut() {
            subjects.remove(s);
        }
        self.listed.retain(|_, subjects| !subjects.is_empty());
        let Some(m) = own else {
            return;
        };
        let prefixes = m.writers.iter().chain(m.cuts.iter().map(|c| &c.of));
        for ns in prefixes.filter_map(personal_namespace_of) {
            if matches!(self.adopted.get(&ns), Some(Adopted::Held { .. })) {
                self.stale.insert(ns.clone());
            }
            self.listed.entry(ns).or_default().insert(s.clone());
        }
    }

    /// The view judging a packet of `ns`, a person's namespace no context
    /// held covers, that is `about` this: the scoped one when a record in
    /// force lists `ns` for a subject the packet lies in — or, for a summary
    /// node, lies on the way to — and `ns` is adopted; else `None` (the
    /// device's own validator, which refuses it).
    fn judge(&self, ns: &Name, about: &About) -> Option<Arc<Validator>> {
        let inside =
            self.listed.get(ns)?.iter().any(|s| {
                about.subject.has_prefix(s) || (about.toward && s.has_prefix(&about.subject))
            });
        match self.adopted.get(ns) {
            Some(Adopted::Held { judge, .. }) if inside => Some(Arc::clone(judge)),
            _ => None,
        }
    }

    /// What to ask the host for now: each namespace listed that the node
    /// does not hold (`held`), not adopted, not being adopted and past its
    /// pause — and each adopted one a new record listed — while fewer than
    /// [`SCOPE_ASKS`] adoptions are in flight; each with the version held,
    /// to refresh from. Marks them in flight.
    fn asks_due(
        &mut self,
        held: impl Fn(&Name) -> bool,
        now: Instant,
    ) -> Vec<(Name, Option<ScopedContext>)> {
        let mut flying = self.refreshing.len()
            + self
                .adopted
                .values()
                .filter(|a| matches!(a, Adopted::Asking))
                .count();
        let mut out = Vec::new();
        for ns in self.listed.keys() {
            if flying >= SCOPE_ASKS {
                break;
            }
            if held(ns) {
                continue;
            }
            let ask = match self.adopted.get(ns) {
                None => Some(None),
                Some(Adopted::Refused { again, .. }) if *again <= now => Some(None),
                Some(Adopted::Held { ctx, .. })
                    if self.stale.contains(ns) && !self.refreshing.contains(ns) =>
                {
                    Some(Some(ctx.clone()))
                }
                _ => None,
            };
            let Some(from) = ask else {
                continue;
            };
            flying += 1;
            out.push((ns.clone(), from));
        }
        for (ns, from) in &out {
            match from {
                Some(_) => {
                    self.stale.remove(ns);
                    self.refreshing.insert(ns.clone());
                }
                None => {
                    self.adopted.insert(ns.clone(), Adopted::Asking);
                }
            }
        }
        out
    }

    /// The adopted namespaces no record in force lists any more, or that
    /// the node now holds (its held context judges them from now on):
    /// dropped here, for the host to release.
    fn release_unlisted(&mut self, held: impl Fn(&Name) -> bool) -> Vec<Name> {
        let gone: Vec<Name> = self
            .adopted
            .iter()
            .filter(|(ns, a)| {
                matches!(a, Adopted::Held { .. }) && (!self.listed.contains_key(*ns) || held(ns))
            })
            .map(|(ns, _)| ns.clone())
            .collect();
        for ns in &gone {
            self.adopted.remove(ns);
            self.stale.remove(ns);
        }
        // A refusal no record calls for any more is forgotten.
        let listed = &self.listed;
        self.adopted
            .retain(|ns, a| !matches!(a, Adopted::Refused { .. }) || listed.contains_key(ns));
        gone
    }
}

impl Inner {
    /// The validator that judges the packet named `name`: for a packet of a
    /// person's namespace the node does not hold, about a subject a record
    /// in force lists that namespace for, the view adopted for it (spec
    /// §6.3); else the device's own, which judges every other packet — and
    /// refuses that namespace's packets about anything else.
    pub(super) fn judge(&self, name: &Name) -> Arc<Validator> {
        let scoped = self
            .validator
            .keyring()
            .unheld_personal_namespace(name)
            .and_then(|ns| Some((ns, about(name)?)))
            .and_then(|(ns, about)| self.st.lock().scopes.judge(&ns, &about));
        scoped.unwrap_or_else(|| Arc::clone(&self.validator))
    }

    /// Ask the host to adopt, for their scopes, the persons' namespaces the
    /// records in force list that the node does not hold (and to refresh
    /// those a new record listed), and to release those nothing lists any
    /// more (spec §6.3). Without a host that adopts, they are not adopted,
    /// and the records' versions of those writers wait, refused here.
    pub(super) fn scope_writers(self: &Arc<Self>) {
        let keyring = self.validator.keyring();
        let held = |ns: &Name| keyring.held_for(ns).is_some();
        let (asks, released) = {
            let mut st = self.st.lock();
            let released = st.scopes.release_unlisted(held);
            (st.scopes.asks_due(held, Instant::now()), released)
        };
        if asks.is_empty() && released.is_empty() {
            return;
        }
        let Some(host) = self.config.introducer.clone() else {
            for (ns, from) in asks {
                self.scoped(
                    &ns,
                    from,
                    Err(format!(
                        "a members record lists {ns} as a writer, and this device has no host \
                         to adopt it for the folder (Config::introducer): configure one and \
                         start the device again, or adopt {ns} on its node"
                    )),
                );
            }
            return;
        };
        for ns in released {
            tracing::info!(me = %self.device, %ns, "no members record lists it any more, or the node holds it: released");
            host.release_scoped(&ns);
        }
        for (ns, from) in asks {
            let inner = Arc::clone(self);
            let host = Arc::clone(&host);
            rt::spawn(async move {
                let got = host.adopt_scoped(&ns, from.as_ref()).await;
                let refuses = inner.scoped(&ns, from, got);
                inner.adopted_scoped(&ns, refuses).await;
            });
        }
    }

    /// Take the host's answer for `ns`, adopted from `from` (the version
    /// held, for a refresh): whether the version now held may refuse more
    /// than the one before it, if one is held now. A refusal keeps a
    /// version held before (judging goes on with it) and is asked again
    /// after a pause.
    fn scoped(
        self: &Arc<Self>,
        ns: &Name,
        from: Option<ScopedContext>,
        got: Result<ScopedContext, String>,
    ) -> Option<bool> {
        let mut st = self.st.lock();
        st.scopes.refreshing.remove(ns);
        let listed = st.scopes.listed.contains_key(ns);
        match got {
            Ok(ctx) if listed => {
                let refuses = refuses_more(from.as_ref().map(|f| &**f.context()), ctx.context());
                tracing::info!(me = %self.device, %ns, version = ctx.context().version(), "adopted by name for judging the data of the folders that list it as a writer");
                let judge = Arc::new(self.validator.scoped_view(&ctx));
                st.scopes
                    .adopted
                    .insert(ns.clone(), Adopted::Held { ctx, judge });
                Some(refuses)
            }
            // Adopted after the last record listing it went: released.
            Ok(_) => {
                st.scopes.adopted.remove(ns);
                drop(st);
                if let Some(host) = &self.config.introducer {
                    host.release_scoped(ns);
                }
                None
            }
            Err(why) => {
                if from.is_some() {
                    // A refresh that failed: the version held still judges.
                    tracing::debug!(me = %self.device, %ns, "not refreshed: {why}");
                    st.scopes.stale.insert(ns.clone());
                    return None;
                }
                let pause = match st.scopes.adopted.get(ns) {
                    Some(Adopted::Refused { pause, .. }) => (*pause * 2).min(SCOPE_PAUSE_MAX),
                    _ => SCOPE_PAUSE,
                };
                tracing::warn!(me = %self.device, %ns, "a members record lists it as a writer, and it is not adopted for the folder: {why}; its versions there wait, and it is asked again in {pause:?}");
                st.scopes.adopted.insert(
                    ns.clone(),
                    Adopted::Refused {
                        again: Instant::now() + pause,
                        pause,
                    },
                );
                drop(st);
                let inner = Arc::clone(self);
                rt::spawn(async move {
                    rt::sleep(pause).await;
                    inner.scope_writers();
                });
                None
            }
        }
    }

    /// Once `ns` is adopted for its scopes (`refuses`: whether the version
    /// may refuse more than the one before), what is held of it is judged
    /// again, and the summaries of every namespace whose subjects list it
    /// are refreshed, so what was refused for want of it is fetched again.
    /// Then the next namespaces waiting are asked for.
    async fn adopted_scoped(self: &Arc<Self>, ns: &Name, refuses: Option<bool>) {
        if let Some(refuses) = refuses {
            self.rejudge(match refuses {
                true => Rejudge::Namespace(ns.clone()),
                false => Rejudge::Withdrawn(None),
            })
            .await;
            let owners: BTreeSet<Name> = self
                .st
                .lock()
                .scopes
                .listed
                .get(ns)
                .into_iter()
                .flatten()
                .filter_map(namespace_of)
                .collect();
            for o in owners {
                self.refresh_group(&o);
            }
        }
        self.scope_writers();
    }
}
