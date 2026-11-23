//! Epoch keys, sealing and grants (spec §6).
//!
//! Under construction: the module lands behind its `wip-seal` feature.

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn epoch(creator: &str, seq: u64) -> EpochId {
        EpochId {
            creator: n(creator),
            seq,
        }
    }

    fn keys() -> Keys {
        Keys::new(RecipientKey::generate())
    }

    #[test]
    fn a_key_that_fails_the_key_check_is_dropped() {
        let (space, e) = (n("/alice/32=data/notes"), epoch("/alice/laptop", 4));
        let key = ContentKey::generate();
        let named = key_check(&key, &space, &e);
        assert!(accept_key(&named, &space, &e, &key));
        assert!(
            !accept_key(&named, &space, &e, &ContentKey::generate()),
            "another key"
        );
        assert!(
            !accept_key(&named, &n("/alice/32=data/other"), &e, &key),
            "another space"
        );
        assert!(
            !accept_key(&named, &space, &epoch("/alice/laptop", 9), &key),
            "another epoch"
        );
        assert!(
            !accept_key(&named, &space, &epoch("/alice/phone", 4), &key),
            "another creator"
        );

        let mut held = keys();
        assert!(!held.take(&space, &e, &named, ContentKey::generate()));
        assert!(held.key(&space, &e).is_none(), "a failing key is not held");
        assert!(held.take(&space, &e, &named, key.clone()));
        assert_eq!(held.key(&space, &e).unwrap().expose(), key.expose());
        assert!(
            held.key(&n("/alice/32=data/other"), &e).is_none(),
            "a key is held for one space"
        );
        assert!(
            held.key(&space, &epoch("/alice/laptop", 9)).is_none(),
            "a key is held for one epoch"
        );
    }

    #[test]
    fn seal_then_open_round_trips_and_the_aad_binds_the_entry_name() {
        let key = ContentKey::generate();
        let name = n("/alice/laptop/32=log/alice/32=data/notes/seq=5");
        let plain = b"the path and the payload, as TLV".as_slice();
        let stored = seal_payload(&key, &name, plain);
        assert_eq!(
            stored.len(),
            12 + 16 + plain.len(),
            "nonce ‖ tag ‖ ciphertext"
        );
        assert_ne!(&stored[28..], plain, "the payload is not in the clear");
        assert_eq!(open_payload(&key, &name, &stored).as_deref(), Some(plain));
        assert_ne!(
            stored,
            seal_payload(&key, &name, plain),
            "a fresh random nonce each time"
        );

        let other = n("/alice/laptop/32=log/alice/32=data/notes/seq=6");
        assert_eq!(open_payload(&key, &other, &stored), None, "bound to its name");

        let mut flipped = stored.to_vec();
        *flipped.last_mut().unwrap() ^= 1;
        assert_eq!(open_payload(&key, &name, &flipped), None, "tampered");
        assert_eq!(open_payload(&key, &name, &stored[..20]), None, "truncated");
    }

    #[test]
    fn a_wrong_epoch_key_does_not_open() {
        let name = n("/alice/laptop/32=log/alice/32=data/notes/seq=5");
        let stored = seal_payload(&ContentKey::generate(), &name, b"secret");
        assert_eq!(open_payload(&ContentKey::generate(), &name, &stored), None);
    }

    /// A view with each of the four facts a grant needs switchable.
    struct View {
        names: bool,
        audience: bool,
        reads: bool,
        holds: bool,
    }

    impl GrantView for View {
        fn names_epoch(&self, _: &EpochId) -> bool {
            self.names
        }
        fn in_audience(&self, _: &EpochId, _: &Name) -> bool {
            self.audience
        }
        fn reads_now(&self, _: &Name) -> bool {
            self.reads
        }
        fn holds_key(&self, _: &EpochId) -> bool {
            self.holds
        }
    }

    #[test]
    fn may_grant_refuses_each_of_the_four_conditions_and_names_which() {
        let e = epoch("/alice/laptop", 1);
        let asker = n("/bob");
        let all = View {
            names: true,
            audience: true,
            reads: true,
            holds: true,
        };
        assert_eq!(may_grant(&all, &e, &asker), Ok(()));
        let refusals = [
            (
                View {
                    names: false,
                    ..all
                },
                GrantRefusal::EpochNotNamed,
            ),
            (
                View {
                    audience: false,
                    ..all
                },
                GrantRefusal::NotInAudience,
            ),
            (
                View {
                    reads: false,
                    ..all
                },
                GrantRefusal::NotReaderNow,
            ),
            (
                View {
                    holds: false,
                    ..all
                },
                GrantRefusal::KeyNotHeld,
            ),
        ];
        let mut said = BTreeSet::new();
        for (view, refusal) in refusals {
            assert_eq!(may_grant(&view, &e, &asker), Err(refusal));
            assert!(said.insert(refusal.to_string()), "each says which: {refusal}");
        }
        // Every condition is checked in the plan's order.
        let none = View {
            names: false,
            audience: false,
            reads: false,
            holds: false,
        };
        assert_eq!(
            may_grant(&none, &e, &asker),
            Err(GrantRefusal::EpochNotNamed)
        );
    }

    #[test]
    fn the_epoch_key_round_trips_through_the_wrap_and_the_grant_aad_binds_the_grant_name() {
        let me = RecipientKey::generate();
        let key = ContentKey::generate();
        let grant = n("/alice/laptop/32=grant/abc");
        let (ephemeral, wrapped) = wrap_key(&me.public(), &key, &grant).unwrap();
        let opened = unwrap_key(&me, &grant, &ephemeral, &wrapped).unwrap();
        assert_eq!(opened.expose(), key.expose());
        assert!(
            unwrap_key(&me, &n("/alice/laptop/32=grant/abd"), &ephemeral, &wrapped).is_none(),
            "another grant name"
        );
        assert!(
            unwrap_key(&RecipientKey::generate(), &grant, &ephemeral, &wrapped).is_none(),
            "another recipient"
        );
        let mut torn = wrapped.to_vec();
        *torn.last_mut().unwrap() ^= 1;
        assert!(unwrap_key(&me, &grant, &ephemeral, &torn).is_none(), "tampered");
        assert!(
            unwrap_key(&me, &grant, &ephemeral, &wrapped[..10]).is_none(),
            "truncated"
        );
        let (second, again) = wrap_key(&me.public(), &key, &grant).unwrap();
        assert_ne!(second, ephemeral, "a fresh ephemeral key per wrap");
        assert_ne!(again, wrapped);
    }

    #[test]
    fn a_stored_epoch_key_comes_back_only_under_its_name_and_check() {
        let (space, e) = (n("/alice/32=data/notes"), epoch("/alice/laptop", 2));
        let key = ContentKey::generate();
        let named = key_check(&key, &space, &e);
        let at = n("/localhost/ndn-heap/epoch/alice/32=data/notes/laptop/2");
        let mut first = keys();
        let (ephemeral, wrapped) = wrap_key(&first.public(), &key, &at).unwrap();

        let mut second = Keys::new(first.recipient().clone());
        assert!(
            !second.restore(&space, &e, &[0; 32], &at, &ephemeral, &wrapped),
            "a stored key that fails the check is dropped"
        );
        assert!(
            !second.restore(&space, &e, &named, &n("/elsewhere"), &ephemeral, &wrapped),
            "a stored key is bound to its store name"
        );
        assert!(second.key(&space, &e).is_none());
        assert!(second.restore(&space, &e, &named, &at, &ephemeral, &wrapped));
        assert_eq!(second.key(&space, &e).unwrap().expose(), key.expose());
        assert!(
            !first.restore(&space, &e, &named, &at, &ephemeral, &wrapped[..9]),
            "malformed"
        );
    }

    #[test]
    fn the_recipient_key_is_made_once_and_stable_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let identity = n("/alice");
        let device = n("/alice/laptop");
        let (first, public) = {
            let (sm, _) = SecurityManager::auto_init(&identity, dir.path()).unwrap();
            let key = recipient_key(&sm, &device).unwrap();
            let again = recipient_key(&sm, &device).unwrap();
            assert_eq!(key.public(), again.public(), "made once in a run");
            (key.expose().to_vec(), key.public())
        };
        let (sm, _) = SecurityManager::auto_init(&identity, dir.path()).unwrap();
        let back = recipient_key(&sm, &device).unwrap();
        assert_eq!(back.expose().to_vec(), first, "kept across a restart");
        assert_eq!(back.public(), public);
        let other = recipient_key(&sm, &n("/alice/phone")).unwrap();
        assert_ne!(other.public(), public, "one per device");
    }

    #[test]
    fn a_recipient_secret_of_the_wrong_length_is_refused_not_replaced() {
        let sm = SecurityManager::new();
        let device = n("/alice/laptop");
        sm.put_secret(recipient_secret_name(&device), &[1u8; 31])
            .unwrap();
        let err = recipient_key(&sm, &device).unwrap_err();
        assert!(matches!(err, SealError::BadSecret { len: 31, .. }), "{err}");
        assert_eq!(
            sm.secret(&recipient_secret_name(&device)).unwrap().len(),
            31,
            "the stored bytes are left alone"
        );
    }

    #[test]
    fn the_recipient_secret_lives_under_the_local_prefix() {
        assert_eq!(
            recipient_secret_name(&n("/alice/laptop")),
            n("/localhost/ndn-heap/seal/alice/laptop")
        );
    }

    #[test]
    fn keys_are_zeroized_on_drop() {
        fn zeroizes<T: ZeroizeOnDrop>() {}
        zeroizes::<ContentKey>();
        zeroizes::<RecipientKey>();
        zeroizes::<Keys>();
    }
}
