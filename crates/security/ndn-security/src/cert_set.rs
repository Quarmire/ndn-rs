//! [`CertSet`]: the certificates a device serves by name, and which one
//! answers a request.
//!
//! - An Interest naming one certificate exactly gets that certificate.
//! - A CanBePrefix Interest (a key name, as a validator following a
//!   KeyLocator asks) gets the newest certificate valid now under its name,
//!   else the newest one, so an expired certificate reads as expired rather
//!   than missing.
//! - [`CertSet::chain_of`] walks a key's newest valid certificate and the
//!   issuer certificates held after it, nearest first, up to a self-signed
//!   one, one not held, or [`MAX_CHAIN`] certificates: what a device hands a
//!   peer so it can validate the device without fetching anything.

use std::collections::HashMap;

use bytes::Bytes;
use ndn_packet::Name;

use crate::cert_cache::Certificate;
use crate::cert_name::key_name_of;

/// The longest chain [`CertSet::chain_of`] returns.
pub const MAX_CHAIN: usize = 8;

#[derive(Debug, Clone)]
struct Held {
    cert: Certificate,
    wire: Bytes,
}

/// Certificates by certificate name, each with its Data wire, served
/// byte for byte.
#[derive(Debug, Clone, Default)]
pub struct CertSet {
    certs: HashMap<Name, Held>,
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

impl CertSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold `cert` (decoded from `wire`). `false`: a certificate of that
    /// name is held already (it is held once).
    pub fn insert(&mut self, cert: Certificate, wire: Bytes) -> bool {
        let name = (*cert.name).clone();
        if self.certs.contains_key(&name) {
            return false;
        }
        self.certs.insert(name, Held { cert, wire });
        true
    }

    /// Whether a certificate of `key` is held.
    pub fn holds_key(&self, key: &Name) -> bool {
        self.certs.keys().any(|name| key_name_of(name) == *key)
    }

    /// Remove every certificate whose name `remove` selects; their names.
    pub fn remove_where(&mut self, remove: impl Fn(&Name) -> bool) -> Vec<Name> {
        let mut removed = Vec::new();
        self.certs.retain(|name, _| {
            if remove(name) {
                removed.push(name.clone());
                false
            } else {
                true
            }
        });
        removed
    }

    /// The certificate Data that answers a request for `name`: by exact
    /// name, or with `can_be_prefix` the newest valid certificate under it
    /// (else the newest).
    pub fn answer(&self, name: &Name, can_be_prefix: bool) -> Option<Bytes> {
        if let Some(held) = self.certs.get(name) {
            return Some(held.wire.clone());
        }
        if !can_be_prefix {
            return None;
        }
        let now = now_ns();
        self.certs
            .iter()
            .filter(|(held, _)| held.has_prefix(name))
            .max_by(|(a, x), (b, y)| {
                (x.cert.is_valid_at(now), x.cert.valid_from, *a)
                    .cmp(&(y.cert.is_valid_at(now), y.cert.valid_from, *b))
            })
            .map(|(_, held)| held.wire.clone())
    }

    /// The newest certificate valid now under `name` (a key name or a
    /// certificate name).
    pub fn newest_valid(&self, name: &Name) -> Option<&Certificate> {
        self.newest_valid_held(name, now_ns()).map(|held| &held.cert)
    }

    fn newest_valid_held(&self, name: &Name, now: u64) -> Option<&Held> {
        self.certs
            .iter()
            .filter(|(n, held)| n.has_prefix(name) && held.cert.is_valid_at(now))
            .max_by(|(a, x), (b, y)| (x.cert.valid_from, *a).cmp(&(y.cert.valid_from, *b)))
            .map(|(_, held)| held)
    }

    /// The newest valid certificate of `key` and the issuer certificates
    /// held after it, nearest first, up to a self-signed one or one not
    /// held, at most [`MAX_CHAIN`]. Empty when no valid certificate of
    /// `key` is held.
    pub fn chain_of(&self, key: &Name) -> Vec<Bytes> {
        let now = now_ns();
        let mut chain: Vec<Bytes> = Vec::new();
        let mut next = Some(key.clone());
        while let Some(key) = next.take()
            && chain.len() < MAX_CHAIN
            && let Some(held) = self.newest_valid_held(&key, now)
        {
            if chain.contains(&held.wire) {
                break;
            }
            chain.push(held.wire.clone());
            next = held
                .cert
                .issuer
                .as_deref()
                .map(key_name_of)
                .filter(|issuer| *issuer != key);
        }
        chain
    }
}
