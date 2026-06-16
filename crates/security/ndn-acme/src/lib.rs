//! TLS cert provisioning shared by every cert-bearing face transport
//! (WebSocket-TLS, WebTransport, and raw QUIC).
//!
//! [`CertSource`] is the operator-facing config — one shape (`self_signed_dev`
//! / `pem` / `acme`) for all of them. It [`resolve`](CertSource::resolve)s to
//! [`CertMaterial`] (PEM chain + key), whose [`leaf_sha256`](CertMaterial::leaf_sha256)
//! is the value a pinning dialer trusts. [`SelfSignedProfile`] lets one source
//! serve both a browser-pinnable transport and a long-lived backbone link.
//!
//! For ACME: [`AcmeClient`] runs the RFC 8555 order; [`DnsProvider`] fulfills
//! the DNS-01 challenge; [`renewal_loop`] re-runs the order inside the 30-day
//! window.

mod cache;
mod cert_source;
mod client;
mod dns;
mod renewal;

pub use cache::CertCache;
pub use cert_source::{AcmeConfig, CertMaterial, CertSource, SelfSignedDev, SelfSignedProfile};
pub use client::{AcmeClient, AcmeError};
pub use dns::{CloudflareDnsProvider, DnsProvider, DnsRecord, NoopDnsProvider};
pub use renewal::{CertStatus, cert_status, needs_renewal, renewal_loop};
