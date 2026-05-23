//! ACME (RFC 8555) DNS-01 cert provisioning for the browser-trusted
//! transports (WebSocket-TLS, WebTransport).
//!
//! [`CertSource`] is the operator-facing config; [`AcmeClient`] runs the
//! RFC 8555 order; [`DnsProvider`] fulfills the DNS-01 challenge;
//! [`renewal_loop`] re-runs the order inside the 30-day window.

mod cache;
mod cert_source;
mod client;
mod dns;
mod renewal;

pub use cache::CertCache;
pub use cert_source::{AcmeConfig, CertMaterial, CertSource, SelfSignedDev};
pub use client::{AcmeClient, AcmeError};
pub use dns::{CloudflareDnsProvider, DnsProvider, DnsRecord, NoopDnsProvider};
pub use renewal::{CertStatus, cert_status, needs_renewal, renewal_loop};
