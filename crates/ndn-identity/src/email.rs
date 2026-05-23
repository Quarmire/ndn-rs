//! [`EmailSender`] implementations for the NDNCERT email challenge.
//!
//! [`LoggingEmailSender`] is dependency-free and logs the one-time code instead
//! of delivering it — the dev / test path, and the fallback when no real SMTP
//! relay is configured. A production SMTP sender lives behind the host
//! binary's `smtp` feature (`ndn-fwd`), so the identity library stays free of a
//! heavy async-SMTP dependency.

use std::future::Future;
use std::pin::Pin;

use ndn_cert::EmailSender;

/// Logs the email challenge code via `tracing` instead of sending it. Lets the
/// email challenge run end-to-end without an SMTP relay (operator reads the
/// code from the log). **Not** for production delivery.
pub struct LoggingEmailSender;

impl EmailSender for LoggingEmailSender {
    fn send<'a>(
        &'a self,
        address: &'a str,
        code: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        let address = address.to_string();
        let code = code.to_string();
        Box::pin(async move {
            tracing::info!(
                target: "ndncert.email",
                %address,
                %code,
                "email challenge code (LoggingEmailSender — not actually delivered)",
            );
            Ok(())
        })
    }
}
