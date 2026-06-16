//! Background certificate-renewal task. Currently logs only — re-enrollment
//! must be performed manually.

use std::{path::PathBuf, sync::Arc, time::Duration};

use ndn_packet::Name;
use ndn_security::SecurityManager;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::device::RenewalPolicy;

pub struct RenewalHandle {
    task: JoinHandle<()>,
}

impl Drop for RenewalHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn start_renewal(
    manager: Arc<SecurityManager>,
    key_name: Name,
    namespace: Name,
    policy: &RenewalPolicy,
    _storage: Option<PathBuf>,
) -> RenewalHandle {
    let check_interval = match policy {
        RenewalPolicy::WhenPercentRemaining(_pct) => Duration::from_secs(600),
        RenewalPolicy::Every(d) => *d,
        RenewalPolicy::Manual => {
            return RenewalHandle {
                task: tokio::spawn(async {}),
            };
        }
    };

    let percent = match policy {
        RenewalPolicy::WhenPercentRemaining(p) => *p as u64,
        _ => 20,
    };

    let task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(check_interval).await;

            let should_renew = check_renewal_needed(&manager, &key_name, percent);
            if should_renew {
                info!(
                    identity = %namespace,
                    "Certificate approaching expiry, initiating renewal"
                );
                warn!(
                    identity = %namespace,
                    "Automatic renewal not yet implemented; please re-enroll manually"
                );
            }
        }
    });

    RenewalHandle { task }
}

fn check_renewal_needed(manager: &SecurityManager, key_name: &Name, threshold_pct: u64) -> bool {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    if let Some(cert) = manager
        .cert_cache()
        .get(&std::sync::Arc::new(key_name.clone()))
    {
        let total = cert.valid_until.saturating_sub(cert.valid_from);
        let remaining = cert.valid_until.saturating_sub(now_ns);
        if total == 0 {
            return false;
        }
        let remaining_pct = (remaining * 100) / total;
        return remaining_pct < threshold_pct;
    }
    false
}
