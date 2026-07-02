//! `/localhost/nfd/ext/{list,set}` — generic introspection/control for
//! out-of-core subsystems via the [`ControlSurface`] registry.
//!
//! ndn-mgmt serves these with **zero compile-time knowledge** of the subsystems
//! (rearchitecture note §5, the cold control plane): a subsystem in its own
//! crate/repo registers an `Arc<dyn ControlSurface>` via
//! `MgmtHandles::control_surfaces`, and the dashboard discovers it here. The
//! richly-typed verb modules (coding/rate-limit/…) keep their own surfaces; this
//! is the generic layer so an *unknown* subsystem is still inspectable.

use std::sync::Arc;

use async_trait::async_trait;
use ndn_mgmt_wire::{
    ControlParameters, ControlResponse, ControlSurface, control_response::status, render_pairs,
};

use crate::MgmtResponse;
use crate::module::{MgmtContext, MgmtModule};

/// `ext/list` — every registered surface with its caps, current options
/// (`option.<k>=<v>`), and runtime stats (`stat.<k>=<v>`), one `[<name>]`
/// section each. Self-describing text so a client renders loaded extensions and
/// their knobs without knowing any at compile time.
fn ext_list(surfaces: &[Arc<dyn ControlSurface>]) -> ControlResponse {
    let mut body = String::new();
    for s in surfaces {
        let info = s.describe();
        body.push_str(&format!("[{}]\n", s.name()));
        body.push_str(&render_pairs(&info.caps));
        for (k, v) in &info.options {
            body.push_str(&format!("option.{k}={v}\n"));
        }
        for (k, v) in &s.stats().entries {
            body.push_str(&format!("stat.{k}={v}\n"));
        }
    }
    ControlResponse::ok_empty(body)
}

/// `ext/set` — apply a runtime option update. `Uri = "<name> <key> <value>"`
/// (split into at most three; the value may contain spaces).
fn ext_set(surfaces: &[Arc<dyn ControlSurface>], params: ControlParameters) -> ControlResponse {
    let spec = match params.uri.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                "Uri must be '<name> <key> <value>'",
            );
        }
    };
    let mut it = spec.splitn(3, ' ');
    let (name, key, value) = match (it.next(), it.next(), it.next()) {
        (Some(n), Some(k), Some(v)) => (n, k, v),
        _ => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                "Uri must be '<name> <key> <value>'",
            );
        }
    };
    match surfaces.iter().find(|s| s.name() == name) {
        Some(s) => match s.set_option(key, value) {
            Ok(()) => ControlResponse::ok_empty(format!("{name}: {key}={value}\n")),
            Err(e) => ControlResponse::error(status::BAD_PARAMS, e),
        },
        None => ControlResponse::error(status::NOT_FOUND, format!("no extension '{name}'")),
    }
}

pub(crate) struct ExtModule;

#[async_trait]
impl MgmtModule for ExtModule {
    fn name(&self) -> &'static [u8] {
        b"ext"
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        match verb {
            b"list" => ext_list(ctx.control_surfaces),
            b"set" => ext_set(ctx.control_surfaces, params),
            _ => ControlResponse::error(status::NOT_FOUND, "unknown ext verb"),
        }
        .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_mgmt_wire::{ControlInfo, ControlStats};
    use std::sync::Mutex;

    /// A stand-in for a split-out subsystem registering its surface.
    struct Sample {
        mode: Mutex<String>,
    }

    impl ControlSurface for Sample {
        fn name(&self) -> &str {
            "sample"
        }
        fn describe(&self) -> ControlInfo {
            ControlInfo {
                caps: vec![("transport".into(), "test".into())],
                options: vec![("mode".into(), self.mode.lock().unwrap().clone())],
            }
        }
        fn stats(&self) -> ControlStats {
            ControlStats {
                entries: vec![("count".into(), "7".into())],
            }
        }
        fn set_option(&self, key: &str, value: &str) -> Result<(), String> {
            if key == "mode" {
                *self.mode.lock().unwrap() = value.into();
                Ok(())
            } else {
                Err(format!("unknown option '{key}'"))
            }
        }
    }

    fn surfaces() -> Vec<Arc<dyn ControlSurface>> {
        vec![Arc::new(Sample {
            mode: Mutex::new("a".into()),
        })]
    }

    #[test]
    fn list_renders_caps_options_and_stats_generically() {
        let s = surfaces();
        let r = ext_list(&s);
        assert_eq!(r.status_code, status::OK);
        let body = r.status_text;
        assert!(body.contains("[sample]"), "{body}");
        assert!(body.contains("transport=test"), "{body}");
        assert!(body.contains("option.mode=a"), "{body}");
        assert!(body.contains("stat.count=7"), "{body}");
    }

    #[test]
    fn set_applies_then_list_reflects_it() {
        let s = surfaces();
        let ok = ext_set(
            &s,
            ControlParameters {
                uri: Some("sample mode b".into()),
                ..Default::default()
            },
        );
        assert_eq!(ok.status_code, status::OK);
        assert!(ext_list(&s).status_text.contains("option.mode=b"));
    }

    #[test]
    fn set_rejects_unknown_extension_and_option() {
        let s = surfaces();
        assert_eq!(
            ext_set(
                &s,
                ControlParameters {
                    uri: Some("nope mode b".into()),
                    ..Default::default()
                },
            )
            .status_code,
            status::NOT_FOUND
        );
        assert_eq!(
            ext_set(
                &s,
                ControlParameters {
                    uri: Some("sample bogus b".into()),
                    ..Default::default()
                },
            )
            .status_code,
            status::BAD_PARAMS
        );
    }
}
