//! Dev/issuer helper: wrap an existing artifact as an `ndn-trust://…` URI for
//! testing the mobile onboarding router (and a stand-in until the dashboard /
//! CLIs emit envelopes natively).
//!
//! ```sh
//! cargo run -p ndn-trust-envelope --example emit -- bag <safebag-file> <key-name>
//! cargo run -p ndn-trust-envelope --example emit -- anchor <version> <context-content-file>
//! ```

use std::{env, fs, process::exit};

use bytes::Bytes;
use ndn_trust_envelope::TrustEnvelope;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let env = match args.first().map(String::as_str) {
        Some("bag") if args.len() == 3 => TrustEnvelope::Bag {
            key_name: args[2].clone(),
            safebag: read_artifact(&args[1]),
        },
        Some("anchor") if args.len() == 3 => TrustEnvelope::Anchor {
            version: args[1].parse().unwrap_or_else(|_| die("version must be a number")),
            context_content: read_artifact(&args[2]),
        },
        Some("invite") if args.len() == 4 || args.len() == 5 => TrustEnvelope::Invite {
            ca_prefix: args[1].clone(),
            identity_namespace: args[2].clone(),
            token: args[3].clone(),
            ttl_secs: args.get(4).and_then(|s| s.parse().ok()),
        },
        // Round-trip check: parse a URI back and describe it.
        Some("decode") if args.len() == 2 => {
            let parsed = TrustEnvelope::from_uri(&args[1]).unwrap_or_else(|e| die(&format!("decode: {e}")));
            eprintln!("decoded kind={:?} -> {parsed:?}", parsed.kind());
            return;
        }
        // Render a URI as a scannable QR SVG (testing the mobile scanner).
        Some("qr") if args.len() == 3 => {
            use qrcode::QrCode;
            let code = QrCode::new(args[1].as_bytes()).unwrap_or_else(|e| die(&format!("qr: {e}")));
            let svg = code
                .render::<qrcode::render::svg::Color<'_>>()
                .min_dimensions(420, 420)
                .build();
            fs::write(&args[2], svg).unwrap_or_else(|e| die(&format!("write {}: {e}", args[2])));
            eprintln!("wrote QR to {}", args[2]);
            return;
        }
        _ => die(
            "usage: emit (bag <safebag-file> <key-name> | anchor <version> <content-file> | \
             invite <ca-prefix> <identity> <token> [ttl-secs] | decode <uri>)",
        ),
    };
    println!("{}", env.to_uri());
}

/// Read a file as raw bytes, transparently base64-decoding it if it looks like
/// base64 text (so both `.raw` and base64-exported artifacts work).
fn read_artifact(path: &str) -> Bytes {
    use base64::Engine as _;
    let raw = fs::read(path).unwrap_or_else(|e| die(&format!("read {path}: {e}")));
    if let Ok(text) = std::str::from_utf8(&raw) {
        let t = text.trim();
        if !t.is_empty() && t.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_')) {
            for eng in [
                base64::engine::general_purpose::STANDARD,
                base64::engine::general_purpose::URL_SAFE_NO_PAD,
            ] {
                if let Ok(decoded) = eng.decode(t) {
                    return Bytes::from(decoded);
                }
            }
        }
    }
    Bytes::from(raw)
}

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    exit(2);
}
