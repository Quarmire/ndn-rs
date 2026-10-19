//! Dev helper: wrap an existing artifact as an `ndn-trust://…` URI for testing
//! the mobile onboarding router. (Issuer CLIs emit envelopes natively:
//! `ndn-trust-context build`, `ndn-fwd-tokens new`, `ndn-fwd init`.)
//!
//! ```sh
//! cargo run -p ndn-trust-envelope --example emit -- bag <safebag-file> <key-name>
//! cargo run -p ndn-trust-envelope --example emit -- anchor <namespace> <fingerprint-hex> <signed-context-data-file>
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
            namespace: None,
            fingerprint: None,
        },
        // `<signed-context-data-file>` is a signed context Data wire, e.g. the
        // `<pib>/contexts/<hex>.tc` file `ndn-fwd init` / `ndn-fwd adopt` write.
        Some("anchor") if args.len() == 4 => TrustEnvelope::Anchor {
            namespace: Some(args[1].clone()),
            fingerprint: Some(parse_fingerprint(&args[2])),
            version: None,
            context_data: Some(read_artifact(&args[3])),
            context_content: None,
        },
        Some("invite") if args.len() == 4 || args.len() == 5 => TrustEnvelope::Invite {
            ca_prefix: args[1].clone(),
            identity_namespace: args[2].clone(),
            token: args[3].clone(),
            ttl_secs: args.get(4).and_then(|s| s.parse().ok()),
            anchor_fingerprint: None,
            device: None,
        },
        // Round-trip check: parse a URI back and describe it.
        Some("decode") if args.len() == 2 => {
            let parsed =
                TrustEnvelope::from_uri(&args[1]).unwrap_or_else(|e| die(&format!("decode: {e}")));
            eprintln!("decoded kind={:?} -> {parsed:?}", parsed.kind());
            return;
        }
        // Render a URI as a scannable QR SVG (testing the mobile scanner).
        Some("qr") if args.len() == 3 => {
            let code = ndn_trust_envelope::qr::encode(&args[1])
                .unwrap_or_else(|e| die(&format!("qr: {e}")));
            let svg = code
                .render::<qrcode::render::svg::Color<'_>>()
                .min_dimensions(420, 420)
                .build();
            fs::write(&args[2], svg).unwrap_or_else(|e| die(&format!("write {}: {e}", args[2])));
            eprintln!("wrote QR to {}", args[2]);
            return;
        }
        _ => die("usage: emit (bag <safebag-file> <key-name> | \
             anchor <namespace> <fingerprint-hex> <signed-context-data-file> | \
             invite <ca-prefix> <identity> <token> [ttl-secs] | decode <uri>)"),
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
        if !t.is_empty()
            && t.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
        {
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

/// Parse a 64-hex-digit anchor fingerprint.
fn parse_fingerprint(hex: &str) -> [u8; ndn_trust_envelope::ANCHOR_FINGERPRINT_LEN] {
    let hex = hex.trim();
    let mut out = [0u8; ndn_trust_envelope::ANCHOR_FINGERPRINT_LEN];
    if hex.len() != out.len() * 2 || !hex.is_ascii() {
        die("fingerprint must be 64 hex digits");
    }
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
            .unwrap_or_else(|_| die("fingerprint must be 64 hex digits"));
    }
    out
}

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    exit(2);
}
