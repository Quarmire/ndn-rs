/// ndn-sec — NDN key and certificate management tool.
///
/// Manages a file-based Public Info Base (PIB) that stores Ed25519 keys and
/// their self-signed certificates for use by `ndn-fwd` and other NDN tools.
///
/// # Quick start
///
/// ```sh
/// # Generate the router's identity key (self-signed, 1-year validity):
/// ndn-sec keygen /ndn/router1
///
/// # Make it a trust anchor so other nodes can validate its certificates:
/// ndn-sec anchor add /ndn/router1
///
/// # Inspect the stored certificate:
/// ndn-sec certdump /ndn/router1
///
/// # List all keys in the PIB:
/// ndn-sec list
///
/// # Use a custom PIB path instead of ~/.ndn/pib:
/// ndn-sec --pib /etc/ndn/pib keygen /ndn/site1/router-a
/// ```
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use clap::{Parser, Subcommand};
use ndn_packet::Name;
use ndn_security::{
    cert_cache::Certificate,
    pib::{FilePib, name_to_uri},
};

// ─── CLI definition ───────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "ndn-sec",
    about = "NDN key and certificate management",
    version
)]
struct Cli {
    /// Path to the PIB directory.  Defaults to $NDN_PIB or ~/.ndn/pib.
    #[arg(long, global = true, env = "NDN_PIB")]
    pib: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new Ed25519 key pair and self-signed certificate.
    Keygen {
        /// NDN identity name (e.g., /ndn/router1).
        name: String,

        /// Also register the new certificate as a trust anchor in the PIB.
        #[arg(long)]
        anchor: bool,

        /// Certificate validity in days (default: 365).
        #[arg(long, default_value = "365")]
        days: u64,

        /// Skip silently if a key for this identity already exists in the PIB.
        ///
        /// Useful for idempotent NixOS / systemd ExecStartPre invocations:
        /// the key is generated on first boot and ignored on subsequent starts.
        #[arg(long)]
        skip_if_exists: bool,
    },

    /// Display certificate details for a stored key.
    Certdump {
        /// NDN identity name.
        name: String,
    },

    /// List all keys stored in the PIB.
    List,

    /// Delete a key and its certificate from the PIB.
    Delete {
        /// NDN identity name.
        name: String,
    },

    /// Trust anchor sub-commands.
    #[command(subcommand_value_name = "SUBCOMMAND")]
    Anchor {
        #[command(subcommand)]
        subcmd: AnchorCmd,
    },
}

#[derive(Subcommand)]
enum AnchorCmd {
    /// Mark an existing key's certificate as a trust anchor.
    Add {
        /// NDN identity name.
        name: String,
    },
    /// Remove a trust anchor from the PIB.
    Remove {
        /// NDN identity name.
        name: String,
    },
    /// List all trust anchors stored in the PIB.
    List,
}

// ─── Entry point ──────────────────────────────────────────────────────────────

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let pib_path = resolve_pib_path(cli.pib.as_deref());

    match cli.command {
        Command::Keygen {
            name,
            anchor,
            days,
            skip_if_exists,
        } => {
            cmd_keygen(&pib_path, &name, anchor, days, skip_if_exists)?;
        }
        Command::Certdump { name } => {
            cmd_certdump(&pib_path, &name)?;
        }
        Command::List => {
            cmd_list(&pib_path)?;
        }
        Command::Delete { name } => {
            cmd_delete(&pib_path, &name)?;
        }
        Command::Anchor { subcmd } => match subcmd {
            AnchorCmd::Add { name } => cmd_anchor_add(&pib_path, &name)?,
            AnchorCmd::Remove { name } => cmd_anchor_remove(&pib_path, &name)?,
            AnchorCmd::List => cmd_anchor_list(&pib_path)?,
        },
    }

    Ok(())
}

// ─── Commands ─────────────────────────────────────────────────────────────────

fn cmd_keygen(
    pib_path: &PathBuf,
    name_str: &str,
    make_anchor: bool,
    days: u64,
    skip_if_exists: bool,
) -> anyhow::Result<()> {
    let key_name = parse_name(name_str)?;
    let pib = FilePib::new(pib_path)?;

    // With --skip-if-exists: if a key already exists for this identity, do nothing.
    if skip_if_exists
        && let Ok(keys) = pib.list_keys()
        && keys.iter().any(|k| k == &key_name)
    {
        return Ok(());
    }

    // Generate key and store it.
    let signer = pib.generate_ed25519(&key_name)?;
    let pk = Bytes::copy_from_slice(&signer.public_key_bytes());

    // Issue self-signed certificate.
    let now = now_ns();
    let validity_ns = days * 24 * 3600 * 1_000_000_000;
    let cert = Certificate {
        name: Arc::new(key_name.clone()),
        public_key: pk.clone(),
        valid_from: now,
        valid_until: now.saturating_add(validity_ns),
        issuer: None,
        signed_region: None,
        sig_value: None,
    };
    pib.store_cert(&key_name, &cert)?;

    if make_anchor {
        pib.add_trust_anchor(&key_name, &cert)?;
        println!("Generated key and self-signed certificate for {name_str} (trust anchor).");
    } else {
        println!("Generated key and self-signed certificate for {name_str}.");
    }

    println!("  Public key : {}", hex_encode(&pk));
    println!("  Valid from : {}", format_ns(now));
    println!("  Valid until: {}", format_ns(cert.valid_until));
    println!("  PIB        : {}", pib_path.display());

    Ok(())
}

fn cmd_certdump(pib_path: &PathBuf, name_str: &str) -> anyhow::Result<()> {
    let key_name = parse_name(name_str)?;
    let pib = open_pib(pib_path)?;
    let cert = pib
        .get_cert(&key_name)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let expired = cert.valid_until != u64::MAX && cert.valid_until < now_ns();
    println!("Certificate for {name_str}");
    println!("  Public key : {}", hex_encode(&cert.public_key));
    println!("  Valid from : {}", format_ns(cert.valid_from));
    println!(
        "  Valid until: {}{}",
        format_ns(cert.valid_until),
        if expired { "  [EXPIRED]" } else { "" }
    );

    Ok(())
}

fn cmd_list(pib_path: &PathBuf) -> anyhow::Result<()> {
    let pib = open_pib(pib_path)?;
    let keys = pib.list_keys()?;

    if keys.is_empty() {
        println!("No keys in PIB at {}.", pib_path.display());
        return Ok(());
    }

    println!("Keys in {} ({}):", pib_path.display(), keys.len());
    for name in &keys {
        let uri = name_to_uri(name);
        let has_cert = pib.get_cert(name).is_ok();
        println!(
            "  {}  {}",
            uri,
            if has_cert { "[cert]" } else { "[no cert]" }
        );
    }

    Ok(())
}

fn cmd_delete(pib_path: &PathBuf, name_str: &str) -> anyhow::Result<()> {
    let key_name = parse_name(name_str)?;
    let pib = open_pib(pib_path)?;
    pib.delete_key(&key_name)?;
    println!("Deleted {name_str} from PIB.");
    Ok(())
}

fn cmd_anchor_add(pib_path: &PathBuf, name_str: &str) -> anyhow::Result<()> {
    let key_name = parse_name(name_str)?;
    let pib = open_pib(pib_path)?;
    let cert = pib.get_cert(&key_name).map_err(|_| {
        anyhow::anyhow!("No certificate for {name_str}. Run `ndn-sec keygen {name_str}` first.")
    })?;
    pib.add_trust_anchor(&key_name, &cert)?;
    println!("Marked {name_str} as a trust anchor.");
    Ok(())
}

fn cmd_anchor_remove(pib_path: &PathBuf, name_str: &str) -> anyhow::Result<()> {
    let key_name = parse_name(name_str)?;
    let pib = open_pib(pib_path)?;
    pib.remove_trust_anchor(&key_name)?;
    println!("Removed {name_str} from trust anchors.");
    Ok(())
}

fn cmd_anchor_list(pib_path: &PathBuf) -> anyhow::Result<()> {
    let pib = open_pib(pib_path)?;
    let names = pib.list_anchors()?;

    if names.is_empty() {
        println!("No trust anchors in PIB at {}.", pib_path.display());
        return Ok(());
    }

    println!("Trust anchors ({}):", names.len());
    for name in &names {
        println!("  {}", name_to_uri(name));
    }

    Ok(())
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Resolve the PIB path: CLI flag → $NDN_PIB → ~/.ndn/pib.
fn resolve_pib_path(arg: Option<&str>) -> PathBuf {
    if let Some(p) = arg {
        return PathBuf::from(p);
    }
    if let Ok(p) = std::env::var("NDN_PIB") {
        return PathBuf::from(p);
    }
    let mut home = dirs_next();
    home.push(".ndn");
    home.push("pib");
    home
}

/// Return the user's home directory, falling back to `/tmp/ndn-pib`.
fn dirs_next() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/ndn-pib-fallback"))
}

fn open_pib(path: &PathBuf) -> anyhow::Result<FilePib> {
    FilePib::open(path).map_err(|e| {
        anyhow::anyhow!(
            "{e}\nRun `ndn-sec keygen <name>` to create a PIB at {}.",
            path.display()
        )
    })
}

/// Parse an NDN URI like `/ndn/router1` into a `Name`.
fn parse_name(s: &str) -> anyhow::Result<Name> {
    s.parse()
        .map_err(|e| anyhow::anyhow!("Invalid NDN name '{s}': {e}"))
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Format a nanosecond Unix timestamp as a human-readable date/time.
fn format_ns(ns: u64) -> String {
    if ns == u64::MAX {
        return "never".to_string();
    }
    let secs = ns / 1_000_000_000;
    format_unix_secs(secs)
}

/// Minimal RFC 3339 date formatter using only stdlib arithmetic.
///
/// Handles all dates representable as a u64 nanosecond timestamp (year ≥ 1970).
fn format_unix_secs(secs: u64) -> String {
    let s_in_day = secs % 86400;
    let h = s_in_day / 3600;
    let m = (s_in_day % 3600) / 60;
    let s = s_in_day % 60;

    // Civil calendar from https://howardhinnant.github.io/date_algorithms.html
    let z = (secs / 86400) as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
