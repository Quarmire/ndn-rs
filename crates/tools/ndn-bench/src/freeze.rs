//! `bench freeze` — compute the fixed-point trio and (with `--pin`) write
//! the pins (R14, D-K8): H(V₀.2), H(IM₀), H(T₀) into
//! `crates/core/ndn-manifest/src/kernel_hash.rs` and `conformance/FREEZE.md`.
//!
//! The pins are recorded by THIS tool on a real toolchain — never
//! hand-computed (D-K8; FRICTION F36). The ceremony countersigning slot
//! (knob #5: editor key + two channel-orthogonal plural-registry witnesses,
//! D-18) stays an explicit, human-shaped blank in FREEZE.md: this tool
//! declares the slot and refuses to fake it.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use ndn_manifest::kernel::{fixed_point, verify_fixed_point, FixedPoint, FixedPointStatus};

fn hex32(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// The freeze report (also the body printed by `bench freeze`).
pub fn report(fp: &FixedPoint) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "fixed point (computed by this binary's encoder — R14):");
    let _ = writeln!(s, "  H(V₀.2) = {}  ({} bytes)", hex32(&fp.v0_hash), fp.v0_bytes.len());
    let _ = writeln!(s, "  H(IM₀)  = {}  ({} bytes)", hex32(&fp.im0_hash), fp.im0_bytes.len());
    let _ = writeln!(s, "  H(T₀)   = {}  ({} bytes)", hex32(&fp.t0_hash), fp.t0_bytes.len());
    match verify_fixed_point() {
        FixedPointStatus::Verified => {
            let _ = writeln!(s, "  status: VERIFIED against pinned constants");
        }
        FixedPointStatus::Unpinned => {
            let _ = writeln!(s, "  status: UNPINNED — run `ndn-bench freeze --pin` to record these (D-K8)");
        }
        FixedPointStatus::Mismatch { which, .. } => {
            let _ = writeln!(s, "  status: MISMATCH on {which} — the baked kernel and the pins have diverged; refusing");
        }
    }
    s
}

/// Rewrite `kernel_hash.rs` with the computed pins. `workspace_root` is the
/// directory that contains `crates/`.
pub fn pin(workspace_root: &Path) -> Result<String, String> {
    let fp = fixed_point();
    // A mismatch against EXISTING pins is a refusal, not an overwrite: a
    // divergent kernel needs a deliberate decision (and a supersedes edge),
    // not a silent re-pin.
    if let FixedPointStatus::Mismatch { which, .. } = verify_fixed_point() {
        return Err(format!(
            "existing pin for {which} disagrees with the computed kernel — refusing to overwrite; \
             if this divergence is deliberate, blank the pins in kernel_hash.rs first and record the \
             supersession (L-07)"
        ));
    }

    let kh_path = workspace_root.join("crates/core/ndn-manifest/src/kernel_hash.rs");
    let mut src = String::new();
    let _ = writeln!(src, "//! The pinned fixed-point hashes (R14) — WRITTEN BY `ndn-bench freeze --pin`.");
    let _ = writeln!(src, "//!");
    let _ = writeln!(src, "//! Recorded by the bench on a real toolchain (D-K8); never hand-edited.");
    let _ = writeln!(src, "//! To re-pin after a DELIBERATE kernel change: set these to `None`, record");
    let _ = writeln!(src, "//! the supersession (L-07), and run the freeze again.");
    let _ = writeln!(src);
    let _ = writeln!(src, "/// H(V₀.2), lowercase hex, once pinned.");
    let _ = writeln!(src, "pub const V0_2_HASH_HEX: Option<&str> = Some(\"{}\");", hex32(&fp.v0_hash));
    let _ = writeln!(src);
    let _ = writeln!(src, "/// H(IM₀), lowercase hex, once pinned.");
    let _ = writeln!(src, "pub const IM0_HASH_HEX: Option<&str> = Some(\"{}\");", hex32(&fp.im0_hash));
    let _ = writeln!(src);
    let _ = writeln!(src, "/// H(T₀), lowercase hex, once pinned.");
    let _ = writeln!(src, "pub const T0_HASH_HEX: Option<&str> = Some(\"{}\");", hex32(&fp.t0_hash));
    fs::write(&kh_path, &src).map_err(|e| format!("{}: {e}", kh_path.display()))?;

    let freeze_md = workspace_root.join("conformance/FREEZE.md");
    fs::create_dir_all(freeze_md.parent().unwrap()).map_err(|e| e.to_string())?;
    let md = freeze_markdown(&fp);
    fs::write(&freeze_md, md).map_err(|e| format!("{}: {e}", freeze_md.display()))?;

    Ok(format!(
        "pinned:\n{}\nwrote {} and {}\nNOTE: rebuild so the constants take effect, then rerun \
         `ndn-bench freeze` — it must print VERIFIED.",
        report(&fp),
        kh_path.display(),
        freeze_md.display()
    ))
}

/// The FREEZE.md body — mechanism + pins + the explicit ceremony slot.
pub fn freeze_markdown(fp: &FixedPoint) -> String {
    format!(
        "# The Freeze — R14 fixed point\n\n\
         The kernel is baked into every implementation AND published as data written in\n\
         itself (D-49). These pins are the bridge: the hashes below were computed by\n\
         `ndn-bench freeze --pin` from the live encoder — decode ∘ encode is byte\n\
         identity (R13), and every implementation must refuse to run if its baked-in\n\
         kernel does not hash-match these values.\n\n\
         | artifact | canonical bytes | SHA-256 |\n\
         |---|---|---|\n\
         | V₀.2 (32 terms) | {} B | `{}` |\n\
         | IM₀ (implicit-manifest stratum) | {} B | `{}` |\n\
         | T₀ (terminal contract) | {} B | `{}` |\n\n\
         ## Ceremony (knob #5 · D-18) — NOT YET PERFORMED\n\n\
         The genesis countersigning is a governance act no tool can perform. The slot:\n\n\
         - [ ] editor key signature over the three hashes above: `____________________`\n\
         - [ ] witness 1 (plural registry, channel A): `____________________`\n\
         - [ ] witness 2 (plural registry, channel B — MUST be channel-orthogonal to A): `____________________`\n\n\
         Until all three lines are filled, the freeze is *pinned* but not *ratified*.\n\
         This file states the difference instead of blurring it.\n",
        fp.v0_bytes.len(),
        hex32(&fp.v0_hash),
        fp.im0_bytes.len(),
        hex32(&fp.im0_hash),
        fp.t0_bytes.len(),
        hex32(&fp.t0_hash),
    )
}
