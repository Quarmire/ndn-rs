//! The `ndn-bench` CLI.
//!
//! ```text
//! ndn-bench compile <files…> [--out <dir>] [--lock <file>]
//! ndn-bench lint    <files…> [--lock <file>]
//! ndn-bench doc     <file.ndfs | petname> [--lock <file>] [--store <dir>]
//! ndn-bench vectors <dir> [--record]
//! ndn-bench freeze  [--pin] [--workspace <root>]
//! ```
//!
//! Lock format (Atelier.lock): one `petname = <64hex>` per line, `#` comments.
//! Store: a directory of `<64hex>.ndf` canonical-byte files.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ndn_bench::compile::{compile, Resolver};
use ndn_bench::lint::{self, Severity};
use ndn_bench::{doccard, freeze, script, vectors};
use ndn_manifest::canon::decode_document;
use ndn_manifest::model::Document;

fn hex32(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn load_lock(path: &Path) -> Result<BTreeMap<String, [u8; 32]>, String> {
    let mut out = BTreeMap::new();
    let src = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    for (i, raw) in src.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((pet, h)) = line.split_once('=') else {
            return Err(format!("{}:{}: expected `petname = <64hex>`", path.display(), i + 1));
        };
        let hash = parse_hex32(h.trim())
            .ok_or_else(|| format!("{}:{}: bad hash for `{}`", path.display(), i + 1, pet.trim()))?;
        out.insert(pet.trim().to_string(), hash);
    }
    Ok(out)
}

fn save_lock(path: &Path, lock: &BTreeMap<String, [u8; 32]>) -> Result<(), String> {
    let mut s = String::from("# Atelier.lock — petname → content hash (F21). Diffable; committed.\n");
    for (pet, h) in lock {
        s.push_str(&format!("{pet} = {}\n", hex32(h)));
    }
    fs::write(path, s).map_err(|e| format!("{}: {e}", path.display()))
}

/// Seed a resolver from a lock file + store directory: every pinned
/// vocabulary that exists in the store is loaded and indexed.
fn seed_resolver(lock_path: Option<&Path>, store: Option<&Path>) -> Result<Resolver, String> {
    let mut rz = Resolver::default();
    let Some(lock_path) = lock_path else { return Ok(rz) };
    if !lock_path.exists() {
        return Ok(rz);
    }
    let lock = load_lock(lock_path)?;
    for (pet, hash) in &lock {
        rz.lock.insert(pet.clone(), *hash);
        if let Some(store) = store {
            let p = store.join(format!("{}.ndf", hex32(hash)));
            if let Ok(bytes) = fs::read(&p) {
                match decode_document(&bytes) {
                    Ok(d) => {
                        if let Document::Vocabulary(v) = d.doc {
                            rz.add_vocabulary(pet, *hash, v);
                        }
                    }
                    Err(r) => {
                        return Err(format!("{}: stored artifact rejects: {}", p.display(), r.code()));
                    }
                }
            }
        }
    }
    Ok(rz)
}

struct Args {
    positional: Vec<String>,
    flags: BTreeMap<String, String>,
    switches: Vec<String>,
}

fn parse_args(argv: &[String]) -> Args {
    let mut positional = Vec::new();
    let mut flags = BTreeMap::new();
    let mut switches = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if let Some(name) = a.strip_prefix("--") {
            // value-taking flags
            if matches!(name, "out" | "lock" | "store" | "workspace") && i + 1 < argv.len() {
                flags.insert(name.to_string(), argv[i + 1].clone());
                i += 2;
                continue;
            }
            switches.push(name.to_string());
        } else {
            positional.push(a.clone());
        }
        i += 1;
    }
    Args { positional, flags, switches }
}

fn cmd_compile_or_lint(args: &Args, lint_only: bool) -> Result<bool, String> {
    let lock_path = args.flags.get("lock").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("Atelier.lock"));
    let store = args.flags.get("store").map(PathBuf::from);
    let out_dir = args.flags.get("out").map(PathBuf::from);
    let mut rz = seed_resolver(Some(&lock_path), store.as_deref())?;
    let mut lock_file: BTreeMap<String, [u8; 32]> =
        if lock_path.exists() { load_lock(&lock_path)? } else { BTreeMap::new() };
    let mut any_error = false;

    // L-12 runs once per invocation: the kernel triple re-emits on every
    // bench run (the freeze owns the pin comparison).
    for dg in lint::lint_kernel_reemission() {
        println!("kernel: {dg}");
        if dg.severity == Severity::Error {
            any_error = true;
        }
    }

    for f in &args.positional {
        let path = Path::new(f);
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let src = fs::read_to_string(path).map_err(|e| format!("{f}: {e}"))?;
        let ast = match script::parse(&src, ext) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("error {f}: {e}");
                any_error = true;
                continue;
            }
        };
        // L-07 detection needs the PRE-compile pin.
        let prior_pin = match &ast {
            script::Script::Stratum(s) => rz.lock.get(&s.name).copied(),
            _ => None,
        };
        let compiled = match compile(&ast, &mut rz) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("error {f}: {e}");
                any_error = true;
                continue;
            }
        };
        for note in &compiled.expansions {
            println!("note {f}: {note}");
        }
        // Lints (including document-level belt-and-suspenders).
        let mut diags = lint::lint(&ast, &compiled, &rz);
        diags.extend(lint::lint_document(&compiled));
        if let (Some(prev), script::Script::Stratum(s)) = (prior_pin, &ast) {
            if prev != compiled.hash
                && !s.items.iter().any(|i| matches!(i, script::Item::Supersedes { .. }))
            {
                diags.push(lint::Diagnostic {
                    rule: "L-07",
                    severity: Severity::Error,
                    line: 0,
                    msg: format!(
                        "`{}` was pinned at {}… and this compile changes it without a `supersedes` line — \
                         editing published terms compiles to version + supersedes (L-07)",
                        s.name,
                        &hex32(&prev)[..8]
                    ),
                });
            }
        }
        let (mut e, mut w, mut i) = (0, 0, 0);
        for dg in &diags {
            match dg.severity {
                Severity::Error => e += 1,
                Severity::Warn => w += 1,
                Severity::Info => i += 1,
            }
            println!("{f}: {dg}");
        }
        println!("{f}: {e} err / {w} warn / {i} info");
        if e > 0 {
            any_error = true;
            continue; // errors block publish
        }
        if lint_only {
            continue;
        }
        // Emit the artifact + constraints sidecar + lock line.
        if let Some(dir) = &out_dir {
            fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            let art = dir.join(format!("{}.ndf", hex32(&compiled.hash)));
            fs::write(&art, &compiled.bytes).map_err(|e| format!("{}: {e}", art.display()))?;
            println!("wrote {} ({} bytes)", art.display(), compiled.bytes.len());
            if let script::Script::Stratum(s) = &ast {
                let entries = lint::collect_constraints(s);
                if let Some(stub) = lint::constraints_stub(&s.name, &entries) {
                    let sp = dir.join(format!("{}-constraints.ndfs", s.name));
                    fs::write(&sp, stub).map_err(|e| format!("{}: {e}", sp.display()))?;
                    println!("wrote {} (L-13 sidecar stub)", sp.display());
                }
            }
        }
        lock_file.insert(compiled.petname.clone(), compiled.hash);
        println!("{} = {}", compiled.petname, hex32(&compiled.hash));
    }

    if !lint_only && !args.positional.is_empty() {
        save_lock(&lock_path, &lock_file)?;
        println!("lock updated: {}", lock_path.display());
    }
    Ok(!any_error)
}

fn cmd_doc(args: &Args) -> Result<bool, String> {
    let Some(target) = args.positional.first() else {
        return Err("doc needs a .ndfs file or a pinned petname".into());
    };
    let lock_path = args.flags.get("lock").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("Atelier.lock"));
    let store = args.flags.get("store").map(PathBuf::from);
    if target.ends_with(".ndfs") {
        let src = fs::read_to_string(target).map_err(|e| format!("{target}: {e}"))?;
        let ast = script::parse_stratum(&src).map_err(|e| format!("{target}: {e}"))?;
        let mut rz = seed_resolver(Some(&lock_path), store.as_deref())?;
        let compiled = compile(&script::Script::Stratum(ast), &mut rz).map_err(|e| format!("{target}: {e}"))?;
        if let Document::Vocabulary(v) = &compiled.document {
            print!("{}", doccard::card(v, &hex32(&compiled.hash)[..8]));
        }
        return Ok(true);
    }
    // A petname: resolve through the lock + store.
    let rz = seed_resolver(Some(&lock_path), store.as_deref())?;
    let Some(h) = rz.lock.get(target) else {
        return Err(format!("petname `{target}` is not in {}", lock_path.display()));
    };
    let Some(v) = rz.vocabularies.get(h) else {
        return Err(format!(
            "`{target}` is pinned but its artifact is not in the store — pass --store <dir> with {}.ndf present",
            hex32(h)
        ));
    };
    print!("{}", doccard::card(v, &hex32(h)[..8]));
    Ok(true)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = argv.first().map(String::as_str) else {
        eprintln!("usage: ndn-bench <compile|lint|doc|vectors|freeze> …");
        return ExitCode::from(2);
    };
    let args = parse_args(&argv[1..]);
    let result: Result<bool, String> = match cmd {
        "compile" => cmd_compile_or_lint(&args, false),
        "lint" => cmd_compile_or_lint(&args, true),
        "doc" => cmd_doc(&args),
        "vectors" => {
            let dir = args.positional.first().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("conformance/vectors"));
            let record = args.switches.iter().any(|s| s == "record");
            let (report, _pass, fail, _skip) = vectors::run_dir(&dir, record);
            print!("{report}");
            Ok(fail == 0)
        }
        "freeze" => {
            let fp = ndn_manifest::kernel::fixed_point();
            if args.switches.iter().any(|s| s == "pin") {
                let root = args
                    .flags
                    .get("workspace")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("."));
                match freeze::pin(&root) {
                    Ok(msg) => {
                        println!("{msg}");
                        Ok(true)
                    }
                    Err(e) => Err(e),
                }
            } else {
                print!("{}", freeze::report(&fp));
                Ok(true)
            }
        }
        other => Err(format!("unknown command {other:?}")),
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
