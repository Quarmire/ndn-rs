//! `.ndfv` conformance-vector runner (format ruled in FRICTION F42; the
//! format itself is documented in conformance/vectors/FORMAT.md).
//!
//! A vector is a small line-oriented text file:
//!
//! ```text
//! # comment
//! name: W-07-duplicate-map-key
//! bytes: 30 1c 4b 20 …            # hex, whitespace-tolerant
//! expect: reject DuplicateMapKey
//! ```
//!
//! Supported expectations this round (the honesty ledger in
//! conformance/vectors/LEDGER.md records what is NOT covered here):
//!
//! - `expect: roundtrip` — bytes decode; decode∘encode is byte-identical
//!   (R13, enforced inside the decoder). With a `golden: <64hex>` line the
//!   document hash must match; `--record` fills absent goldens (D-K8).
//! - `expect: reject <Code>` — bytes reject with exactly that typed code.
//! - `expect: hash-distinct` — `bytes:` and `bytes2:` both decode and their
//!   hashes differ (the W-14 NFC/NFD family).
//! - `expect: compile-ok` — `file: <script>` compiles with zero errors.
//! - `expect: compile-error <L-rule>` — the script fails with that rule.
//! - `expect: verdict <intent> <Express|Approximate|Refuse|Unresolved>` —
//!   with `dag:` (scripts, space-separated), `contract:` (script), and
//!   `admit:` (petnames) lines: compile everything, match, check.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use ndn_manifest::canon::{decode_document, document_hash};
use ndn_manifest::dag::FrozenDag;
use ndn_render_contract::{r#match, Budget, TrustFrontier, Verdict};

use crate::compile::{compile, Resolver};
use crate::lint;
use crate::script;

/// One parsed `.ndfv`.
#[derive(Debug, Default)]
pub struct Vector {
    /// Vector name (defaults to the file stem).
    pub name: String,
    /// Primary byte string.
    pub bytes: Option<Vec<u8>>,
    /// Secondary byte string (hash-distinct family).
    pub bytes2: Option<Vec<u8>>,
    /// Golden document hash (hex).
    pub golden: Option<String>,
    /// Script file (compile families), relative to the vector.
    pub file: Option<String>,
    /// DAG scripts (verdict family).
    pub dag: Vec<String>,
    /// Contract script (verdict family).
    pub contract: Option<String>,
    /// Admitted petnames (verdict family).
    pub admit: Vec<String>,
    /// The expectation line, split.
    pub expect: Vec<String>,
    /// Source path.
    pub path: PathBuf,
}

/// A run outcome.
#[derive(Debug)]
pub enum Outcome {
    /// Passed.
    Pass,
    /// Failed, with why.
    Fail(String),
    /// Skipped (unsupported expectation), with why — recorded, never padded.
    Skip(String),
    /// `--record` wrote a golden.
    Recorded(String),
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    (0..clean.len() / 2)
        .map(|i| u8::from_str_radix(&clean[2 * i..2 * i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Parse one `.ndfv` file.
pub fn parse_vector(path: &Path) -> Result<Vector, String> {
    let src = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut v = Vector {
        name: path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default(),
        path: path.to_path_buf(),
        ..Vector::default()
    };
    for raw in src.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, val)) = line.split_once(':') else {
            return Err(format!("{}: malformed line {line:?}", path.display()));
        };
        let val = val.trim();
        match key.trim() {
            "name" => v.name = val.into(),
            "bytes" => v.bytes = Some(parse_hex_bytes(val)?),
            "bytes2" => v.bytes2 = Some(parse_hex_bytes(val)?),
            "golden" => v.golden = Some(val.to_ascii_lowercase()),
            "file" => v.file = Some(val.into()),
            "dag" => v.dag = val.split_whitespace().map(String::from).collect(),
            "contract" => v.contract = Some(val.into()),
            "admit" => v.admit = val.split_whitespace().map(String::from).collect(),
            "expect" => v.expect = val.split_whitespace().map(String::from).collect(),
            other => return Err(format!("{}: unknown key {other:?}", path.display())),
        }
    }
    if v.expect.is_empty() {
        return Err(format!("{}: missing `expect:` line", path.display()));
    }
    Ok(v)
}

fn hex(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

fn compile_script_file(path: &Path, rz: &mut Resolver) -> Result<crate::compile::Compiled, String> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let src = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let ast = script::parse(&src, ext).map_err(|e| format!("{}: {e}", path.display()))?;
    compile(&ast, rz).map_err(|e| format!("{}: {e}", path.display()))
}

/// Run one vector. `record` fills missing goldens (and reports having done
/// so — goldens are recorded by the bench, never hand-computed: D-K8).
pub fn run_vector(v: &Vector, record: bool) -> Outcome {
    let kind = v.expect[0].as_str();
    match kind {
        "roundtrip" => {
            let Some(bytes) = &v.bytes else { return Outcome::Fail("roundtrip needs `bytes:`".into()) };
            match decode_document(bytes) {
                Ok(_) => {
                    let h = hex(&document_hash(bytes));
                    match (&v.golden, record) {
                        (Some(g), _) if *g == h => Outcome::Pass,
                        (Some(g), _) => Outcome::Fail(format!("golden mismatch: expected {g}, got {h}")),
                        (None, true) => Outcome::Recorded(h),
                        (None, false) => Outcome::Pass, // decode already proved R13
                    }
                }
                Err(r) => Outcome::Fail(format!("expected roundtrip, got reject {}", r.code())),
            }
        }
        "reject" => {
            let Some(code) = v.expect.get(1) else { return Outcome::Fail("reject needs a code".into()) };
            let Some(bytes) = &v.bytes else { return Outcome::Fail("reject needs `bytes:`".into()) };
            match decode_document(bytes) {
                Err(r) if r.code() == code => Outcome::Pass,
                Err(r) => Outcome::Fail(format!("expected reject {code}, got reject {}", r.code())),
                Ok(_) => Outcome::Fail(format!("expected reject {code}, but the bytes decoded")),
            }
        }
        "hash-distinct" => {
            let (Some(a), Some(b)) = (&v.bytes, &v.bytes2) else {
                return Outcome::Fail("hash-distinct needs `bytes:` and `bytes2:`".into());
            };
            if decode_document(a).is_err() || decode_document(b).is_err() {
                return Outcome::Fail("both byte strings must decode".into());
            }
            if document_hash(a) != document_hash(b) {
                Outcome::Pass
            } else {
                Outcome::Fail("hashes collide — the wire normalized something it must not (R5)".into())
            }
        }
        "compile-ok" | "compile-error" => {
            let Some(file) = &v.file else { return Outcome::Fail(format!("{kind} needs `file:`")) };
            let base = v.path.parent().unwrap_or(Path::new("."));
            let mut rz = Resolver::default();
            // Vector scripts may `use` each other: pre-compile every dag: line
            // in order into the resolver first.
            for dep in &v.dag {
                if let Err(e) = compile_script_file(&base.join(dep), &mut rz) {
                    return Outcome::Fail(format!("dep {dep}: {e}"));
                }
            }
            let result = compile_script_file(&base.join(file), &mut rz);
            match (kind, result) {
                ("compile-ok", Ok(compiled)) => {
                    // compile-ok also demands zero lint ERRORS.
                    let src = fs::read_to_string(base.join(file)).unwrap_or_default();
                    let ext = Path::new(file).extension().and_then(|e| e.to_str()).unwrap_or("");
                    if let Ok(ast) = script::parse(&src, ext) {
                        let diags = lint::lint(&ast, &compiled, &rz);
                        if let Some(e) = diags.iter().find(|d| d.severity == lint::Severity::Error) {
                            return Outcome::Fail(format!("lint error: {e}"));
                        }
                    }
                    Outcome::Pass
                }
                ("compile-ok", Err(e)) => Outcome::Fail(format!("expected compile-ok: {e}")),
                ("compile-error", Err(e)) => {
                    let want = v.expect.get(1).map(String::as_str).unwrap_or("");
                    if want.is_empty() || e.contains(&format!("[{want}]")) {
                        Outcome::Pass
                    } else {
                        Outcome::Fail(format!("expected [{want}], got: {e}"))
                    }
                }
                ("compile-error", Ok(compiled)) => {
                    // Maybe the error is a lint error rather than a compile error.
                    let want = v.expect.get(1).map(String::as_str).unwrap_or("");
                    let src = fs::read_to_string(base.join(file)).unwrap_or_default();
                    let ext = Path::new(file).extension().and_then(|e| e.to_str()).unwrap_or("");
                    if let Ok(ast) = script::parse(&src, ext) {
                        let diags = lint::lint(&ast, &compiled, &rz);
                        if diags
                            .iter()
                            .any(|d| d.severity == lint::Severity::Error && (want.is_empty() || d.rule == want))
                        {
                            return Outcome::Pass;
                        }
                    }
                    Outcome::Fail(format!("expected a [{want}] error, but the script compiled clean"))
                }
                _ => unreachable!(),
            }
        }
        "verdict" => {
            let (Some(intent), Some(want)) = (v.expect.get(1), v.expect.get(2)) else {
                return Outcome::Fail("verdict needs `expect: verdict <intent> <Verdict>`".into());
            };
            let Some(contract_file) = &v.contract else {
                return Outcome::Fail("verdict needs `contract:`".into());
            };
            let base = v.path.parent().unwrap_or(Path::new("."));
            let mut rz = Resolver::default();
            let mut dag = FrozenDag::new();
            let mut pets: BTreeMap<String, ndn_manifest::Hash> = BTreeMap::new();
            for dep in &v.dag {
                match compile_script_file(&base.join(dep), &mut rz) {
                    Ok(c) => {
                        if dag.insert_bytes(&c.bytes).is_err() {
                            return Outcome::Fail(format!("{dep}: emitted bytes failed decode"));
                        }
                        pets.insert(c.petname.clone(), c.hash);
                    }
                    Err(e) => return Outcome::Fail(format!("dag {dep}: {e}")),
                }
            }
            let ch = match compile_script_file(&base.join(contract_file), &mut rz) {
                Ok(c) => {
                    if dag.insert_bytes(&c.bytes).is_err() {
                        return Outcome::Fail("contract bytes failed decode".into());
                    }
                    c.hash
                }
                Err(e) => return Outcome::Fail(format!("contract: {e}")),
            };
            let mut frontier = TrustFrontier::new();
            for pet in &v.admit {
                match pets.get(pet) {
                    Some(h) => {
                        frontier.admit(*h);
                    }
                    None => return Outcome::Fail(format!("admit: unknown petname {pet}")),
                }
            }
            let ms = match r#match(&dag, &[ch], &frontier, Budget::generous()) {
                Ok(ms) => ms,
                Err(e) => return Outcome::Fail(format!("budget exceeded: {e:?}")),
            };
            let got = ms.iter().find(|m| &m.intent == intent).map(|m| &m.verdict);
            let ok = match (want.as_str(), got) {
                ("Express", Some(Verdict::Express)) => true,
                ("Approximate", Some(Verdict::Approximate(_))) => true,
                ("Refuse", Some(Verdict::Refuse)) => true,
                ("Unresolved", Some(Verdict::Unresolved(_))) => true,
                ("Mismatch", None) => true, // no Match at all — the third silence
                _ => false,
            };
            if ok {
                Outcome::Pass
            } else {
                Outcome::Fail(format!("expected {want}, got {got:?}"))
            }
        }
        other => Outcome::Skip(format!("unsupported expectation {other:?} — recorded in the ledger, never padded")),
    }
}

/// Run every `.ndfv` under a directory (recursively). Returns a report and
/// (pass, fail, skip) counts. With `record`, absent goldens are written back
/// into the vector files.
pub fn run_dir(dir: &Path, record: bool) -> (String, usize, usize, usize) {
    let mut files = Vec::new();
    collect_ndfv(dir, &mut files);
    files.sort();
    let mut report = String::new();
    let (mut pass, mut fail, mut skip) = (0usize, 0usize, 0usize);
    for f in &files {
        match parse_vector(f) {
            Err(e) => {
                fail += 1;
                let _ = writeln!(report, "FAIL {} — parse: {e}", f.display());
            }
            Ok(v) => match run_vector(&v, record) {
                Outcome::Pass => {
                    pass += 1;
                    let _ = writeln!(report, "pass {}", v.name);
                }
                Outcome::Recorded(golden) => {
                    pass += 1;
                    if let Ok(src) = fs::read_to_string(f) {
                        let mut out = src;
                        if !out.ends_with('\n') {
                            out.push('\n');
                        }
                        out.push_str(&format!("golden: {golden}\n"));
                        let _ = fs::write(f, out);
                    }
                    let _ = writeln!(report, "pass {} (golden recorded: {golden})", v.name);
                }
                Outcome::Fail(why) => {
                    fail += 1;
                    let _ = writeln!(report, "FAIL {} — {why}", v.name);
                }
                Outcome::Skip(why) => {
                    skip += 1;
                    let _ = writeln!(report, "skip {} — {why}", v.name);
                }
            },
        }
    }
    let _ = writeln!(report, "\n{pass} pass · {fail} fail · {skip} skip · {} total", files.len());
    (report, pass, fail, skip)
}

fn collect_ndfv(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                collect_ndfv(&p, out);
            } else if p.extension().and_then(|e| e.to_str()) == Some("ndfv") {
                out.push(p);
            }
        }
    }
}
