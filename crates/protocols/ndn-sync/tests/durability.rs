//! Durability conformance of the persistent [`DataStore`] (`BackendStore`)
//! over both on-disk engines, fjall and redb — the two guarantees of the
//! trait's `# Durability` section, each checked against a real process kill.
//!
//! Every case runs its writer in a child process: this test binary re-executed
//! (`std::env::current_exe()`) with `--exact <child test> --ignored
//! --nocapture` and the environment naming its engine and directory. The child
//! tests are `#[ignore]` and return at once without that environment, so a
//! plain run (cargo test or cargo-nextest) only runs the parents. The child
//! reports on stderr one line per step it completed; the parent SIGKILLs it
//! (`Child::kill`) while it keeps writing, then reads what it reported before
//! dying. Only whole lines count: a line cut by the kill claims nothing.
//!
//! # Case 1 — a write that returned survives `kill -9`
//!
//! The child opens TWO stores of one engine in different directories (a
//! device store and a separate local store, as ndn-data and ndf do) and
//! inserts numbered keys into each, alternately, reporting each insert after
//! it returned. The parent kills it right after a chosen report, reopens both
//! stores, and requires every reported key with its exact value — in its own
//! store, and only there. The kernel is untouched by a process kill, so what
//! this checks is that a returned write is out of the process: in the engine's
//! file as the OS holds it, not in a user-space buffer.
//!
//! # Case 2 — a write before a returned `sync` survives a power loss
//!
//! The child runs under an `LD_PRELOAD` *fsync shadow* (`tests/durability/
//! fsync_shadow.c`, compiled here with `cc`) and commits numbered changes:
//! `DataStore::insert`s, `DataStore::remove`s and three-key
//! `SyncBackend::write_batch`es on the store's backend (each batch must land
//! whole or not at all). After some commits it calls a sync — a
//! `DataStore::sync` after an insert, a `SyncBackend::sync` after a batch —
//! and reports the last commit it covers; it keeps committing and is
//! SIGKILLed.
//!
//! What the shadow records, and so what is simulated:
//!
//! - **File data becomes durable only at `fsync`/`fdatasync`** (and
//!   `syncfs`/`sync`): at each such call on a file under the store's root,
//!   the file's whole current content is copied into the shadow.
//!   `sync_file_range` makes nothing durable (it flushes neither metadata nor
//!   the disk's cache) and is not interposed.
//! - **A name (the file being there at all) is durable once any fsync
//!   followed it**, as on ext4, where an fsync commits the one metadata
//!   journal: at each fsync of a file or directory under the root, every
//!   file then under it is marked named. `rename*`, `unlink*` and `rmdir`
//!   are mirrored onto the shadow and the marks as they succeed.
//! - Only calls through libc are seen. rustix (under `tempfile`, which fjall
//!   uses to replace its metadata files) is built for this test with its
//!   libc backend (the `use-libc` dev-dependency) so its renames are seen too.
//!
//! From the files the OS held at the kill and the shadow, the parent builds
//! many power-loss images (a seeded RNG; the seed is in every failure
//! message). Per file, the image starts from the shadow — the content at the
//! last fsync — and keeps an arbitrary subset of the writes made after it,
//! at 512-byte-sector granularity:
//!
//! - a sector overwritten since the last fsync (redb rewrites pages; fjall
//!   rewrites nothing in place) holds its old or its new content;
//! - the file's length is anything between the fsynced and the current
//!   length, so an appended tail is cut at an arbitrary byte;
//! - an appended sector that did not land reads as zeros (the size grew, the
//!   data did not), and the last sector may hold garbage (a torn write);
//! - a file never fsynced is empty, a random prefix of its content, or that
//!   prefix padded with zeros to its full length — or absent, unless an
//!   fsync since its creation made its name durable.
//! - directories are always there.
//!
//! Each image must open without error, and hold exactly the state after
//! commits `0..=j` for some `j` at least the last commit a returned sync
//! covered: every earlier change kept, every batch whole, no later change
//! without all those before it. The files the OS held (no power cut) must
//! hold every commit the child reported.
//!
//! Not simulated: a disk that loses data it acknowledged as flushed, bit rot,
//! or a write torn inside a sector other than a file's last.

use std::collections::{BTreeMap, hash_map::DefaultHasher};
use std::ffi::OsString;
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_packet::Name;
use ndn_storage::{FjallBackend, RedbBackend, SyncBackend, WriteOp, name_key};
use ndn_sync::store::BackendStore;
use ndn_sync::svsync::DataStore;

/// Names the child's engine (`fjall` / `redb`); absent in a normal run.
const ENV_ENGINE: &str = "NDN_DURABILITY_ENGINE";
/// The directory the child keeps its stores in.
const ENV_DIR: &str = "NDN_DURABILITY_DIR";

/// How long the parent waits for the child's next line before it gives up.
const CHILD_SILENCE: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------- engines --

#[derive(Clone, Copy, Debug)]
enum Engine {
    Fjall,
    Redb,
}

impl Engine {
    fn label(self) -> &'static str {
        match self {
            Engine::Fjall => "fjall",
            Engine::Redb => "redb",
        }
    }

    fn from_label(s: &str) -> Engine {
        match s {
            "fjall" => Engine::Fjall,
            "redb" => Engine::Redb,
            other => panic!("{ENV_ENGINE}={other:?} names no engine; use fjall or redb"),
        }
    }

    /// Where store `name` lives under `dir`: a directory for fjall, a file
    /// for redb.
    fn path(self, dir: &Path, name: &str) -> PathBuf {
        match self {
            Engine::Fjall => dir.join(name),
            Engine::Redb => dir.join(format!("{name}.redb")),
        }
    }
}

/// A `BackendStore` over either engine.
enum Store {
    Fjall(BackendStore<FjallBackend>),
    Redb(BackendStore<RedbBackend>),
}

impl Store {
    fn open(engine: Engine, path: &Path) -> std::io::Result<Store> {
        Ok(match engine {
            Engine::Fjall => Store::Fjall(BackendStore::open_fjall(path)?),
            Engine::Redb => Store::Redb(BackendStore::open_redb(path)?),
        })
    }

    fn data(&self) -> &dyn DataStore {
        match self {
            Store::Fjall(s) => s,
            Store::Redb(s) => s,
        }
    }

    fn backend(&self) -> &dyn SyncBackend {
        match self {
            Store::Fjall(s) => s.backend(),
            Store::Redb(s) => s.backend(),
        }
    }

    /// Every `(key, value)` under `/dur`, read through the backend so a read
    /// error is an error, not an empty store.
    fn contents(&self) -> Result<BTreeMap<Vec<u8>, Bytes>, String> {
        self.backend()
            .scan_prefix(&name_key(&n("/dur")), 0)
            .map(|v| v.into_iter().map(|(k, v)| (k.to_vec(), v)).collect())
            .map_err(|e| format!("reading the store back failed: {e}"))
    }
}

fn n(s: &str) -> Name {
    s.parse().expect("test name parses")
}

fn show(key: &[u8]) -> String {
    Name::decode(Bytes::copy_from_slice(key))
        .map(|n| n.to_string())
        .unwrap_or_else(|_| format!("{key:02x?}"))
}

/// The value written for commit `i` under `tag`: ~40-160 bytes that name it.
fn value(i: u64, tag: &str) -> Bytes {
    let mut v = format!("{tag}:{i}:").into_bytes();
    let pad = 40 + (i as usize * 37) % 120;
    v.extend((0..pad).map(|k| b'a' + ((i as usize + k) % 26) as u8));
    Bytes::from(v)
}

// ------------------------------------------------------ child plumbing ----

/// The child's environment, or `None` in a normal run.
fn child_env() -> Option<(Engine, PathBuf)> {
    let engine = std::env::var(ENV_ENGINE).ok()?;
    let dir = std::env::var_os(ENV_DIR)
        .unwrap_or_else(|| panic!("{ENV_ENGINE} is set but {ENV_DIR} is not; set both"));
    Some((Engine::from_label(&engine), PathBuf::from(dir)))
}

/// Report a completed step: one line, one `write` call.
fn say(line: String) {
    let mut line = line;
    line.push('\n');
    std::io::stderr()
        .write_all(line.as_bytes())
        .expect("reporting to the parent failed");
}

/// A running child and the whole lines it reported.
struct Writer {
    child: Child,
    lines: Receiver<String>,
    /// Everything else it printed (panics), for failure messages.
    other: Vec<String>,
}

impl Writer {
    fn spawn(test: &str, engine: Engine, dir: &Path, extra: &[(&str, OsString)]) -> Writer {
        let exe = std::env::current_exe().expect("the test binary's own path");
        let mut cmd = Command::new(exe);
        cmd.args([
            "--exact",
            test,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ENV_ENGINE, engine.label())
        .env(ENV_DIR, dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let mut child = cmd
            .spawn()
            .expect("re-executing the test binary as the writer");
        let stderr = child.stderr.take().expect("piped stderr");
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            let mut r = BufReader::new(stderr);
            let mut buf = Vec::new();
            loop {
                buf.clear();
                match r.read_until(b'\n', &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let s = String::from_utf8_lossy(&buf).into_owned();
                        // A line without its newline was cut by the kill: it
                        // claims nothing.
                        let s = match s.strip_suffix('\n') {
                            Some(whole) => whole.to_owned(),
                            None => format!("[cut by the kill] {s}"),
                        };
                        if tx.send(s).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Writer {
            child,
            lines,
            other: Vec::new(),
        }
    }

    /// The next line while the child runs; panics if it exits on its own or
    /// falls silent.
    fn next(&mut self) -> String {
        match self.lines.recv_timeout(CHILD_SILENCE) {
            Ok(l) => l,
            Err(RecvTimeoutError::Timeout) => {
                let _ = self.child.kill();
                panic!(
                    "the writer printed nothing for {CHILD_SILENCE:?}; it hangs (a sync that \
                     never returns?). Its other output: {:?}",
                    self.other
                );
            }
            Err(RecvTimeoutError::Disconnected) => {
                let status = self.child.wait().ok();
                panic!(
                    "the writer exited ({status:?}) before it was killed; its output: {:?}",
                    self.other
                );
            }
        }
    }

    /// SIGKILL the child, wait for it, and return every whole line it
    /// reported before it died.
    fn kill(mut self) -> (Vec<String>, Vec<String>) {
        self.child.kill().expect("SIGKILL the writer");
        self.child.wait().expect("reap the writer");
        let rest: Vec<String> = self.lines.iter().collect();
        (rest, self.other)
    }
}

// ------------------------------------------------------------- case 1 ----

/// Child of case 1: two stores, alternate inserts, a report after each.
#[test]
#[ignore = "child process of kill_9_keeps_every_returned_write_*; run by it, not alone"]
fn child_kill_writer() {
    let Some((engine, dir)) = child_env() else {
        return;
    };
    let device = Store::open(engine, &engine.path(&dir, "device")).expect("open device store");
    let local = Store::open(engine, &engine.path(&dir, "local")).expect("open local store");
    for i in 0u64.. {
        device
            .data()
            .insert(n(&format!("/dur/d/{i:08}")), value(i, "d"));
        say(format!("ok d {i}"));
        local
            .data()
            .insert(n(&format!("/dur/l/{i:08}")), value(i, "l"));
        say(format!("ok l {i}"));
    }
}

fn kill_9_keeps_every_returned_write(engine: Engine) {
    let mut rng = fastrand::Rng::with_seed(0x6b69_6c6c ^ engine as u64);
    for round in 0..3 {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path();
        let kill_after = rng.u64(150..400);
        let mut w = Writer::spawn("child_kill_writer", engine, dir, &[]);
        let mut reported = Vec::new();
        loop {
            let line = w.next();
            let done = line == format!("ok l {kill_after}");
            if line.starts_with("ok ") {
                reported.push(line);
            } else {
                w.other.push(line);
            }
            if done {
                break;
            }
        }
        let (rest, other) = w.kill();
        reported.extend(rest.into_iter().filter(|l| l.starts_with("ok ")));

        let device = Store::open(engine, &engine.path(dir, "device"))
            .unwrap_or_else(|e| panic!("{engine:?} round {round}: device store reopen: {e}"));
        let local = Store::open(engine, &engine.path(dir, "local"))
            .unwrap_or_else(|e| panic!("{engine:?} round {round}: local store reopen: {e}"));
        let held = [
            device.contents().expect("device contents"),
            local.contents().expect("local contents"),
        ];
        let mut lost = Vec::new();
        for line in &reported {
            let mut parts = line.split(' ').skip(1);
            let (which, i) = (parts.next().unwrap(), parts.next().unwrap());
            let i: u64 = i.parse().expect("reported index");
            let (store, own, other_store) = match which {
                "d" => (0, "device", 1),
                _ => (1, "local", 0),
            };
            let key = name_key(&n(&format!("/dur/{which}/{i:08}")));
            if held[store].get(&key) != Some(&value(i, which)) {
                lost.push(format!("{} (in the {own} store)", show(&key)));
            }
            assert!(
                !held[other_store].contains_key(&key),
                "{engine:?} round {round}: {} turned up in the other store; the two \
                 instances must be separate",
                show(&key)
            );
        }
        assert!(
            lost.is_empty(),
            "{engine:?} round {round}: {} of {} inserts that had returned before kill -9 \
             are missing or changed after reopening: {:?}…; the writer's other output: {other:?}",
            lost.len(),
            reported.len(),
            &lost[..lost.len().min(10)],
        );
    }
}

#[test]
fn kill_9_keeps_every_returned_write_fjall() {
    kill_9_keeps_every_returned_write(Engine::Fjall);
}

#[test]
fn kill_9_keeps_every_returned_write_redb() {
    kill_9_keeps_every_returned_write(Engine::Redb);
}

// ------------------------------------------------------------- case 2 ----

/// One numbered change the power-loss writer makes.
enum Commit {
    Insert(Name, Bytes),
    Remove(Name),
    Batch(Vec<(Name, Bytes)>),
}

fn commit(i: u64) -> Commit {
    match i % 4 {
        0 | 2 => Commit::Insert(n(&format!("/dur/s/{i:08}")), value(i, "s")),
        1 => Commit::Batch(vec![
            (n(&format!("/dur/b/{i:08}/a")), value(i, "a")),
            (n(&format!("/dur/b/{i:08}/b")), value(i, "b")),
            (n("/dur/head"), value(i, "head")),
        ]),
        // Drop an earlier insert (commit i - 3 inserted it).
        _ => Commit::Remove(n(&format!("/dur/s/{:08}", i - 3))),
    }
}

/// The sync to call after commit `i`, if any: `DataStore::sync` after an
/// insert (it covers the store's own writes), `SyncBackend::sync` after a
/// batch made directly on the backend (which the store does not count).
/// Each is the only sync at its point, so neither hides the other's fault.
fn sync_after(i: u64) -> Option<Barrier> {
    match i % 24 {
        2 => Some(Barrier::Store),
        13 => Some(Barrier::Backend),
        _ => None,
    }
}

enum Barrier {
    Store,
    Backend,
}

fn apply(map: &mut BTreeMap<Vec<u8>, Bytes>, c: &Commit) {
    match c {
        Commit::Insert(name, v) => {
            map.insert(name_key(name), v.clone());
        }
        Commit::Remove(name) => {
            map.remove(&name_key(name));
        }
        Commit::Batch(puts) => {
            for (name, v) in puts {
                map.insert(name_key(name), v.clone());
            }
        }
    }
}

/// Child of case 2: commits forever, syncing at `sync_after` points.
#[test]
#[ignore = "child process of power_loss_keeps_everything_before_sync_*; run by it, not alone"]
fn child_power_writer() {
    let Some((engine, dir)) = child_env() else {
        return;
    };
    let store = Store::open(engine, &engine.path(&dir, "store")).expect("open store");
    for i in 0u64.. {
        match commit(i) {
            Commit::Insert(name, v) => store.data().insert(name, v),
            Commit::Remove(name) => store.data().remove(&name),
            Commit::Batch(puts) => store
                .backend()
                .write_batch(
                    puts.into_iter()
                        .map(|(name, v)| WriteOp::Put(name_key(&name), v))
                        .collect(),
                )
                .expect("write_batch"),
        }
        say(format!("c {i}"));
        match sync_after(i) {
            Some(Barrier::Store) => store.data().sync().expect("DataStore::sync"),
            Some(Barrier::Backend) => store.backend().sync().expect("SyncBackend::sync"),
            None => continue,
        }
        say(format!("synced {i}"));
    }
}

/// Order-independent digest of a store's content: per-entry hashes summed.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
struct Digest {
    sum: u64,
    count: usize,
}

fn entry_hash(k: &[u8], v: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    k.hash(&mut h);
    v.hash(&mut h);
    h.finish()
}

fn digest(map: &BTreeMap<Vec<u8>, Bytes>) -> Digest {
    map.iter().fold(Digest::default(), |d, (k, v)| Digest {
        sum: d.sum.wrapping_add(entry_hash(k, v)),
        count: d.count + 1,
    })
}

/// `digests[j + 1]` = digest of the state after commits `0..=j`
/// (`digests[0]` = empty), for `j` up to `last`.
fn state_digests(last: u64) -> Vec<Digest> {
    let mut map = BTreeMap::new();
    let mut out = vec![Digest::default()];
    for i in 0..=last {
        apply(&mut map, &commit(i));
        out.push(digest(&map));
    }
    out
}

fn state_after(j: i64) -> BTreeMap<Vec<u8>, Bytes> {
    let mut map = BTreeMap::new();
    for i in 0..=j {
        apply(&mut map, &commit(i as u64));
    }
    map
}

/// Which `j` (`-1` = nothing) in `lo..=hi` the content is the state after.
fn matching_state(
    content: &BTreeMap<Vec<u8>, Bytes>,
    digests: &[Digest],
    lo: i64,
    hi: i64,
) -> Option<i64> {
    let d = digest(content);
    (lo..=hi).rev().find(|&j| digests[(j + 1) as usize] == d)
}

/// Why `content` is not the state after any `j >= synced`.
fn explain(content: &BTreeMap<Vec<u8>, Bytes>, synced: i64) -> String {
    let want = state_after(synced);
    let missing: Vec<String> = want
        .iter()
        .filter(|(k, v)| content.get(*k) != Some(v))
        .take(6)
        .map(|(k, _)| show(k))
        .collect();
    let head = content
        .get(&name_key(&n("/dur/head")))
        .map(|v| String::from_utf8_lossy(&v[..v.len().min(16)]).into_owned());
    format!(
        "{} entries, head {head:?}; synced entries missing or changed: {missing:?}",
        content.len()
    )
}

const SECTOR: usize = 512;

/// `src[start..end]`, cut at `src`'s end.
fn clip(src: &[u8], start: usize, end: usize) -> &[u8] {
    &src[start.min(src.len())..end.min(src.len())]
}

/// What one file holds after a power loss: `shadow` is its content at the
/// last fsync (`None`: never fsynced), `now` what the OS held at the kill,
/// `named` whether an fsync since its creation made its name durable.
fn after_power_loss(
    shadow: Option<&[u8]>,
    now: &[u8],
    named: bool,
    rng: &mut fastrand::Rng,
) -> Option<Vec<u8>> {
    let Some(old) = shadow else {
        return match rng.u8(if named { 1..4 } else { 0..4 }) {
            0 => None,
            1 => Some(Vec::new()),
            2 => Some(now[..rng.usize(0..=now.len())].to_vec()),
            _ => {
                let mut v = now[..rng.usize(0..=now.len())].to_vec();
                v.resize(now.len(), 0);
                Some(v)
            }
        };
    };
    if old == now {
        return Some(now.to_vec());
    }
    let (lo, hi) = (old.len().min(now.len()), old.len().max(now.len()));
    let len = match rng.u8(0..4) {
        0 => old.len(),
        1 => now.len(),
        _ => rng.usize(lo..=hi),
    };
    // The chance that a sector written since the last fsync landed.
    let landed = match rng.u8(0..4) {
        0 => 0.0,
        1 => 1.0,
        _ => rng.f64(),
    };
    let mut out = Vec::with_capacity(len);
    for start in (0..len).step_by(SECTOR) {
        let end = (start + SECTOR).min(len);
        let (was, is) = (clip(old, start, end), clip(now, start, end));
        if was == is && was.len() == end - start {
            out.extend_from_slice(is); // not written since the last fsync
        } else if rng.f64() < landed {
            // Landed: the new bytes (the old ones where the file shrank).
            out.extend_from_slice(is);
            out.extend_from_slice(clip(old, start + is.len(), end));
        } else {
            // Not landed: the old bytes, zeros where the file grew.
            out.extend_from_slice(was);
        }
        out.resize(end, 0);
    }
    if len > old.len() && rng.u8(0..4) == 0 {
        // A torn last sector: garbage past what was fsynced.
        let from = old.len().max(len.saturating_sub(SECTOR));
        for b in &mut out[from..] {
            *b = rng.u8(..);
        }
    }
    Some(out)
}

/// Every file and directory under `root`, relative to it.
fn walk(root: &Path, rel: &Path, files: &mut Vec<PathBuf>, dirs: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(root.join(rel)).expect("read_dir") {
        let e = e.expect("dir entry");
        let rel = rel.join(e.file_name());
        let ty = e.file_type().expect("file type");
        if ty.is_dir() {
            dirs.push(rel.clone());
            walk(root, &rel, files, dirs);
        } else if ty.is_file() {
            files.push(rel);
        }
    }
}

/// One file of the tree the OS held at the kill.
struct KilledFile {
    path: PathBuf,
    /// Its content at the kill.
    now: Vec<u8>,
    /// Its content at the last fsync (`None`: never fsynced).
    shadow: Option<Vec<u8>>,
    /// Whether an fsync since its creation made its name durable.
    named: bool,
}

/// The tree the OS held at the kill, with what the fsync shadow recorded.
struct Killed {
    dirs: Vec<PathBuf>,
    files: Vec<KilledFile>,
}

fn load_killed(real: &Path, shadow: &Path) -> Killed {
    let (mut files, mut dirs) = (Vec::new(), Vec::new());
    walk(real, Path::new(""), &mut files, &mut dirs);
    files.sort();
    let files = files
        .into_iter()
        .map(|path| KilledFile {
            now: std::fs::read(real.join(&path)).expect("read real file"),
            shadow: std::fs::read(shadow.join(&path)).ok(),
            named: shadow.join(".names").join(&path).exists(),
            path,
        })
        .collect();
    Killed { dirs, files }
}

/// Write `data` to a new file at `path`, leaving all-zero 64 KiB runs as
/// holes (fjall's journal is a mostly-empty preallocated file).
fn write_sparse(path: &Path, data: &[u8]) {
    use std::os::unix::fs::FileExt;
    const RUN: usize = 1 << 16;
    static ZEROS: [u8; RUN] = [0; RUN];
    let f = std::fs::File::create(path).expect("create image file");
    f.set_len(data.len() as u64).expect("size image file");
    for (i, run) in data.chunks(RUN).enumerate() {
        if run != &ZEROS[..run.len()] {
            f.write_all_at(run, (i * RUN) as u64)
                .expect("write image file");
        }
    }
}

/// Build in `out` what the killed tree holds after a power loss.
fn power_loss_image(killed: &Killed, out: &Path, rng: &mut fastrand::Rng) {
    std::fs::create_dir_all(out).expect("image dir");
    for d in &killed.dirs {
        std::fs::create_dir_all(out.join(d)).expect("image subdir");
    }
    for f in &killed.files {
        if let Some(content) = after_power_loss(f.shadow.as_deref(), &f.now, f.named, rng) {
            write_sparse(&out.join(&f.path), &content);
        }
    }
}

/// Compile the fsync shadow into `dir`.
fn build_shadow_lib(dir: &Path) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/durability/fsync_shadow.c");
    let lib = dir.join("libfsync_shadow.so");
    let out = Command::new("cc")
        .args(["-shared", "-fPIC", "-O2", "-o"])
        .arg(&lib)
        .arg(&src)
        .arg("-ldl")
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "the power-loss test builds an LD_PRELOAD fsync shadow with `cc` and could not \
                 run it ({e}); install a C compiler (gcc or clang) as `cc` on PATH"
            )
        });
    assert!(
        out.status.success(),
        "compiling {} failed: {}; fix the fixture or the C toolchain",
        src.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    lib
}

const IMAGES: u64 = 64;

fn power_loss_keeps_everything_before_sync(engine: Engine) {
    let seed = 0x7077_726c ^ engine as u64;
    let mut rng = fastrand::Rng::with_seed(seed);
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().canonicalize().expect("canonical tempdir");
    let (root, shadow, images) = (base.join("root"), base.join("shadow"), base.join("images"));
    for d in [&root, &shadow, &images] {
        std::fs::create_dir(d).expect("mkdir");
    }
    let lib = build_shadow_lib(&base);

    let mut w = Writer::spawn(
        "child_power_writer",
        engine,
        &root,
        &[
            ("LD_PRELOAD", lib.into_os_string()),
            ("SHADOW_ROOT", root.clone().into_os_string()),
            ("SHADOW_OUT", shadow.clone().into_os_string()),
        ],
    );
    let (mut synced, mut committed) = (-1i64, -1i64);
    let note = |line: &str, synced: &mut i64, committed: &mut i64| -> bool {
        if let Some(i) = line.strip_prefix("synced ") {
            *synced = i.parse().expect("synced index");
        } else if let Some(i) = line.strip_prefix("c ") {
            *committed = i.parse().expect("commit index");
        } else {
            return false;
        }
        true
    };
    // Kill once a sync covered a fair history and commits went on past it
    // (sync points are 11 and 13 commits apart).
    while !(synced >= 120 && committed >= synced + 5) {
        let line = w.next();
        if !note(&line, &mut synced, &mut committed) {
            w.other.push(line);
        }
    }
    let (rest, other) = w.kill();
    for line in rest {
        note(&line, &mut synced, &mut committed);
    }

    let digests = state_digests(committed as u64 + 1);
    let store_path = engine.path(&root, "store");
    let killed = load_killed(&root, &shadow);
    let mut failures = Vec::new();
    for k in 0..IMAGES {
        let img = images.join(format!("{k}"));
        power_loss_image(&killed, &img, &mut rng);
        let opened = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let store = Store::open(engine, &engine.path(&img, "store"))
                .map_err(|e| format!("open failed: {e}"))?;
            store.contents()
        }));
        let _ = std::fs::remove_dir_all(&img);
        match opened {
            Ok(Ok(content)) => {
                if matching_state(&content, &digests, synced, committed + 1).is_none() {
                    failures.push(format!(
                        "image {k}: not the state after any commit from the last synced one \
                         on: {}",
                        explain(&content, synced)
                    ));
                }
            }
            Ok(Err(e)) => failures.push(format!("image {k}: {e}")),
            Err(_) => failures.push(format!("image {k}: open or read panicked")),
        }
    }
    assert!(
        failures.is_empty(),
        "{engine:?} (seed {seed:#x}): {} of {IMAGES} power-loss images break the barrier \
         (last synced commit {synced}, last reported commit {committed}):\n  {}\n\
         writer's other output: {other:?}",
        failures.len(),
        failures.join("\n  ")
    );

    // No power cut: the files the OS held hold every reported commit.
    let store = Store::open(engine, &store_path).expect("reopen after kill -9");
    let content = store.contents().expect("contents after kill -9");
    assert!(
        matching_state(&content, &digests, committed, committed + 1).is_some(),
        "{engine:?}: after kill -9 (no power loss) the store is not the state after the last \
         reported commit {committed}: {}",
        explain(&content, committed)
    );
}

#[test]
fn power_loss_keeps_everything_before_sync_fjall() {
    power_loss_keeps_everything_before_sync(Engine::Fjall);
}

#[test]
fn power_loss_keeps_everything_before_sync_redb() {
    power_loss_keeps_everything_before_sync(Engine::Redb);
}

// ------------------------------------------------------------ latency ----

/// Median and p99 of `samples`, which it sorts.
fn percentiles(samples: &mut [Duration]) -> (Duration, Duration) {
    samples.sort();
    let at = |q: f64| samples[((samples.len() - 1) as f64 * q).round() as usize];
    (at(0.5), at(0.99))
}

/// What an insert and a sync cost on this machine, through `BackendStore`:
/// each round inserts one ~100-byte value and then syncs it (so every sync
/// has a write to flush). Prints; asserts nothing about the numbers. Run:
/// `cargo test --release -p ndn-sync --test durability -- --ignored
/// --nocapture --exact measure_insert_and_sync_latency`.
#[test]
#[ignore = "a measurement, not a check; run it by name with --ignored --nocapture"]
fn measure_insert_and_sync_latency() {
    const SAMPLES: u64 = 2000;
    for engine in [Engine::Fjall, Engine::Redb] {
        let tmp = tempfile::tempdir().expect("tempdir");
        if let Ok(df) = Command::new("df").arg("-T").arg(tmp.path()).output() {
            print!("{}", String::from_utf8_lossy(&df.stdout));
        }
        let store = Store::open(engine, &engine.path(tmp.path(), "store")).expect("open store");
        let (mut insert, mut sync) = (Vec::new(), Vec::new());
        for i in 0..SAMPLES {
            let name = n(&format!("/dur/m/{i:08}"));
            let v = Bytes::from(vec![b'x'; 100]);
            let t = Instant::now();
            store.data().insert(name, v);
            insert.push(t.elapsed());
            let t = Instant::now();
            store.data().sync().expect("sync");
            sync.push(t.elapsed());
        }
        let (im, ip) = percentiles(&mut insert);
        let (sm, sp) = percentiles(&mut sync);
        println!(
            "{engine:?} over {SAMPLES} rounds: insert median {im:?} p99 {ip:?}; \
             sync median {sm:?} p99 {sp:?}"
        );
    }
}
