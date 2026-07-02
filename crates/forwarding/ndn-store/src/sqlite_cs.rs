//! Persistent content store backed by bundled [SQLite](https://sqlite.org)
//! via [rusqlite]. Available with the `sqlite-cs` feature.
//!
//! This is the Android persistent-CS backend: fjall's directory lock relies on
//! `std::fs::File::try_lock`, which returns `Unsupported` on
//! `target_os = "android"` (and fjall maps that to a hard error). SQLite's own
//! locking works there, and the `bundled` C amalgamation links cleanly into the
//! JNI `.so`. On desktop the engine keeps using [`FjallCs`](crate::FjallCs).
//!
//! Schema — one row per Data packet, keyed by the same NDN-lexicographic name
//! encoding [`FjallCs`](crate::FjallCs) uses (see [`crate::cs_keycodec`]) so
//! `CanBePrefix` lookups are `BLOB` range scans:
//!
//! ```sql
//! CREATE TABLE cs (
//!     key         BLOB    PRIMARY KEY,  -- name_to_key(name)
//!     stale_at    INTEGER NOT NULL,     -- u64 nanos, stored bit-cast as i64
//!     data        BLOB    NOT NULL,     -- wire-format Data
//!     last_access INTEGER NOT NULL      -- u64 nanos; drives true-LRU eviction
//! )
//! ```

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use ndn_packet::{Interest, Name};

use crate::cs_keycodec::{name_to_key, now_ns, prefix_upper_bound};
use crate::{ContentStore, CsCapacity, CsEntry, CsMeta, InsertResult};

/// Persistent CS backed by bundled SQLite. `max_bytes` bounds *logical* Data
/// bytes (the `data` column; excludes SQLite page overhead); rows survive
/// process restarts. Eviction is true-LRU on `last_access`.
pub struct SqliteCs {
    conn: Mutex<Connection>,
    max_bytes: AtomicUsize,
    current_bytes: AtomicUsize,
    entry_count: AtomicUsize,
}

/// `u64` nanos ⇄ SQLite `INTEGER` (i64). Bit-cast round-trips every value
/// exactly, including the `u64::MAX` "never stale" sentinel.
#[inline]
fn to_i64(v: u64) -> i64 {
    v as i64
}
#[inline]
fn from_i64(v: i64) -> u64 {
    v as u64
}

impl SqliteCs {
    /// Open (or create) a persistent CS at `path` (a single SQLite file).
    pub fn open(path: impl AsRef<std::path::Path>, max_bytes: usize) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        // Rollback journal (TRUNCATE), NOT WAL. The CS is single-process-
        // exclusive (only the tunnel/`:vpn` engine opens it), so WAL's
        // multi-reader concurrency is unused — and WAL's `-shm` mmap byte-range
        // locks are fragile on Android internal storage after a SIGKILL (the OS
        // kills the engine process without a graceful close, then service
        // restart reopens). That path fails with POSIX EAGAIN and never
        // recovers. A TRUNCATE rollback journal recovers cleanly on the next
        // open with only a single main-db-file lock. `busy_timeout` rides out
        // the brief contention while a dead handle's lock is still being
        // reclaimed during the service restart. synchronous=NORMAL is durable
        // across process death (only a true power-loss could lose the tail,
        // acceptable for a cache).
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "TRUNCATE")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS cs (\
                 key         BLOB    PRIMARY KEY, \
                 stale_at    INTEGER NOT NULL, \
                 data        BLOB    NOT NULL, \
                 last_access INTEGER NOT NULL\
             )",
            [],
        )?;
        conn.execute("CREATE INDEX IF NOT EXISTS cs_lru ON cs(last_access)", [])?;

        let (count, bytes): (i64, i64) = conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(data)), 0) FROM cs",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
            max_bytes: AtomicUsize::new(max_bytes),
            current_bytes: AtomicUsize::new(bytes as usize),
            entry_count: AtomicUsize::new(count as usize),
        })
    }

    /// Evict least-recently-used rows until `needed` more logical bytes fit.
    fn evict_to_fit(&self, conn: &Connection, needed: usize) {
        let max = self.max_bytes.load(Ordering::Relaxed);
        let mut current = self.current_bytes.load(Ordering::Relaxed);
        if current + needed <= max {
            return;
        }

        let mut victims: Vec<(Vec<u8>, usize)> = Vec::new();
        if let Ok(mut stmt) =
            conn.prepare("SELECT key, length(data) FROM cs ORDER BY last_access ASC")
            && let Ok(rows) = stmt.query_map([], |r| {
                let key: Vec<u8> = r.get(0)?;
                let len: i64 = r.get(1)?;
                Ok((key, len as usize))
            })
        {
            for row in rows.flatten() {
                if current + needed <= max {
                    break;
                }
                current = current.saturating_sub(row.1);
                victims.push(row);
            }
        }

        for (key, data_len) in &victims {
            if conn
                .execute("DELETE FROM cs WHERE key = ?1", [key.as_slice()])
                .is_ok()
            {
                self.current_bytes.fetch_sub(*data_len, Ordering::Relaxed);
                self.entry_count.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    /// Fetch `(stale_at, data)` for an exact key, refreshing `last_access`.
    fn fetch_exact(&self, conn: &Connection, key: &[u8]) -> Option<(u64, Bytes)> {
        let row: Option<(i64, Vec<u8>)> = conn
            .query_row("SELECT stale_at, data FROM cs WHERE key = ?1", [key], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .ok();
        let (stale_at, data) = row?;
        let _ = conn.execute(
            "UPDATE cs SET last_access = ?1 WHERE key = ?2",
            rusqlite::params![to_i64(now_ns()), key],
        );
        Some((from_i64(stale_at), Bytes::from(data)))
    }
}

impl ContentStore for SqliteCs {
    async fn get(&self, interest: &Interest) -> Option<CsEntry> {
        if self.entry_count.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let conn = self.conn.lock().ok()?;

        let comps = interest.name.components();
        let has_implicit_digest =
            !comps.is_empty() && comps.last().unwrap().typ == ndn_packet::tlv_type::IMPLICIT_SHA256;

        let entry = if has_implicit_digest {
            let data_name = Name::from_components(comps[..comps.len() - 1].iter().cloned());
            let key = name_to_key(&data_name);
            let (stale_at, data) = self.fetch_exact(&conn, &key)?;

            let expected_digest = &comps.last().unwrap().value;
            let actual = Sha256::digest(&data);
            if expected_digest.as_ref() != actual.as_slice() {
                return None;
            }
            CsEntry {
                data,
                stale_at,
                name: Arc::new(data_name),
            }
        } else if interest.selectors().can_be_prefix {
            let prefix_key = name_to_key(&interest.name);
            // First row (BLOB order = NDN lexicographic order) under the prefix.
            let found: Option<(Vec<u8>, i64, Vec<u8>)> = match prefix_upper_bound(&prefix_key) {
                Some(upper) => conn
                    .query_row(
                        "SELECT key, stale_at, data FROM cs \
                         WHERE key >= ?1 AND key < ?2 ORDER BY key ASC LIMIT 1",
                        rusqlite::params![prefix_key.as_slice(), upper.as_slice()],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .ok(),
                None => conn
                    .query_row(
                        "SELECT key, stale_at, data FROM cs \
                         WHERE key >= ?1 ORDER BY key ASC LIMIT 1",
                        [prefix_key.as_slice()],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .ok(),
            };
            let (key, stale_at, data) = found?;
            let name = crate::cs_keycodec::key_to_name(&key)?;
            let _ = conn.execute(
                "UPDATE cs SET last_access = ?1 WHERE key = ?2",
                rusqlite::params![to_i64(now_ns()), key.as_slice()],
            );
            CsEntry {
                data: Bytes::from(data),
                stale_at: from_i64(stale_at),
                name: Arc::new(name),
            }
        } else {
            let key = name_to_key(&interest.name);
            let (stale_at, data) = self.fetch_exact(&conn, &key)?;
            CsEntry {
                data,
                stale_at,
                name: interest.name.clone(),
            }
        };

        if interest.selectors().must_be_fresh && !entry.is_fresh(now_ns()) {
            return None;
        }
        Some(entry)
    }

    async fn insert(&self, data: Bytes, name: Arc<Name>, meta: CsMeta) -> InsertResult {
        let entry_bytes = data.len();
        let key = name_to_key(&name);
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return InsertResult::Skipped,
        };

        let old_len: Option<i64> = conn
            .query_row(
                "SELECT length(data) FROM cs WHERE key = ?1",
                [key.as_slice()],
                |r| r.get(0),
            )
            .ok();
        let was_present = old_len.is_some();
        if let Some(old) = old_len {
            self.current_bytes
                .fetch_sub(old as usize, Ordering::Relaxed);
        }

        self.evict_to_fit(&conn, entry_bytes);

        let res = conn.execute(
            "INSERT OR REPLACE INTO cs (key, stale_at, data, last_access) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                key.as_slice(),
                to_i64(meta.stale_at),
                data.as_ref(),
                to_i64(now_ns())
            ],
        );
        if res.is_err() {
            return InsertResult::Skipped;
        }

        self.current_bytes.fetch_add(entry_bytes, Ordering::Relaxed);
        if was_present {
            InsertResult::Replaced
        } else {
            self.entry_count.fetch_add(1, Ordering::Relaxed);
            InsertResult::Inserted
        }
    }

    async fn evict(&self, name: &Name) -> bool {
        let key = name_to_key(name);
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return false,
        };
        let old_len: Option<i64> = conn
            .query_row(
                "SELECT length(data) FROM cs WHERE key = ?1",
                [key.as_slice()],
                |r| r.get(0),
            )
            .ok();
        if let Some(old) = old_len
            && conn
                .execute("DELETE FROM cs WHERE key = ?1", [key.as_slice()])
                .is_ok()
        {
            self.current_bytes
                .fetch_sub(old as usize, Ordering::Relaxed);
            self.entry_count.fetch_sub(1, Ordering::Relaxed);
            return true;
        }
        false
    }

    fn capacity(&self) -> CsCapacity {
        CsCapacity::bytes(self.max_bytes.load(Ordering::Relaxed))
    }

    fn len(&self) -> usize {
        self.entry_count.load(Ordering::Relaxed)
    }

    fn current_bytes(&self) -> usize {
        self.current_bytes.load(Ordering::Relaxed)
    }

    fn set_capacity(&self, max_bytes: usize) {
        self.max_bytes.store(max_bytes, Ordering::Relaxed);
        if let Ok(conn) = self.conn.lock() {
            self.evict_to_fit(&conn, 0);
        }
    }

    fn variant_name(&self) -> &str {
        "sqlite"
    }

    async fn evict_prefix(&self, prefix: &Name, limit: Option<usize>) -> usize {
        let prefix_key = name_to_key(prefix);
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return 0,
        };
        let max = limit.unwrap_or(usize::MAX);
        let mut victims: Vec<(Vec<u8>, usize)> = Vec::new();

        let sql_collect = |stmt: &mut rusqlite::Statement, params: &[&dyn rusqlite::ToSql]| {
            if let Ok(rows) = stmt.query_map(params, |r| {
                let key: Vec<u8> = r.get(0)?;
                let len: i64 = r.get(1)?;
                Ok((key, len as usize))
            }) {
                rows.flatten().collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        };

        let collected = match prefix_upper_bound(&prefix_key) {
            Some(upper) => {
                let mut stmt = match conn.prepare(
                    "SELECT key, length(data) FROM cs WHERE key >= ?1 AND key < ?2 ORDER BY key ASC",
                ) {
                    Ok(s) => s,
                    Err(_) => return 0,
                };
                sql_collect(&mut stmt, &[&prefix_key as &dyn rusqlite::ToSql, &upper])
            }
            None => {
                let mut stmt = match conn
                    .prepare("SELECT key, length(data) FROM cs WHERE key >= ?1 ORDER BY key ASC")
                {
                    Ok(s) => s,
                    Err(_) => return 0,
                };
                sql_collect(&mut stmt, &[&prefix_key as &dyn rusqlite::ToSql])
            }
        };

        for row in collected.into_iter().take(max) {
            victims.push(row);
        }

        let mut evicted = 0;
        for (key, data_len) in &victims {
            if conn
                .execute("DELETE FROM cs WHERE key = ?1", [key.as_slice()])
                .is_ok()
            {
                self.current_bytes.fetch_sub(*data_len, Ordering::Relaxed);
                self.entry_count.fetch_sub(1, Ordering::Relaxed);
                evicted += 1;
            }
        }
        evicted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::{Interest, Name, NameComponent};
    use ndn_tlv::TlvWriter;

    fn arc_name(components: &[&str]) -> Arc<Name> {
        Arc::new(Name::from_components(components.iter().map(|s| {
            NameComponent::generic(Bytes::copy_from_slice(s.as_bytes()))
        })))
    }

    fn meta_fresh() -> CsMeta {
        CsMeta { stale_at: u64::MAX }
    }
    fn meta_stale() -> CsMeta {
        CsMeta { stale_at: 0 }
    }

    fn interest(components: &[&str]) -> Interest {
        Interest::new((*arc_name(components)).clone())
    }

    fn interest_fresh(components: &[&str]) -> Interest {
        use ndn_packet::tlv_type;
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                for comp in components {
                    w.write_tlv(tlv_type::NAME_COMPONENT, comp.as_bytes());
                }
            });
            w.write_tlv(tlv_type::MUST_BE_FRESH, &[]);
        });
        Interest::decode(w.finish()).unwrap()
    }

    fn interest_can_be_prefix(components: &[&str]) -> Interest {
        use ndn_packet::tlv_type;
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                for comp in components {
                    w.write_tlv(tlv_type::NAME_COMPONENT, comp.as_bytes());
                }
            });
            w.write_tlv(tlv_type::CAN_BE_PREFIX, &[]);
        });
        Interest::decode(w.finish()).unwrap()
    }

    fn tmp() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cs.sqlite");
        (dir, path)
    }

    #[tokio::test]
    async fn insert_then_exact_get() {
        let (_d, path) = tmp();
        let cs = SqliteCs::open(&path, 1 << 20).unwrap();
        let name = arc_name(&["a", "b"]);
        let data = Bytes::from_static(b"hello");
        assert_eq!(
            cs.insert(data.clone(), name.clone(), meta_fresh()).await,
            InsertResult::Inserted
        );
        let got = cs.get(&interest(&["a", "b"])).await.unwrap();
        assert_eq!(got.data, data);
        assert_eq!(cs.len(), 1);
        assert_eq!(cs.current_bytes(), 5);
    }

    #[tokio::test]
    async fn replace_updates_byte_accounting() {
        let (_d, path) = tmp();
        let cs = SqliteCs::open(&path, 1 << 20).unwrap();
        let name = arc_name(&["x"]);
        cs.insert(Bytes::from_static(b"aaaa"), name.clone(), meta_fresh())
            .await;
        assert_eq!(
            cs.insert(Bytes::from_static(b"bb"), name.clone(), meta_fresh())
                .await,
            InsertResult::Replaced
        );
        assert_eq!(cs.len(), 1);
        assert_eq!(cs.current_bytes(), 2);
    }

    #[tokio::test]
    async fn must_be_fresh_filters_stale() {
        let (_d, path) = tmp();
        let cs = SqliteCs::open(&path, 1 << 20).unwrap();
        cs.insert(Bytes::from_static(b"v"), arc_name(&["s"]), meta_stale())
            .await;
        assert!(cs.get(&interest(&["s"])).await.is_some());
        assert!(cs.get(&interest_fresh(&["s"])).await.is_none());
    }

    #[tokio::test]
    async fn can_be_prefix_returns_first_under_prefix() {
        let (_d, path) = tmp();
        let cs = SqliteCs::open(&path, 1 << 20).unwrap();
        cs.insert(
            Bytes::from_static(b"1"),
            arc_name(&["p", "a"]),
            meta_fresh(),
        )
        .await;
        cs.insert(
            Bytes::from_static(b"2"),
            arc_name(&["p", "b"]),
            meta_fresh(),
        )
        .await;
        let got = cs.get(&interest_can_be_prefix(&["p"])).await.unwrap();
        assert_eq!(got.name.components().len(), 2);
    }

    #[tokio::test]
    async fn lru_eviction_bounds_bytes() {
        let (_d, path) = tmp();
        // Cap at 10 bytes; each entry is 4 bytes of data.
        let cs = SqliteCs::open(&path, 10).unwrap();
        cs.insert(Bytes::from_static(b"aaaa"), arc_name(&["a"]), meta_fresh())
            .await;
        cs.insert(Bytes::from_static(b"bbbb"), arc_name(&["b"]), meta_fresh())
            .await;
        // Touch "a" so "b" is the LRU victim.
        let _ = cs.get(&interest(&["a"])).await;
        cs.insert(Bytes::from_static(b"cccc"), arc_name(&["c"]), meta_fresh())
            .await;
        assert!(cs.current_bytes() <= 10);
        assert!(cs.get(&interest(&["a"])).await.is_some());
        assert!(cs.get(&interest(&["b"])).await.is_none());
    }

    #[tokio::test]
    async fn survives_reopen() {
        let (_d, path) = tmp();
        {
            let cs = SqliteCs::open(&path, 1 << 20).unwrap();
            cs.insert(
                Bytes::from_static(b"persist"),
                arc_name(&["k"]),
                meta_fresh(),
            )
            .await;
        }
        let cs = SqliteCs::open(&path, 1 << 20).unwrap();
        assert_eq!(cs.len(), 1);
        assert_eq!(cs.current_bytes(), 7);
        assert!(cs.get(&interest(&["k"])).await.is_some());
    }

    #[tokio::test]
    async fn evict_prefix_removes_subtree() {
        let (_d, path) = tmp();
        let cs = SqliteCs::open(&path, 1 << 20).unwrap();
        cs.insert(
            Bytes::from_static(b"1"),
            arc_name(&["p", "a"]),
            meta_fresh(),
        )
        .await;
        cs.insert(
            Bytes::from_static(b"2"),
            arc_name(&["p", "b"]),
            meta_fresh(),
        )
        .await;
        cs.insert(Bytes::from_static(b"3"), arc_name(&["q"]), meta_fresh())
            .await;
        assert_eq!(cs.evict_prefix(&arc_name(&["p"]), None).await, 2);
        assert_eq!(cs.len(), 1);
        assert!(cs.get(&interest(&["q"])).await.is_some());
    }
}
