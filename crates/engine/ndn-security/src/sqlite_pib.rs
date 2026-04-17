//! SQLite-backed Public Info Base (PIB), wire-compatible with
//! `ndn-cxx`'s `pib-sqlite3` backend.
//!
//! # Compatibility
//!
//! An ndn-rs binary using `SqlitePib` should be able to open a `pib.db`
//! created by `ndnsec` (the ndn-cxx CLI) and operate on it without
//! corruption, and vice versa. To make that work, this module replicates
//! the ndn-cxx schema **bit-for-bit** — same tables, same indexes, same
//! triggers, same column types, same `wireEncode()`-based name storage.
//! Diverging from the schema in any way (adding `PRAGMA user_version`,
//! storing names as URI strings, omitting a trigger, ...) would silently
//! make the resulting database incompatible.
//!
//! Pinned to ndn-cxx tag `ndn-cxx-0.9.0`, commit
//! `0751bba88021b745c1a0ab7198efd279756c9a3c`, file
//! `ndn-cxx/security/pib/impl/pib-sqlite3.cpp` lines 33–186 (`DB_INIT`).
//!
//! # Storage conventions (MUST match ndn-cxx)
//!
//! - Default DB path: `$HOME/.ndn/pib.db` (with `TEST_HOME` and CWD
//!   fallbacks; see [`SqlitePib::open_default`]).
//! - All `Name` columns hold the **TLV wire encoding** of the Name
//!   (outer type `0x07` + length + components), not URI strings.
//! - The `key_bits` column holds raw public-key bytes — for
//!   ndn-cxx-issued keys, this is a DER-encoded `SubjectPublicKeyInfo`.
//! - The `certificate_data` column holds the full Data-packet wire
//!   encoding of the certificate.
//! - `tpm_locator` is stored as a UTF-8 string in a `BLOB` column.
//! - `PRAGMA foreign_keys=ON` is set at every connection open. Without
//!   it the `ON DELETE CASCADE` rules become no-ops, leaking orphan
//!   rows that `ndnsec` will then trip over.
//! - Default-row invariants are maintained by triggers, not by Rust
//!   code. `add_*` calls just `INSERT` and let the triggers do the
//!   rest. Mutating a row's `is_default` is also delegated.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use bytes::Bytes;
use ndn_packet::{Name, NameComponent, tlv_type};
use ndn_tlv::{TlvReader, TlvWriter};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use crate::pib::PibError;

/// Schema embedded character-for-character from ndn-cxx 0.9.0
/// `ndn-cxx/security/pib/impl/pib-sqlite3.cpp` lines 33–186. **Do not edit.**
/// Any divergence from this string will cause silent incompatibility with
/// `ndnsec` and other ndn-cxx tools that share the same `pib.db`.
const DB_INIT: &str = r#"
CREATE TABLE IF NOT EXISTS
  tpmInfo(
    tpm_locator           BLOB
  );

CREATE TABLE IF NOT EXISTS
  identities(
    id                    INTEGER PRIMARY KEY,
    identity              BLOB NOT NULL,
    is_default            INTEGER DEFAULT 0
  );

CREATE UNIQUE INDEX IF NOT EXISTS
  identityIndex ON identities(identity);

CREATE TRIGGER IF NOT EXISTS
  identity_default_before_insert_trigger
  BEFORE INSERT ON identities
  FOR EACH ROW
  WHEN NEW.is_default=1
  BEGIN
    UPDATE identities SET is_default=0;
  END;

CREATE TRIGGER IF NOT EXISTS
  identity_default_after_insert_trigger
  AFTER INSERT ON identities
  FOR EACH ROW
  WHEN NOT EXISTS
    (SELECT id
       FROM identities
       WHERE is_default=1)
  BEGIN
    UPDATE identities
      SET is_default=1
      WHERE identity=NEW.identity;
  END;

CREATE TRIGGER IF NOT EXISTS
  identity_default_update_trigger
  BEFORE UPDATE ON identities
  FOR EACH ROW
  WHEN NEW.is_default=1 AND OLD.is_default=0
  BEGIN
    UPDATE identities SET is_default=0;
  END;

CREATE TABLE IF NOT EXISTS
  keys(
    id                    INTEGER PRIMARY KEY,
    identity_id           INTEGER NOT NULL,
    key_name              BLOB NOT NULL,
    key_bits              BLOB NOT NULL,
    is_default            INTEGER DEFAULT 0,
    FOREIGN KEY(identity_id)
      REFERENCES identities(id)
      ON DELETE CASCADE
      ON UPDATE CASCADE
  );

CREATE UNIQUE INDEX IF NOT EXISTS
  keyIndex ON keys(key_name);

CREATE TRIGGER IF NOT EXISTS
  key_default_before_insert_trigger
  BEFORE INSERT ON keys
  FOR EACH ROW
  WHEN NEW.is_default=1
  BEGIN
    UPDATE keys
      SET is_default=0
      WHERE identity_id=NEW.identity_id;
  END;

CREATE TRIGGER IF NOT EXISTS
  key_default_after_insert_trigger
  AFTER INSERT ON keys
  FOR EACH ROW
  WHEN NOT EXISTS
    (SELECT id
       FROM keys
       WHERE is_default=1
         AND identity_id=NEW.identity_id)
  BEGIN
    UPDATE keys
      SET is_default=1
      WHERE key_name=NEW.key_name;
  END;

CREATE TRIGGER IF NOT EXISTS
  key_default_update_trigger
  BEFORE UPDATE ON keys
  FOR EACH ROW
  WHEN NEW.is_default=1 AND OLD.is_default=0
  BEGIN
    UPDATE keys
      SET is_default=0
      WHERE identity_id=NEW.identity_id;
  END;

CREATE TABLE IF NOT EXISTS
  certificates(
    id                    INTEGER PRIMARY KEY,
    key_id                INTEGER NOT NULL,
    certificate_name      BLOB NOT NULL,
    certificate_data      BLOB NOT NULL,
    is_default            INTEGER DEFAULT 0,
    FOREIGN KEY(key_id)
      REFERENCES keys(id)
      ON DELETE CASCADE
      ON UPDATE CASCADE
  );

CREATE UNIQUE INDEX IF NOT EXISTS
  certIndex ON certificates(certificate_name);

CREATE TRIGGER IF NOT EXISTS
  cert_default_before_insert_trigger
  BEFORE INSERT ON certificates
  FOR EACH ROW
  WHEN NEW.is_default=1
  BEGIN
    UPDATE certificates
      SET is_default=0
      WHERE key_id=NEW.key_id;
  END;

CREATE TRIGGER IF NOT EXISTS
  cert_default_after_insert_trigger
  AFTER INSERT ON certificates
  FOR EACH ROW
  WHEN NOT EXISTS
    (SELECT id
       FROM certificates
       WHERE is_default=1
         AND key_id=NEW.key_id)
  BEGIN
    UPDATE certificates
      SET is_default=1
      WHERE certificate_name=NEW.certificate_name;
  END;

CREATE TRIGGER IF NOT EXISTS
  cert_default_update_trigger
  BEFORE UPDATE ON certificates
  FOR EACH ROW
  WHEN NEW.is_default=1 AND OLD.is_default=0
  BEGIN
    UPDATE certificates
      SET is_default=0
      WHERE key_id=NEW.key_id;
  END;
"#;

/// Encode a `Name` to its canonical TLV wire form (outer type `0x07` +
/// length + components), as ndn-cxx's `Name::wireEncode()` produces.
/// This is the byte sequence stored in the `identity`, `key_name`, and
/// `certificate_name` BLOB columns of the SQLite PIB.
fn name_wire_encode(name: &Name) -> Vec<u8> {
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::NAME, |w| {
        for c in name.components() {
            w.write_tlv(c.typ, &c.value);
        }
    });
    w.finish().to_vec()
}

fn name_wire_decode(blob: &[u8]) -> Result<Name, PibError> {
    let mut reader = TlvReader::new(Bytes::copy_from_slice(blob));
    let (typ, value) = reader
        .read_tlv()
        .map_err(|e| PibError::Corrupt(format!("name TLV: {e:?}")))?;
    if typ != tlv_type::NAME {
        return Err(PibError::Corrupt(format!(
            "expected Name TLV (0x07), got 0x{typ:x}"
        )));
    }
    Name::decode(value).map_err(|e| PibError::Corrupt(format!("name body: {e:?}")))
}

/// SQLite-backed PIB, wire-compatible with ndn-cxx `pib-sqlite3`.
///
/// All public methods take `&self` and serialise through an internal
/// `Mutex<Connection>`. SQLite handles its own concurrency control, but
/// `rusqlite::Connection` is not `Sync` so we wrap it.
pub struct SqlitePib {
    conn: Mutex<Connection>,
    path: PathBuf,
}

impl SqlitePib {
    /// Open or create a `pib.db` at `path`, initialising the schema if
    /// absent. Equivalent to ndn-cxx's `PibSqlite3(location)` constructor
    /// when `location` points at a directory; here we expect the full
    /// file path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PibError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )
        .map_err(map_sqlite_err)?;

        // MANDATORY for ndn-cxx compatibility — without it, the cascade
        // rules on the `keys` and `certificates` foreign keys silently
        // become no-ops and orphan rows accumulate. ndn-cxx sets this on
        // every open (`pib-sqlite3.cpp:223`); we must too.
        conn.execute_batch("PRAGMA foreign_keys=ON;")
            .map_err(map_sqlite_err)?;

        // `IF NOT EXISTS` everywhere makes this idempotent — running
        // against an existing ndn-cxx-created DB is a no-op.
        conn.execute_batch(DB_INIT).map_err(map_sqlite_err)?;

        Ok(Self {
            conn: Mutex::new(conn),
            path,
        })
    }

    /// Open the default PIB at `$HOME/.ndn/pib.db`, mirroring
    /// `PibSqlite3()` with an empty location argument. Honours
    /// `TEST_HOME` first (for parity with ndn-cxx test harnesses), then
    /// `HOME`, then the current working directory.
    pub fn open_default() -> Result<Self, PibError> {
        let dir = if let Ok(p) = std::env::var("TEST_HOME") {
            PathBuf::from(p).join(".ndn")
        } else if let Ok(p) = std::env::var("HOME") {
            PathBuf::from(p).join(".ndn")
        } else {
            std::env::current_dir()?.join(".ndn")
        };
        Self::open(dir.join("pib.db"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Return the TPM locator string the PIB was last associated with,
    /// e.g. `"tpm-file:"` or `"tpm-file:/custom/path"`. `None` if no
    /// locator has ever been set on this DB.
    pub fn get_tpm_locator(&self) -> Result<Option<String>, PibError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let row = conn
            .query_row("SELECT tpm_locator FROM tpmInfo", [], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .optional()
            .map_err(map_sqlite_err)?;
        Ok(row.map(|bytes| String::from_utf8_lossy(&bytes).into_owned()))
    }

    /// Set the TPM locator string. Mirrors ndn-cxx's update-then-insert
    /// dance (no SQLite UPSERT was available when the schema was
    /// designed): try `UPDATE`, and if no row was affected, `INSERT`.
    pub fn set_tpm_locator(&self, locator: &str) -> Result<(), PibError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let updated = conn
            .execute(
                "UPDATE tpmInfo SET tpm_locator=?",
                params![locator.as_bytes()],
            )
            .map_err(map_sqlite_err)?;
        if updated == 0 {
            conn.execute(
                "INSERT INTO tpmInfo (tpm_locator) VALUES (?)",
                params![locator.as_bytes()],
            )
            .map_err(map_sqlite_err)?;
        }
        Ok(())
    }

    /// Add `identity` to the PIB. Idempotent: re-adding an existing
    /// identity is a no-op (the unique index on `identity` would otherwise
    /// reject it).
    pub fn add_identity(&self, identity: &Name) -> Result<(), PibError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let blob = name_wire_encode(identity);
        let existing: Option<i64> = conn
            .query_row(
                "SELECT id FROM identities WHERE identity=?",
                params![blob],
                |row| row.get(0),
            )
            .optional()
            .map_err(map_sqlite_err)?;
        if existing.is_none() {
            conn.execute(
                "INSERT INTO identities (identity) VALUES (?)",
                params![blob],
            )
            .map_err(map_sqlite_err)?;
        }
        Ok(())
    }

    pub fn has_identity(&self, identity: &Name) -> Result<bool, PibError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let blob = name_wire_encode(identity);
        Ok(conn
            .query_row(
                "SELECT id FROM identities WHERE identity=?",
                params![blob],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(map_sqlite_err)?
            .is_some())
    }

    /// Delete an identity and (via `ON DELETE CASCADE`) all keys and
    /// certificates rooted at it.
    pub fn delete_identity(&self, identity: &Name) -> Result<(), PibError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let blob = name_wire_encode(identity);
        conn.execute("DELETE FROM identities WHERE identity=?", params![blob])
            .map_err(map_sqlite_err)?;
        Ok(())
    }

    pub fn list_identities(&self) -> Result<Vec<Name>, PibError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let mut stmt = conn
            .prepare("SELECT identity FROM identities")
            .map_err(map_sqlite_err)?;
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(map_sqlite_err)?;
        let mut out = Vec::new();
        for row in rows {
            let blob = row.map_err(map_sqlite_err)?;
            out.push(name_wire_decode(&blob)?);
        }
        Ok(out)
    }

    /// Mark `identity` as the default. The trigger
    /// `identity_default_update_trigger` clears the previous default in
    /// the same operation, so callers do not need to do it manually.
    pub fn set_default_identity(&self, identity: &Name) -> Result<(), PibError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let blob = name_wire_encode(identity);
        let updated = conn
            .execute(
                "UPDATE identities SET is_default=1 WHERE identity=?",
                params![blob],
            )
            .map_err(map_sqlite_err)?;
        if updated == 0 {
            return Err(PibError::KeyNotFound(name_to_string(identity)));
        }
        Ok(())
    }

    pub fn get_default_identity(&self) -> Result<Option<Name>, PibError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let blob: Option<Vec<u8>> = conn
            .query_row(
                "SELECT identity FROM identities WHERE is_default=1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(map_sqlite_err)?;
        Ok(match blob {
            Some(b) => Some(name_wire_decode(&b)?),
            None => None,
        })
    }

    /// Add a key under an existing identity. The identity must already
    /// exist; ndn-cxx's `addKey` adds it implicitly via a subquery, so
    /// we do the same here. `key_bits` is the raw public-key bytes (for
    /// ndn-cxx-issued keys this is a DER `SubjectPublicKeyInfo`).
    pub fn add_key(
        &self,
        identity: &Name,
        key_name: &Name,
        key_bits: &[u8],
    ) -> Result<(), PibError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let id_blob = name_wire_encode(identity);
        let key_blob = name_wire_encode(key_name);
        // Ensure the identity exists first so the subquery in INSERT
        // resolves to a valid id (rather than NULL → NOT NULL violation).
        let existing: Option<i64> = conn
            .query_row(
                "SELECT id FROM identities WHERE identity=?",
                params![id_blob],
                |row| row.get(0),
            )
            .optional()
            .map_err(map_sqlite_err)?;
        if existing.is_none() {
            conn.execute(
                "INSERT INTO identities (identity) VALUES (?)",
                params![id_blob],
            )
            .map_err(map_sqlite_err)?;
        }

        // Existing key with same name → UPDATE the bits in place (matches
        // ndn-cxx behaviour at pib-sqlite3.cpp:376–377).
        let key_exists: Option<i64> = conn
            .query_row(
                "SELECT id FROM keys WHERE key_name=?",
                params![key_blob],
                |row| row.get(0),
            )
            .optional()
            .map_err(map_sqlite_err)?;
        if key_exists.is_some() {
            conn.execute(
                "UPDATE keys SET key_bits=? WHERE key_name=?",
                params![key_bits, key_blob],
            )
            .map_err(map_sqlite_err)?;
        } else {
            conn.execute(
                "INSERT INTO keys (identity_id, key_name, key_bits) \
                 VALUES ((SELECT id FROM identities WHERE identity=?), ?, ?)",
                params![id_blob, key_blob, key_bits],
            )
            .map_err(map_sqlite_err)?;
        }
        Ok(())
    }

    pub fn get_key_bits(&self, key_name: &Name) -> Result<Option<Vec<u8>>, PibError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let blob = name_wire_encode(key_name);
        conn.query_row(
            "SELECT key_bits FROM keys WHERE key_name=?",
            params![blob],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sqlite_err)
    }

    pub fn delete_key(&self, key_name: &Name) -> Result<(), PibError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let blob = name_wire_encode(key_name);
        conn.execute("DELETE FROM keys WHERE key_name=?", params![blob])
            .map_err(map_sqlite_err)?;
        Ok(())
    }

    pub fn list_keys(&self, identity: &Name) -> Result<Vec<Name>, PibError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let blob = name_wire_encode(identity);
        let mut stmt = conn
            .prepare(
                "SELECT key_name FROM keys \
                 JOIN identities ON keys.identity_id=identities.id \
                 WHERE identities.identity=?",
            )
            .map_err(map_sqlite_err)?;
        let rows = stmt
            .query_map(params![blob], |row| row.get::<_, Vec<u8>>(0))
            .map_err(map_sqlite_err)?;
        let mut out = Vec::new();
        for row in rows {
            let kb = row.map_err(map_sqlite_err)?;
            out.push(name_wire_decode(&kb)?);
        }
        Ok(out)
    }

    /// Mark `key_name` as the default key for its parent identity.
    pub fn set_default_key(&self, key_name: &Name) -> Result<(), PibError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let blob = name_wire_encode(key_name);
        let updated = conn
            .execute(
                "UPDATE keys SET is_default=1 WHERE key_name=?",
                params![blob],
            )
            .map_err(map_sqlite_err)?;
        if updated == 0 {
            return Err(PibError::KeyNotFound(name_to_string(key_name)));
        }
        Ok(())
    }

    /// Return the default key for `identity`, if one is set.
    pub fn get_default_key(&self, identity: &Name) -> Result<Option<Name>, PibError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let blob = name_wire_encode(identity);
        let row: Option<Vec<u8>> = conn
            .query_row(
                "SELECT key_name FROM keys \
                 JOIN identities ON keys.identity_id=identities.id \
                 WHERE identities.identity=? AND keys.is_default=1",
                params![blob],
                |row| row.get(0),
            )
            .optional()
            .map_err(map_sqlite_err)?;
        Ok(match row {
            Some(b) => Some(name_wire_decode(&b)?),
            None => None,
        })
    }

    /// Add a certificate under an existing key. The key must already
    /// exist (we don't auto-create it; ndn-cxx fails the foreign key
    /// constraint here too).
    pub fn add_certificate(
        &self,
        key_name: &Name,
        cert_name: &Name,
        cert_data: &[u8],
    ) -> Result<(), PibError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let key_blob = name_wire_encode(key_name);
        let cert_blob = name_wire_encode(cert_name);
        let existing: Option<i64> = conn
            .query_row(
                "SELECT id FROM certificates WHERE certificate_name=?",
                params![cert_blob],
                |row| row.get(0),
            )
            .optional()
            .map_err(map_sqlite_err)?;
        if existing.is_some() {
            conn.execute(
                "UPDATE certificates SET certificate_data=? WHERE certificate_name=?",
                params![cert_data, cert_blob],
            )
            .map_err(map_sqlite_err)?;
        } else {
            conn.execute(
                "INSERT INTO certificates (key_id, certificate_name, certificate_data) \
                 VALUES ((SELECT id FROM keys WHERE key_name=?), ?, ?)",
                params![key_blob, cert_blob, cert_data],
            )
            .map_err(map_sqlite_err)?;
        }
        Ok(())
    }

    pub fn get_certificate(&self, cert_name: &Name) -> Result<Option<Vec<u8>>, PibError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let blob = name_wire_encode(cert_name);
        conn.query_row(
            "SELECT certificate_data FROM certificates WHERE certificate_name=?",
            params![blob],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sqlite_err)
    }

    pub fn delete_certificate(&self, cert_name: &Name) -> Result<(), PibError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let blob = name_wire_encode(cert_name);
        conn.execute(
            "DELETE FROM certificates WHERE certificate_name=?",
            params![blob],
        )
        .map_err(map_sqlite_err)?;
        Ok(())
    }

    pub fn list_certificates(&self, key_name: &Name) -> Result<Vec<Name>, PibError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let blob = name_wire_encode(key_name);
        let mut stmt = conn
            .prepare(
                "SELECT certificate_name FROM certificates \
                 JOIN keys ON certificates.key_id=keys.id \
                 WHERE keys.key_name=?",
            )
            .map_err(map_sqlite_err)?;
        let rows = stmt
            .query_map(params![blob], |row| row.get::<_, Vec<u8>>(0))
            .map_err(map_sqlite_err)?;
        let mut out = Vec::new();
        for row in rows {
            let cb = row.map_err(map_sqlite_err)?;
            out.push(name_wire_decode(&cb)?);
        }
        Ok(out)
    }

    /// Mark `cert_name` as the default cert for its parent key.
    pub fn set_default_certificate(&self, cert_name: &Name) -> Result<(), PibError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let blob = name_wire_encode(cert_name);
        let updated = conn
            .execute(
                "UPDATE certificates SET is_default=1 WHERE certificate_name=?",
                params![blob],
            )
            .map_err(map_sqlite_err)?;
        if updated == 0 {
            return Err(PibError::CertNotFound(name_to_string(cert_name)));
        }
        Ok(())
    }

    pub fn get_default_certificate(&self, key_name: &Name) -> Result<Option<Vec<u8>>, PibError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let blob = name_wire_encode(key_name);
        conn.query_row(
            "SELECT certificate_data FROM certificates \
             JOIN keys ON certificates.key_id=keys.id \
             WHERE certificates.is_default=1 AND keys.key_name=?",
            params![blob],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sqlite_err)
    }
}

fn map_sqlite_err(e: rusqlite::Error) -> PibError {
    PibError::Corrupt(format!("sqlite: {e}"))
}

fn name_to_string(name: &Name) -> String {
    let mut s = String::new();
    for c in name.components() {
        s.push('/');
        for &b in c.value.iter() {
            if b.is_ascii_graphic() && b != b'/' {
                s.push(b as char);
            } else {
                s.push_str(&format!("%{b:02X}"));
            }
        }
    }
    if s.is_empty() { "/".into() } else { s }
}

#[allow(dead_code)]
fn _force_use(_c: NameComponent) {}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn comp(s: &'static str) -> NameComponent {
        NameComponent::generic(Bytes::from_static(s.as_bytes()))
    }
    fn name(parts: &[&'static str]) -> Name {
        Name::from_components(parts.iter().map(|p| comp(p)))
    }

    #[test]
    fn wire_roundtrip_through_name_helpers() {
        let n = name(&["alice", "KEY", "k1"]);
        let blob = name_wire_encode(&n);
        // Outer type=0x07, length, then 3 generic-component TLVs.
        assert_eq!(blob[0], 0x07);
        let decoded = name_wire_decode(&blob).unwrap();
        assert_eq!(decoded, n);
    }

    #[test]
    fn open_creates_schema() {
        let dir = tempdir().unwrap();
        let pib = SqlitePib::open(dir.path().join("pib.db")).unwrap();
        // Verify all four tables exist by reading sqlite_master.
        let conn = pib.conn.lock().unwrap();
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(
            tables,
            vec!["certificates", "identities", "keys", "tpmInfo"]
        );
    }

    #[test]
    fn identity_add_list_delete() {
        let dir = tempdir().unwrap();
        let pib = SqlitePib::open(dir.path().join("pib.db")).unwrap();
        let alice = name(&["alice"]);
        let bob = name(&["bob"]);
        pib.add_identity(&alice).unwrap();
        pib.add_identity(&bob).unwrap();
        pib.add_identity(&alice).unwrap(); // idempotent
        let listed = pib.list_identities().unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.contains(&alice));
        assert!(listed.contains(&bob));
        pib.delete_identity(&alice).unwrap();
        let listed = pib.list_identities().unwrap();
        assert_eq!(listed, vec![bob]);
    }

    #[test]
    fn first_identity_becomes_default_via_trigger() {
        let dir = tempdir().unwrap();
        let pib = SqlitePib::open(dir.path().join("pib.db")).unwrap();
        let alice = name(&["alice"]);
        pib.add_identity(&alice).unwrap();
        // The `identity_default_after_insert_trigger` should have promoted
        // the only row to default automatically.
        let def = pib.get_default_identity().unwrap();
        assert_eq!(def, Some(alice));
    }

    #[test]
    fn set_default_identity_clears_previous() {
        let dir = tempdir().unwrap();
        let pib = SqlitePib::open(dir.path().join("pib.db")).unwrap();
        let alice = name(&["alice"]);
        let bob = name(&["bob"]);
        pib.add_identity(&alice).unwrap();
        pib.add_identity(&bob).unwrap();
        // Alice was first → default. Promote bob and ensure alice is no
        // longer marked default (the update trigger handles this).
        pib.set_default_identity(&bob).unwrap();
        assert_eq!(pib.get_default_identity().unwrap(), Some(bob));
    }

    #[test]
    fn key_under_identity_with_cert() {
        let dir = tempdir().unwrap();
        let pib = SqlitePib::open(dir.path().join("pib.db")).unwrap();
        let alice = name(&["alice"]);
        let key1 = name(&["alice", "KEY", "k1"]);
        let cert1 = name(&["alice", "KEY", "k1", "self", "v=1"]);
        pib.add_identity(&alice).unwrap();
        pib.add_key(&alice, &key1, &[0xAA; 32]).unwrap();
        pib.add_certificate(&key1, &cert1, &[0xCC; 64]).unwrap();

        assert_eq!(pib.get_key_bits(&key1).unwrap().unwrap(), vec![0xAA; 32]);
        assert_eq!(pib.list_keys(&alice).unwrap(), vec![key1.clone()]);
        assert_eq!(pib.list_certificates(&key1).unwrap(), vec![cert1.clone()]);
        assert_eq!(pib.get_default_key(&alice).unwrap(), Some(key1.clone()));
        assert_eq!(
            pib.get_default_certificate(&key1).unwrap().unwrap(),
            vec![0xCC; 64]
        );
    }

    #[test]
    fn delete_identity_cascades_to_keys_and_certs() {
        let dir = tempdir().unwrap();
        let pib = SqlitePib::open(dir.path().join("pib.db")).unwrap();
        let alice = name(&["alice"]);
        let key1 = name(&["alice", "KEY", "k1"]);
        let cert1 = name(&["alice", "KEY", "k1", "self", "v=1"]);
        pib.add_identity(&alice).unwrap();
        pib.add_key(&alice, &key1, &[0xAA; 32]).unwrap();
        pib.add_certificate(&key1, &cert1, &[0xCC; 64]).unwrap();
        pib.delete_identity(&alice).unwrap();
        // Cascade should have wiped the key and the cert.
        assert!(pib.get_key_bits(&key1).unwrap().is_none());
        assert!(pib.get_certificate(&cert1).unwrap().is_none());
    }

    #[test]
    fn tpm_locator_roundtrip() {
        let dir = tempdir().unwrap();
        let pib = SqlitePib::open(dir.path().join("pib.db")).unwrap();
        assert_eq!(pib.get_tpm_locator().unwrap(), None);
        pib.set_tpm_locator("tpm-file:").unwrap();
        assert_eq!(pib.get_tpm_locator().unwrap(), Some("tpm-file:".into()));
        // Update path: setting again replaces (single-row table).
        pib.set_tpm_locator("tpm-file:/custom/path").unwrap();
        assert_eq!(
            pib.get_tpm_locator().unwrap(),
            Some("tpm-file:/custom/path".into())
        );
    }

    #[test]
    fn reopen_persists_state() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pib.db");
        let alice = name(&["alice"]);
        let key1 = name(&["alice", "KEY", "k1"]);
        {
            let pib = SqlitePib::open(&path).unwrap();
            pib.add_identity(&alice).unwrap();
            pib.add_key(&alice, &key1, &[0xBB; 32]).unwrap();
            pib.set_tpm_locator("tpm-file:").unwrap();
        }
        let pib = SqlitePib::open(&path).unwrap();
        assert_eq!(pib.list_identities().unwrap(), vec![alice]);
        assert_eq!(pib.get_key_bits(&key1).unwrap().unwrap(), vec![0xBB; 32]);
        assert_eq!(pib.get_tpm_locator().unwrap(), Some("tpm-file:".into()));
    }

    #[test]
    fn delete_key_cascades_to_certs() {
        let dir = tempdir().unwrap();
        let pib = SqlitePib::open(dir.path().join("pib.db")).unwrap();
        let alice = name(&["alice"]);
        let key1 = name(&["alice", "KEY", "k1"]);
        let cert1 = name(&["alice", "KEY", "k1", "self", "v=1"]);
        pib.add_identity(&alice).unwrap();
        pib.add_key(&alice, &key1, &[0; 32]).unwrap();
        pib.add_certificate(&key1, &cert1, &[0; 64]).unwrap();
        pib.delete_key(&key1).unwrap();
        assert!(pib.get_certificate(&cert1).unwrap().is_none());
    }

    #[test]
    fn re_add_key_updates_bits() {
        let dir = tempdir().unwrap();
        let pib = SqlitePib::open(dir.path().join("pib.db")).unwrap();
        let alice = name(&["alice"]);
        let key1 = name(&["alice", "KEY", "k1"]);
        pib.add_identity(&alice).unwrap();
        pib.add_key(&alice, &key1, &[0x11; 32]).unwrap();
        pib.add_key(&alice, &key1, &[0x22; 32]).unwrap();
        assert_eq!(pib.get_key_bits(&key1).unwrap().unwrap(), vec![0x22; 32]);
    }
}
