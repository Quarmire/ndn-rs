//! Wasm-side IdbPib backed by IndexedDB.

use bytes::Bytes;
use js_sys::{Array, Uint8Array};
use ndn_packet::{Data, Name};
use ndn_safebag::SafeBag;
use ndn_safebag::SafeBagAlgorithm;
use ndn_security::{
    Certificate, EcdsaP256Signer, Ed25519Signer, Signer, Validator, trust_schema::TrustSchema,
};
use thiserror::Error;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen::closure::Closure;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    DomException, IdbDatabase, IdbObjectStoreParameters, IdbOpenDbRequest, IdbRequest,
    IdbTransactionMode, IdbVersionChangeEvent,
};

const STORE_SAFEBAGS: &str = "safebags";
const STORE_PASSPHRASES: &str = "passphrases";
const STORE_ANCHORS: &str = "anchors";
const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum IdbPibError {
    #[error("no IndexedDB factory available (not running in a browser/Worker scope)")]
    NoFactory,
    #[error("IndexedDB request failed: {0}")]
    Request(String),
    #[error("IndexedDB blocked open: another tab holds an older schema")]
    Blocked,
    #[error("invalid stored value: {0}")]
    Decode(String),
}

/// `IdbDatabase` is `!Send` (web-sys); the wasm32 JS runtime is
/// single-threaded so this is moot in practice.
pub struct IdbPib {
    db: IdbDatabase,
}

impl IdbPib {
    pub async fn open(db_name: &str) -> Result<Self, IdbPibError> {
        let factory = idb_factory()?;
        let req: IdbOpenDbRequest = factory
            .open_with_u32(db_name, SCHEMA_VERSION)
            .map_err(|e| IdbPibError::Request(format!("open: {e:?}")))?;

        // Fires only on first-ever open or on a version bump.
        let onupgradeneeded =
            Closure::<dyn FnMut(IdbVersionChangeEvent)>::new(move |ev: IdbVersionChangeEvent| {
                let target = match ev.target() {
                    Some(t) => t,
                    None => return,
                };
                let req: IdbOpenDbRequest = match target.dyn_into() {
                    Ok(r) => r,
                    Err(_) => return,
                };
                let db: IdbDatabase = match req.result().and_then(|v| v.dyn_into()) {
                    Ok(d) => d,
                    Err(_) => return,
                };
                let params = IdbObjectStoreParameters::new();
                // At SCHEMA_VERSION = 1 the stores never exist yet; future
                // bumps should treat "already exists" errors as benign.
                for store in [STORE_SAFEBAGS, STORE_PASSPHRASES, STORE_ANCHORS] {
                    let _ = db.create_object_store_with_optional_parameters(store, &params);
                }
            });
        req.set_onupgradeneeded(Some(onupgradeneeded.as_ref().unchecked_ref()));

        let db_value = await_request_value(req.unchecked_ref::<IdbRequest>()).await?;
        drop(onupgradeneeded);

        let db: IdbDatabase = db_value
            .dyn_into()
            .map_err(|_| IdbPibError::Request("open did not return IdbDatabase".into()))?;
        Ok(Self { db })
    }

    /// Wire is `ndnsec export`-compatible.
    pub async fn put_safebag(&self, name: &Name, bag: &SafeBag) -> Result<(), IdbPibError> {
        let wire = bag.encode();
        self.put_bytes(STORE_SAFEBAGS, &name.to_string(), &wire)
            .await
    }

    pub async fn get_safebag(&self, name: &Name) -> Result<Option<SafeBag>, IdbPibError> {
        let v = self.get_bytes(STORE_SAFEBAGS, &name.to_string()).await?;
        match v {
            Some(wire) => SafeBag::decode(&wire)
                .map(Some)
                .map_err(|e| IdbPibError::Decode(format!("safebag decode: {e}"))),
            None => Ok(None),
        }
    }

    /// Origin-scope compromise loses the identity (passphrase
    /// stored next to the bag). Wire shape is unaffected if a
    /// future revision sources the passphrase elsewhere.
    pub async fn put_passphrase(&self, name: &Name, pw: &[u8]) -> Result<(), IdbPibError> {
        self.put_bytes(STORE_PASSPHRASES, &name.to_string(), pw)
            .await
    }

    pub async fn get_passphrase(&self, name: &Name) -> Result<Option<Vec<u8>>, IdbPibError> {
        self.get_bytes(STORE_PASSPHRASES, &name.to_string()).await
    }

    pub async fn put_anchor(&self, name: &Name, wire: Bytes) -> Result<(), IdbPibError> {
        self.put_bytes(STORE_ANCHORS, &name.to_string(), &wire)
            .await
    }

    pub async fn get_anchor(&self, name: &Name) -> Result<Option<Bytes>, IdbPibError> {
        Ok(self
            .get_bytes(STORE_ANCHORS, &name.to_string())
            .await?
            .map(Bytes::from))
    }

    pub async fn list_anchors(&self) -> Result<Vec<Name>, IdbPibError> {
        list_store_keys(&self.db, STORE_ANCHORS).await
    }

    /// Builds a signer from the first persisted SafeBag. Algorithm is
    /// dispatched off the PKCS#8 `PrivateKeyAlgorithm` OID; Ed25519
    /// (1.3.101.112) is ndn-rs only, ECDSA-P256 (1.2.840.10045.2.1)
    /// interops with ndn-cxx / NFD. Any other OID errors instead of
    /// silently falling back. Returns `Ok(None)` when no SafeBag exists.
    pub async fn build_signer(&self) -> Result<Option<std::sync::Arc<dyn Signer>>, IdbPibError> {
        use std::sync::Arc;
        let names = self.list_safebags().await?;
        let Some(key_name) = names.into_iter().next() else {
            return Ok(None);
        };
        let bag = match self.get_safebag(&key_name).await? {
            Some(b) => b,
            None => return Ok(None),
        };
        let pw = self.get_passphrase(&key_name).await?.ok_or_else(|| {
            IdbPibError::Decode(format!(
                "safebag {key_name} present but companion passphrase row missing"
            ))
        })?;
        let algo = bag
            .algorithm(&pw)
            .map_err(|e| IdbPibError::Decode(format!("safebag algorithm probe: {e}")))?;
        let signer: Arc<dyn Signer> = match algo {
            SafeBagAlgorithm::Ed25519 => {
                let seed = bag
                    .decrypt_ed25519_seed(&pw)
                    .map_err(|e| IdbPibError::Decode(format!("safebag decrypt: {e}")))?;
                Arc::new(Ed25519Signer::from_seed(&seed, key_name))
            }
            SafeBagAlgorithm::EcdsaP256 => {
                let pkcs8 = bag
                    .decrypt_pkcs8(&pw)
                    .map_err(|e| IdbPibError::Decode(format!("safebag decrypt: {e}")))?;
                let signer = EcdsaP256Signer::from_pkcs8_der(&pkcs8, key_name)
                    .map_err(|e| IdbPibError::Decode(format!("ecdsa from_pkcs8: {e}")))?;
                Arc::new(signer)
            }
            SafeBagAlgorithm::Other(oid) => {
                return Err(IdbPibError::Decode(format!(
                    "safebag carries unsupported algorithm OID {oid} \
                     (only Ed25519 / ECDSA-P256 wired today)"
                )));
            }
        };
        Ok(Some(signer))
    }

    /// Validator starts with an empty [`TrustSchema`] — only Data
    /// signed directly by an anchor validates until callers add rules.
    pub async fn build_validator(&self) -> Result<Option<Validator>, IdbPibError> {
        let names = self.list_anchors().await?;
        if names.is_empty() {
            return Ok(None);
        }
        let validator = Validator::new(TrustSchema::new());
        for name in &names {
            let wire = match self.get_anchor(name).await? {
                Some(w) => w,
                None => continue,
            };
            let data = Data::decode(wire).map_err(|e| {
                IdbPibError::Decode(format!("anchor {name} not a valid Data wire: {e}"))
            })?;
            let cert = Certificate::decode(&data).map_err(|e| {
                IdbPibError::Decode(format!("anchor {name} not a valid Certificate: {e}"))
            })?;
            validator.add_trust_anchor(cert);
        }
        Ok(Some(validator))
    }

    pub async fn list_safebags(&self) -> Result<Vec<Name>, IdbPibError> {
        list_store_keys(&self.db, STORE_SAFEBAGS).await
    }

    pub async fn clear(&self) -> Result<(), IdbPibError> {
        for store in [STORE_SAFEBAGS, STORE_PASSPHRASES, STORE_ANCHORS] {
            let tx = self
                .db
                .transaction_with_str_and_mode(store, IdbTransactionMode::Readwrite)
                .map_err(|e| IdbPibError::Request(format!("tx({store}): {e:?}")))?;
            let s = tx
                .object_store(store)
                .map_err(|e| IdbPibError::Request(format!("store({store}): {e:?}")))?;
            let req = s
                .clear()
                .map_err(|e| IdbPibError::Request(format!("clear({store}): {e:?}")))?;
            let _ = await_request_value(&req).await?;
        }
        Ok(())
    }

    async fn put_bytes(
        &self,
        store_name: &str,
        key: &str,
        value: &[u8],
    ) -> Result<(), IdbPibError> {
        let tx = self
            .db
            .transaction_with_str_and_mode(store_name, IdbTransactionMode::Readwrite)
            .map_err(|e| IdbPibError::Request(format!("tx({store_name}): {e:?}")))?;
        let store = tx
            .object_store(store_name)
            .map_err(|e| IdbPibError::Request(format!("store({store_name}): {e:?}")))?;
        let array = Uint8Array::new_with_length(value.len() as u32);
        array.copy_from(value);
        let req = store
            .put_with_key(&array.into(), &JsValue::from_str(key))
            .map_err(|e| IdbPibError::Request(format!("put({store_name},{key}): {e:?}")))?;
        let _ = await_request_value(&req).await?;
        Ok(())
    }

    async fn get_bytes(&self, store_name: &str, key: &str) -> Result<Option<Vec<u8>>, IdbPibError> {
        let tx = self
            .db
            .transaction_with_str_and_mode(store_name, IdbTransactionMode::Readonly)
            .map_err(|e| IdbPibError::Request(format!("tx({store_name}): {e:?}")))?;
        let store = tx
            .object_store(store_name)
            .map_err(|e| IdbPibError::Request(format!("store({store_name}): {e:?}")))?;
        let req = store
            .get(&JsValue::from_str(key))
            .map_err(|e| IdbPibError::Request(format!("get({store_name},{key}): {e:?}")))?;
        let value = await_request_value(&req).await?;
        if value.is_undefined() || value.is_null() {
            return Ok(None);
        }
        let arr: Uint8Array = value
            .dyn_into()
            .map_err(|_| IdbPibError::Decode("stored value is not Uint8Array".into()))?;
        let mut out = vec![0u8; arr.length() as usize];
        arr.copy_to(&mut out);
        Ok(Some(out))
    }
}

/// Tries Window.indexedDB then WorkerGlobalScope.indexedDB.
fn idb_factory() -> Result<web_sys::IdbFactory, IdbPibError> {
    let global = js_sys::global();
    if let Ok(window) = global.clone().dyn_into::<web_sys::Window>()
        && let Ok(Some(f)) = window.indexed_db()
    {
        return Ok(f);
    }
    if let Ok(worker) = global.dyn_into::<web_sys::WorkerGlobalScope>()
        && let Ok(Some(f)) = worker.indexed_db()
    {
        return Ok(f);
    }
    Err(IdbPibError::NoFactory)
}

async fn list_store_keys(
    db: &web_sys::IdbDatabase,
    store_name: &str,
) -> Result<Vec<Name>, IdbPibError> {
    let tx = db
        .transaction_with_str_and_mode(store_name, IdbTransactionMode::Readonly)
        .map_err(|e| IdbPibError::Request(format!("tx({store_name}): {e:?}")))?;
    let store = tx
        .object_store(store_name)
        .map_err(|e| IdbPibError::Request(format!("store({store_name}): {e:?}")))?;
    let req = store
        .get_all_keys()
        .map_err(|e| IdbPibError::Request(format!("get_all_keys({store_name}): {e:?}")))?;
    let value = await_request_value(&req).await?;
    let arr: Array = value
        .dyn_into()
        .map_err(|_| IdbPibError::Decode("get_all_keys returned non-array".into()))?;

    let mut out = Vec::with_capacity(arr.length() as usize);
    for entry in arr.iter() {
        let s = entry
            .as_string()
            .ok_or_else(|| IdbPibError::Decode("non-string key in store".into()))?;
        let name: Name = s
            .parse()
            .map_err(|_| IdbPibError::Decode(format!("unparsable name: {s}")))?;
        out.push(name);
    }
    Ok(out)
}

/// Hooks `onsuccess` / `onerror` on `req` and bridges to async via a Promise.
async fn await_request_value(req: &IdbRequest) -> Result<JsValue, IdbPibError> {
    use std::cell::RefCell;
    use std::rc::Rc;

    use js_sys::Promise;

    let req_clone = req.clone();
    let req_for_err = req.clone();
    let resolved = Rc::new(RefCell::new(false));
    let resolved_ok = Rc::clone(&resolved);
    let resolved_err = Rc::clone(&resolved);

    let promise = Promise::new(&mut |resolve, reject| {
        let resolve_cb = resolve.clone();
        let reject_cb = reject.clone();
        let req_inner = req_clone.clone();
        let req_inner_err = req_for_err.clone();
        let resolved_inner = Rc::clone(&resolved_ok);
        let resolved_err_inner = Rc::clone(&resolved_err);

        let onsuccess = Closure::<dyn FnMut(JsValue)>::new(move |_ev: JsValue| {
            if *resolved_inner.borrow() {
                return;
            }
            *resolved_inner.borrow_mut() = true;
            let value = req_inner.result().unwrap_or(JsValue::UNDEFINED);
            let _ = resolve_cb.call1(&JsValue::UNDEFINED, &value);
        });
        let onerror = Closure::<dyn FnMut(JsValue)>::new(move |_ev: JsValue| {
            if *resolved_err_inner.borrow() {
                return;
            }
            *resolved_err_inner.borrow_mut() = true;
            let err = req_inner_err
                .error()
                .ok()
                .flatten()
                .map(|e: DomException| JsValue::from_str(&e.message()))
                .unwrap_or_else(|| JsValue::from_str("unknown IDB error"));
            let _ = reject_cb.call1(&JsValue::UNDEFINED, &err);
        });
        req_clone.set_onsuccess(Some(onsuccess.as_ref().unchecked_ref()));
        req_clone.set_onerror(Some(onerror.as_ref().unchecked_ref()));
        // The request fires once; leaking the closures matches that lifetime.
        onsuccess.forget();
        onerror.forget();
    });

    JsFuture::from(promise)
        .await
        .map_err(|e| IdbPibError::Request(format!("{e:?}")))
}
