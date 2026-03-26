# NDN Security Architecture

## Core Model

Every Data packet is **signed by its producer**. The signature covers Name, MetaInfo, Content, and SignatureInfo — not the wire encoding of the outer packet. Trust travels with the data, not the path. A CS hit from an untrusted forwarder is as secure as a fresh response from the producer — this is what makes NDN caching safe in adversarial environments.

Verification is an **application-layer concern**, not a forwarder concern. The engine pipeline does not validate signatures on transit Data. It cannot — it does not have the application's trust schema or key store. The `AppFace` layer runs validation before delivering Data to the application.

## Signed Region — Zero-Copy Verification

The signed region (Name + MetaInfo + Content + SignatureInfo) is **contiguous** in the NDN wire encoding. SignatureValue is at the end and explicitly excluded. Verification takes a slice directly into the receive buffer:

```rust
impl Data {
    pub fn signed_region(&self) -> &[u8] {
        &self.raw[self.signed_start..self.signed_end]
    }
    pub fn sig_value(&self) -> &[u8] {
        &self.raw[self.sig_value_start..self.sig_value_end]
    }
}
```

Both are zero-copy slices. The crypto library receives `&[u8]` references into the original packet buffer — no intermediate allocation on the verification path.

## `Signer` Trait

```rust
pub trait Signer: Send + Sync + 'static {
    fn sig_type(&self) -> SignatureType;
    fn key_locator(&self) -> Option<&Name>;
    fn sign<'a>(&'a self, region: &'a [u8]) -> BoxFuture<'a, Result<Bytes, TrustError>>;
}
```

`BoxFuture` (not `async fn`) makes the trait dyn-compatible for storage as `Arc<dyn Signer>`.

`Ed25519Signer::from_seed(seed: &[u8; 32])` — use `from_seed` not `generate()`. The `ed25519_dalek::rand_core` path for key generation has compatibility issues; seeded construction is unambiguous.

## `Verifier` Trait

```rust
pub trait Verifier: Send + Sync + 'static {
    fn verify<'a>(
        &'a self, region: &'a [u8], sig: &'a [u8], key: &'a [u8],
    ) -> BoxFuture<'a, Result<VerifyOutcome, TrustError>>;
}

pub enum VerifyOutcome {
    Valid,
    Invalid,   // bad signature — expected outcome, not an Err
}
```

`VerifyOutcome::Invalid` is `Ok(...)` not `Err(...)`. A bad signature is an expected outcome; only malformed keys or wrong key lengths return `Err`.

## Ed25519 Implementation

```rust
impl Verifier for Ed25519Verifier {
    fn verify<'a>(
        &'a self, region: &'a [u8], sig: &'a [u8], key: &'a [u8],
    ) -> BoxFuture<'a, Result<VerifyOutcome, TrustError>> {
        Box::pin(async move {
            use ed25519_dalek::Verifier as _;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(
                key.try_into().map_err(|_| TrustError::InvalidKey)?
            )?;
            let sig = ed25519_dalek::Signature::from_bytes(
                sig.try_into().map_err(|_| TrustError::InvalidSignature)?
            );
            match vk.verify(region, &sig) {
                Ok(()) => Ok(VerifyOutcome::Valid),
                Err(_) => Ok(VerifyOutcome::Invalid),
            }
        })
    }
}
```

Use `ring` for RSA, ECDSA P-256, HMAC-SHA256, SHA256 digest (standard NDN types). Use `ed25519-dalek` for Ed25519 (preferred for new deployments: small keys, fast verification, resistant to implementation errors).

## Trust Schema — Name Pattern Matching

The trust schema makes NDN security **semantically meaningful** rather than just cryptographically sound. A valid signature by a known key is not sufficient — the key must also be authorized to sign names matching the data's name.

```rust
pub enum PatternComponent {
    Literal(NameComponent),      // exact match
    Capture(Arc<str>),           // named capture — binds a variable
    MultiCapture(Arc<str>),      // matches one or more components
}

pub struct NamePattern(Vec<PatternComponent>);
```

Schema evaluation checks both the data pattern and the key pattern, then verifies all captured variables with the same name bound to the same value. Example rule: `/sensor/<node>/<type>` signed by `/sensor/<node>/KEY/<id>` — the `<node>` captured from the data name must match `<node>` captured from the key name. This prevents a sensor node from signing data for a different sensor node even if both use valid keys under the same namespace.

## Certificate Cache

Certificates are just signed Data packets with names like `/sensor/node1/KEY/abc123/self/%FD001`. Fetching a cert is just expressing an Interest — the CS may satisfy it locally.

```rust
pub struct CertCache {
    app_face: Arc<AppFace>,
    local:    DashMap<Name, Certificate>,
    max_age:  Duration,
}

impl CertCache {
    pub async fn get_or_fetch(&self, key_name: &Name) -> Result<Certificate> {
        if let Some(cert) = self.local.get(key_name) {
            return Ok(cert.clone());
        }
        let data = self.app_face.express(Interest::new(key_name.clone())).await?;
        let cert = Certificate::decode(&data)?;
        self.local.insert(key_name.clone(), cert.clone());
        Ok(cert)
    }
}
```

No out-of-band PKI infrastructure — everything travels over NDN.

## Certificate Chain Validation

Chains can be arbitrarily deep. Each step requires fetching the signing cert via an Interest:

```rust
async fn validate_chain(&self, cert: &Certificate, depth: usize) -> Result<ValidationResult> {
    if depth > self.config.max_chain_depth {
        return Err(TrustError::ChainTooDeep);
    }
    if self.trust_anchors.contains(cert.name()) {
        return Ok(ValidationResult::Valid);
    }
    let issuer_name = cert.sig_info.key_locator()?;
    let issuer = self.cert_cache.get_or_fetch(issuer_name).await?;
    self.verifier.verify(cert.signed_region(), cert.sig_value(), issuer.public_key()).await?;
    self.validate_chain(&issuer, depth + 1).await
}
```

**`ValidationResult::Pending`**: Data is held in a pending queue while cert fetching is in progress. Important for cold starts when no certs are cached.

## `SafeData` — Verified Status in the Type

```rust
pub struct SafeData {
    inner:       Data,
    trust_path:  TrustPath,   // chain of cert names that validated this
    verified_at: u64,
}

impl SafeData {
    pub(crate) fn new(data: Data, trust_path: TrustPath) -> Self { ... }

    // only constructable for trusted local faces within the engine crate
    pub(crate) fn from_local_trusted(data: Data, face_creds: &FaceCredentials) -> Self { ... }
}
```

`pub(crate)` constructors mean application code cannot construct `SafeData` without going through the `Validator`. Functions that require verified data take `&SafeData` — the compiler enforces that unverified `Data` cannot be passed where verified data is required.

## Local Trust (IPC / AppFace)

For local faces with verified process credentials, bypass crypto verification entirely. Capture connecting process credentials via `SO_PEERCRED` on the Unix control socket:

```rust
pub struct FaceCredentials {
    pub pid:              u32,
    pub uid:              u32,
    pub gid:              u32,
    pub allowed_prefixes: Vec<Name>,
}
```

A `LocalTrustStage` pipeline stage enforces that Data on a local face only carries names the connecting process is authorized to produce. Data from local faces with `local_scope: true` is not forwarded to remote faces — prevents local IPC processes from injecting data into the network-facing forwarding plane.

## `KeyStore` Trait

```rust
pub trait KeyStore: Send + Sync {
    async fn get_signer(&self, key_name: &Name) -> Result<Arc<dyn Signer>>;
    async fn generate_key(&self, name: Name, algo: KeyAlgorithm) -> Result<Name>;
    async fn delete_key(&self, key_name: &Name) -> Result<()>;
}

pub struct FileKeyStore { path: PathBuf }  // development / research
pub struct TpmKeyStore  { handle: TpmCtx } // production
pub struct MemKeyStore  { keys: DashMap<Name, Arc<dyn Signer>> } // testing
```

`KeyChain` composes `KeyStore` + `CertCache` + `TrustSchema` into the complete security subsystem configured once at startup.
