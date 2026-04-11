# did-ndn-driver

DIF Universal Resolver driver for the `did:ndn` DID method. Implements the DIF
DID Resolution HTTP binding, allowing the Universal Resolver to delegate `did:ndn`
lookups to this service. Internally resolves DIDs by fetching the corresponding
DID Document from the NDN network via `ndn-did` / `ndn-security`.

## Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/1.0/identifiers/{did}` | `GET` | Resolve a `did:ndn:...` identifier; returns a DIF `DidResolutionResult` |
| `/health` | `GET` | Health check; returns `"ok"` |

## Running

```sh
cargo build -p did-ndn-driver
./target/debug/did-ndn-driver

# Custom port:
PORT=9090 ./target/debug/did-ndn-driver
RUST_LOG=did_ndn_driver=debug ./target/debug/did-ndn-driver
```

Default port: `8080`.

## Universal Resolver integration

Add to `uni-resolver-web/src/main/resources/application.yml`:

```yaml
- pattern: "^did:ndn:.+"
  url: "http://did-ndn-driver:8080/1.0/identifiers/"
```

Then submit a PR to the [DIF Universal Resolver](https://github.com/decentralized-identity/universal-resolver).
