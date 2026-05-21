# Glossary

One-line definitions for the terms the rest of the wiki uses
without re-defining.

| Term | Definition |
|---|---|
| **Cert** | A signed `Data` packet whose content is a public key; carries validity period and issuer key locator. |
| **Connection** | The Develop-tier trait an app uses to reach an engine; concrete forms are `IpcConnection` and `InProcConnection`. |
| **Consumer** | The Develop-tier type that expresses Interests and receives Data. |
| **Content Store (CS)** | Per-forwarder cache of Data packets, consulted before the PIT. |
| **Data** | The signed content packet that answers an Interest. |
| **Develop tier** | API tier for application authors; ships as the `ndn` umbrella crate. |
| **DiscoveryProtocol** | Extend-tier trait for neighbour discovery. |
| **Engine** | The forwarder runtime; `ForwarderEngine` in `ndn-engine`. |
| **EngineBuilder** | Builder that assembles an engine from faces, strategies, and routing protocols. |
| **Extend tier** | API tier for protocol, strategy, and face authors. |
| **Face** | NDN-layer link to a peer; `Transport + LinkService`. |
| **FaceKind** | Classification of a face (local, on-demand, persistent, permanent). |
| **FIB** | Forwarding Information Base — name-prefix → candidate faces. |
| **fetch_object** | Develop-tier verb that performs RDR-shaped segmented fetch. |
| **ForwardingHint** | Optional Interest field that delegates name lookup to a different prefix. |
| **InProcConnection** | Develop-tier connection to an embedded engine in the same process. |
| **InProcFace** | Face whose transport is an in-process channel; no IO. |
| **Instrument tier** | API tier for researchers; feature-gated `experimental-instrument`. |
| **Interest** | The request packet; names what the consumer wants. |
| **IPC** | The Unix-socket management + data plane between apps and `ndn-fwd`. |
| **IpcConnection** | Develop-tier connection to an external `ndn-fwd` over Unix socket. |
| **KeyChain** | The object holding identities, keys, certs, and signing/validation policy. |
| **LinkService** | NDNLPv2 framing layer between a `Transport` and the engine. |
| **LVS** | Light Versatile Schema — pattern-based trust policy language. |
| **Management protocol** | TLV Interests under `/localhost/<forwarder>/<module>/<verb>`. |
| **MgmtModule** | Extend-tier trait that owns the verbs for one management module. |
| **Name** | Ordered sequence of `NameComponent` values; the NDN address. |
| **NACK** | Negative acknowledgement; carries a `NackReason`. |
| **NDNCERT** | Automated certificate issuance protocol; `ndn-cert` crate. |
| **NDNLPv2** | The link-layer protocol between faces; fragmentation, IncomingFaceId, congestion marks. |
| **ndn-fwd** | The standalone forwarder binary. |
| **ndn umbrella** | The Develop-tier crate; package `ndn-rs-prelude`, library `ndn`. |
| **PIB** | Personal Information Base — the on-disk identity/key store. |
| **PIT** | Pending Interest Table — name → in-records (face IDs waiting on this name). |
| **Producer** | The Develop-tier type that registers a prefix and serves Data. |
| **Prefix** | A leading slice of a name; a registration covers a prefix. |
| **Queryable / Query** | Develop-tier request/reply primitive (one Interest → one Data). |
| **RDR** | Realtime Data Retrieval — discovery shape for segmented objects (`<name>/32=metadata`). |
| **Responder** | Develop-tier closure-style producer (one closure → one Data). |
| **RoutingProtocol** | Extend-tier trait that produces FIB updates. |
| **SafeBag** | Passphrase-encrypted bundle of an identity, keys, and certs. |
| **SigningInfo** | "Sign me with X" descriptor; resolves to a `SignerSelection` in the KeyChain. |
| **Strategy** | Extend-tier trait that decides which face an Interest goes out on. |
| **Subscriber** | Develop-tier multi-publisher stream subscriber (SVS pub/sub shape). |
| **SVS** | State Vector Sync; the multi-publisher sync protocol that `Subscriber` consumes. |
| **TapFace** | Instrument-tier virtual face that records every wire packet sent to it. |
| **Transport** | Trait for raw byte send/recv; pairs with a `LinkService` to form a `Face`. |
| **TrustPolicy** | Extend-tier trait answering "should this key sign that name?". |
| **ValidationPolicy** | Extend-tier trait composing `TrustPolicy` decisions into a verdict chain. |
