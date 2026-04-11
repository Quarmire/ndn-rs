# App Ideas

NDN applications feel architecturally different from REST APIs almost immediately, and the difference is not superficial. In a traditional client-server model, the application is responsible for knowing where the data lives. You hardcode a hostname, consult a service registry, or do a DNS lookup, and then you open a connection to a specific machine. If that machine is unavailable, you get nothing. If the same data is available on a closer replica, you have to know about it in advance and route around to it yourself. Caching is something you add deliberately, as a separate layer, with explicit cache-key management and invalidation logic.

NDN inverts this. When a consumer expresses an Interest for `/sensor/room42/temperature`, it does not address a host. It names a piece of data, and the network finds it. If the nearest router has it cached, the consumer gets a response in microseconds without the Interest ever leaving the local machine. If no router has it cached, the Interest propagates outward until a node that can satisfy it responds. The consumer's code is identical in both cases — `consumer.get("/sensor/room42/temperature")` works whether the data is in-process, cached at the router down the hall, or produced by a device across the internet. The location is the network's problem, not the application's.

This principle extends to scale in a way that REST cannot match cleanly. The same `ndn-app` API — `Consumer`, `Producer`, `Subscriber`, `Queryable` — works identically when the application is wired to an in-process embedded engine via `ndn-embedded`, connected to a `ndn-fwd` on localhost, or talking to a forwarder on the far side of a WAN link. Application code has no mode switches, no configuration for "local vs. remote," no special handling for offline or disconnected scenarios. The following ideas are all built from this foundation.

---

## Distributed Sensor Mesh

> **Key NDN feature:** Location-independent naming — the namespace is the configuration; sensors are discovered by name, not by address.

A building or industrial facility might have hundreds of environmental sensors ranging from tiny microcontroller nodes that have no operating system to gateway machines running full Linux stacks. In IP, connecting these into a unified monitoring system requires careful orchestration: each sensor needs a fixed address or a dynamic registration mechanism, the gateway must maintain per-sensor state, and the cloud dashboard must know where to query. Adding a new sensor means updating the registry.

In NDN, every sensor simply publishes under its name. A soil moisture sensor in a greenhouse publishes readings under `/greenhouse/bed3/moisture`, and a temperature probe under `/greenhouse/bed3/temp`. The gateway, the local dashboard, and the cloud backend all express Interests for whichever names they care about — they do not need to know whether they are talking to the sensor directly or to a router that has a cached reading. `ndn-embedded` lets each microcontroller node run a minimal forwarder directly, without a router process, while `ndn-app`'s `Producer` handles the publication side on the gateway. The namespace itself is the configuration. New sensors appear in the network simply by starting to publish; existing consumers pick them up through prefix wildcards without any out-of-band registration.

---

## Collaborative Document Editing

> **Key NDN feature:** State-vector sync (SVS) — decentralized multi-writer convergence without a coordination server.

Collaborative editing tools in the IP world require a central server to mediate conflicts, synchronize state, and broadcast changes to all participants. Even architectures that appear peer-to-peer, like operational transform or CRDT-based editors, typically rely on a coordination server that all clients maintain connections to. Offline editing introduces synchronization debt that must be resolved on reconnection, often through a bespoke reconciliation protocol.

SVS sync, exposed through `ndn-app`'s `Subscriber`, turns this into a much smaller problem. Each participant publishes their edits under their own name prefix — Alice under `/doc/project-spec/alice/edit`, Bob under `/doc/project-spec/bob/edit` — and the SVS state vector tells every node which sequence numbers it has seen from every other node. When two writers are offline and then reconnect, the sync group converges automatically: each side's `Subscriber` discovers the missing sequence ranges and fetches them as ordinary named data. There is no "master copy" to reconcile against. The multi-writer property falls out from the data-layer security model: every edit is signed by its author, so the system can attribute and sequence edits correctly even if they have passed through untrusted intermediaries.

---

## Named Video Distribution

> **Key NDN feature:** In-network caching — every forwarder becomes a CDN node automatically, with no operator configuration.

Video streaming at scale is one of the clearest places where NDN's in-network caching pays off immediately. A traditional CDN is an expensive, carefully engineered overlay that replicates content from an origin server to geographically distributed edge nodes. Operating one requires contracts, geographic presence, and significant infrastructure. Even then, the unit of caching is an HTTP response, tied to a URL served from a specific hostname — the CDN configuration must be maintained as a separate operational concern.

NDN makes every router a potential cache. When a producer publishes a video file segmented under `/media/lecture-series/ndn-intro/seg/0` through `/media/lecture-series/ndn-intro/seg/4199`, every forwarder that satisfies an Interest for any segment automatically caches that segment in its Content Store. The tenth viewer watching the same lecture from the same office building gets served from the nearest LAN router, not from the producer. The producer never sees the repeat traffic. From the application's perspective, the `Consumer` simply fetches sequential segments by name; the fact that the first viewer warmed the cache for everyone else is an emergent property of the architecture, not something the application or the operator had to configure.

---

## Field Data Collection

> **Key NDN feature:** Pull model with persistent named data — data sits in the namespace and waits to be fetched; the collector needs no live connection to the device.

Survey teams, ecologists, and field engineers often work in environments with intermittent or absent network connectivity. A traditional field data collection app must either hold all data locally and batch-sync on reconnection, or require a live connection to the central server to record anything. Both approaches require explicit code: a local buffer with sync logic, conflict detection, and a custom protocol for catch-up on reconnect.

NDN's pull model means none of this needs to be written explicitly. A field device running `ndn-embedded` publishes each observation under a timestamped name — `/survey/transect7/obs/20250617T142305` — and the local Content Store holds it. When the device later comes within range of a gateway or mobile hotspot, a data collection agent on the other side simply expresses Interests for the names it does not yet have. The sync group, via `Subscriber`, tells the agent which sequence numbers exist; the agent fetches the gaps. The field device does not need to know when it is online or offline, does not need to manage a retry queue, and does not need to initiate a push. The data sits in the named namespace and waits to be fetched. Data-layer security means the collected observations carry the field device's signature, so their provenance is verifiable even after they have passed through an intermediate cache.

---

## Edge Compute with Structural Memoization

> **Key NDN feature:** In-network computation — computation results are named data; the Content Store automatically memoizes them across all consumers.

A common pattern in IoT and scientific computing is running the same transformation repeatedly on the same input data. An image processing pipeline might downsample the same high-resolution frame for a dozen different consumers needing different thumbnail sizes. In IP, ten consumers requesting the same thumbnail from a REST endpoint produce ten invocations of the resize computation, unless the application author has explicitly wired in a caching layer.

The `ndn-compute` crate eliminates this class of redundant work at the architecture level. A compute handler registered under `/compute/thumbnail` receives Interests of the form `/compute/thumbnail/width=320/src=<digest>`, performs the resize, and returns a Data packet. The forwarder's Content Store caches the result by name. The eleventh consumer requesting the same thumbnail at the same width gets a cache hit before the Interest ever reaches the compute handler — the handler never runs again for those inputs. This is not an optimization the developer opts into; it falls out of how the pipeline handles Data packets, and it applies to any computation that can be expressed as a named function of named inputs. In more advanced deployments, intermediate routers can perform the computation themselves if they have the capability registered — a request that enters the network at one edge node might never reach the origin producer if a closer node can compute the answer. The `ndn-compute` `ComputeFace` is simply another face in the face table, indistinguishable to the pipeline from a UDP or Ethernet face.

---

## Distributed Configuration Management

> **Key NDN feature:** In-network caching with MustBeFresh — forwarders serve fresh configuration to all consumers without the producer seeing every poll.

Distributing configuration to a fleet of services or devices is a deceptively hard problem. IP approaches typically involve a configuration service (etcd, Consul, a custom REST API), which every node must be able to reach, whose address must be known in advance, and whose availability becomes a system-wide dependency. Rolling out a new configuration value requires either push delivery to every node or polling by every node, both of which require connection management.

NDN reduces this to a named data publication. An operator publishes a new configuration under `/config/fleet/v=42` with a freshness period set to the desired polling interval. Every node in the fleet runs a `Consumer` that periodically expresses an Interest for `/config/fleet` with `MustBeFresh` set. As the Interest propagates, any router with a fresh cached copy answers immediately; only nodes that have stale or absent caches forward the Interest toward the configuration producer. Nodes that are temporarily offline simply continue using their cached configuration until they reconnect, at which point a stale cache triggers a fresh Interest automatically. Because configuration data is signed at the data layer, nodes can verify that a configuration came from the authorized publisher without needing a secure channel to the configuration service.

---

## Peer-to-Peer Messaging with Named Identities

> **Key NDN feature:** Location-independent routing + data-layer security — messages route to a name, not an address; signatures are carried in the data, not the transport.

Messaging applications that avoid a central server face a fundamental tension in the IP world: without a server, how does a message find its recipient? Federated protocols (Matrix, ActivityPub) require a home server per domain. Fully decentralized approaches (Briar, Meshtastic) typically bind delivery to the physical proximity of devices or use custom flooding protocols.

NDN gives identities a name, and the network routes by name. Alice's inbox is `/msg/alice` and she runs a `Producer` on that prefix. Bob sends a message by expressing an Interest for `/msg/alice/from=bob/ts=1718620800`, which routes through the network to wherever Alice's `Producer` is registered. The message content is signed with Bob's key, so Alice can verify who sent it without trusting the transport path. Because NDN routes by prefix rather than address, Alice can move between networks — home WiFi, mobile, a VPN — without updating her peers' address books. The routing infrastructure adjusts; the name stays constant. Group messaging maps naturally onto SVS sync groups: each participant publishes their messages under their own prefix, and all members' `Subscriber` instances converge on the full set of messages without a group server.

---

## Cross-Environment Digital Twin

> **Key NDN feature:** Unified local/remote interface — the same `Consumer` API and the same name work across an MCU, a LAN router, and a WAN-connected cloud backend without protocol bridging.

A digital twin — a live, queryable model of a physical asset — requires bridging data from embedded sensors through local edge processing to cloud analytics dashboards. In IP, this bridge is usually built with a stack of adapters: MQTT from the device to a broker, REST from the broker to a database, a query API from the database to the dashboard. Each hop involves a format conversion, an address binding, and a connection to manage. The embedded device speaks a different protocol from the dashboard.

NDN collapses this stack. The physical sensor publishes its state as named data — `/twin/conveyor-7/bearing-temp` — via `ndn-embedded` running directly on the microcontroller. The local edge dashboard expresses an Interest for that name and gets the reading, potentially from a router cache, with no direct connection to the sensor required. The cloud analytics platform expresses the same Interest over a WAN face and gets the same data, signed by the same sensor, without any transcoding or protocol bridging. All three environments — embedded MCU, local LAN, cloud backend — run the same `Consumer` API against the same name. The digital twin is simply the named namespace; what changes per environment is only which forwarder the application connects to, not the application code itself.
