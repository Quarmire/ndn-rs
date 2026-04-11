# Glossary

Terms used throughout the ndn-rs codebase and NDN literature. Organized alphabetically.

---

**Action**
: Enum returned by each `PipelineStage` to control packet flow. Variants: `Continue` (pass to next stage), `Send` (forward to faces and exit), `Satisfy` (satisfy PIT entries), `Drop` (discard), `Nack` (send negative acknowledgement).

**InProcFace**
: An in-process face that connects an application to the ndn-rs engine. Implemented as a pair of shared-memory ring buffers with a Unix socket control channel. Applications interact with the forwarder through `InProcFace` rather than opening network sockets.

**CanBePrefix**
: An Interest selector indicating that the Interest name may be a proper prefix of the Data name. Without this flag, the Data name must exactly match the Interest name.

**CS (Content Store)**
: A per-node cache of Data packets. Any router can serve a cached Data to a future Interest without forwarding upstream. In ndn-rs, CS is a trait (`ContentStore`) with pluggable backends: `LruCs`, `ShardedCs`, `PersistentCs`.

**Data**
: One of the two NDN network-layer packet types. A Data packet carries a name, content, and a cryptographic signature. Data is always a response to an Interest and travels the reverse path.

**Face**
: An NDN communication interface, analogous to a network interface in IP. A face can be a UDP tunnel, TCP connection, Ethernet link, Unix socket, in-process channel, or any transport that implements the `Face` trait (`recv()` + `send()`). Each face has a unique `FaceId`.

**FaceId**
: A `u32` identifier assigned to each face when it is created. Used throughout PIT records, FIB nexthops, and pipeline dispatch. Application code does not use raw `FaceId` values directly.

**FIB (Forwarding Information Base)**
: Maps name prefixes to sets of nexthop faces with costs. Implemented as a `NameTrie` with `Arc<RwLock<TrieNode>>` per level for concurrent longest-prefix match. Analogous to an IP routing table.

**ForwardingAction**
: Enum returned by a Strategy to tell the pipeline what to do with an Interest. Variants: `Forward` (send to faces), `ForwardAfter` (delayed forward for probing), `Nack` (reject), `Suppress` (do not forward).

**FreshnessPeriod**
: A field in a Data packet specifying how long (in milliseconds) the Data should be considered "fresh" after arrival. Used by the CS to honor `MustBeFresh` selectors. Decoded once at CS insert time and stored as a `stale_at` timestamp.

**HopLimit**
: An optional field in an Interest packet, decremented at each hop. When it reaches zero the Interest is dropped. Prevents Interests from looping indefinitely in misconfigured networks.

**Interest**
: One of the two NDN network-layer packet types. An Interest packet carries a name and optional selectors (CanBePrefix, MustBeFresh, Nonce, Lifetime, HopLimit). It requests a Data packet matching the given name.

**MustBeFresh**
: An Interest selector requesting that the returned Data must not be stale (its `FreshnessPeriod` must not have expired). A CS entry whose `stale_at` has passed will not satisfy a MustBeFresh Interest.

**Nack (Network Nack)**
: A negative acknowledgement sent by a router when it cannot satisfy or forward an Interest. Carries a reason code (NoRoute, Congestion, Duplicate). Nacks travel the reverse Interest path, same as Data.

**Name**
: A hierarchical identifier for NDN content. Composed of a sequence of `NameComponent` values. Example: `/ndn/example/data/v1`. In ndn-rs, names use `SmallVec<[NameComponent; 8]>` for stack allocation in the common case and are shared via `Arc<Name>`.

**NameComponent**
: A single segment of an NDN name. Components are typed (GenericNameComponent, ImplicitSha256DigestComponent, ParametersSha256DigestComponent, etc.) and carry arbitrary bytes, not just UTF-8 strings.

**NDNLPv2 (NDN Link Protocol v2)**
: A link-layer protocol that fragments, reassembles, and annotates NDN packets on a single hop. Carries hop-by-hop fields such as PIT tokens, Nack reasons, congestion marks, and fragmentation headers. In ndn-rs, NDNLPv2 headers are parsed before the packet enters the forwarding pipeline.

**Nonce**
: A random 32-bit value carried in every Interest packet. Used for loop detection: if a PIT entry already contains the same nonce, the Interest is a loop and is Nacked. Stored in `SmallVec<[u32; 4]>` per PIT entry.

**PacketContext**
: The per-packet state object passed by value through the pipeline. Contains raw bytes, decoded packet, face ID, name, PIT token, output face list, and extensible tags. Fields are populated progressively as stages execute.

**PipelineStage**
: A trait representing one step in the forwarding pipeline. Each stage receives a `PacketContext` and returns an `Action`. Built-in stages are monomorphized for zero-cost dispatch; plugin stages use dynamic dispatch via `BoxedStage`.

**PIT (Pending Interest Table)**
: Records outstanding Interests that have been forwarded but not yet satisfied. Keyed by name + selector hash. Implemented as a `DashMap` for sharded concurrent access. Each entry tracks in-records (downstream faces), out-records (upstream faces), and nonces seen.

**PitToken**
: A hash derived from the Interest name and selectors, used as the PIT lookup key. Distinct from the NDNLPv2 wire-protocol PIT token (an opaque hop-by-hop value echoed in Data/Nack responses).

**SafeData**
: A newtype wrapper around `Data` that can only be constructed by the `Validator` after successful signature verification. Application callbacks and the Content Store receive `SafeData`, not raw `Data`. This enforces at compile time that unverified data cannot be forwarded or consumed.

**ShmFace**
: A shared-memory face for high-throughput communication between an application and the ndn-rs router on the same host. Uses a ring buffer in a shared memory segment with a Unix socket control channel for signaling.

**Strategy**
: A per-prefix forwarding policy that decides how to handle Interests and Data. Implements the `Strategy` trait with methods like `after_receive_interest` and `after_receive_data`. Strategies receive an immutable `StrategyContext` and return `ForwardingAction` values. A name trie parallel to the FIB maps prefixes to strategy instances.

**TrustSchema**
: A declarative specification of which keys are allowed to sign which names. Uses name pattern matching with capture groups. The `Validator` checks incoming Data against the trust schema before constructing `SafeData`.
