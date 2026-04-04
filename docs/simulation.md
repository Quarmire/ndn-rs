Great question — this is something the architecture is actually well-positioned for, but there's no first-class simulation harness today. Here's my assessment:

    What's Already Favorable

    The library-not-daemon design is the key enabler. Unlike NFD (which is a standalone daemon you poke via Unix sockets), ndn-rs is an embeddable library. ForwarderEngine is just a struct you instantiate
    in-process. This means you can spin up N forwarders in a single process without N OS processes, containers, or network namespaces — which is exactly what makes Mini-NDN hacky (it orchestrates real NFD
    processes via Mininet/Linux namespaces).

    AppFace / in-process channels. Applications connect via AppFace (channel pair) or ShmFace (shared memory ring). For simulation, AppFace is perfect — it's just a Tokio channel, no real network needed.

    EngineBuilder pattern. You can configure each engine differently (different strategies, different CS sizes, different enrichers) programmatically without config files.

    Strategy extensibility. The three-tier strategy system (Rust / composed / WASM) means you can test forwarding algorithms without touching router code.

    What's Missing for True Simulation Support

    1. Virtual/Simulated Faces (Critical)

    There's no SimFace or DirectFace that connects two engines in-process with configurable link properties (delay, loss, bandwidth, jitter). Today you'd have to use real UDP sockets on localhost. You'd
    want something like:

    let (face_a, face_b) = SimLink::pair(LinkConfig {
        delay: Duration::from_millis(10),
        loss_rate: 0.01,
        bandwidth_bps: 1_000_000,
        jitter: Duration::from_millis(2),
    });
    engine_a.add_face(face_a);
    engine_b.add_face(face_b);

    This is probably the single most important missing piece.

    2. Topology Builder

    A DSL or builder for constructing multi-node topologies:

    let mut sim = Simulation::new();
    let n1 = sim.add_node(EngineConfig::default());
    let n2 = sim.add_node(EngineConfig::default());
    sim.link(n1, n2, LinkConfig { delay_ms: 5, .. });
    sim.add_route(n1, "/prefix", n2);

    Mini-NDN's topology files are actually one of its better ideas — just the execution (Mininet + real processes) is the hacky part.

    3. Deterministic Time (Important for Reproducibility)

    Currently everything runs on Tokio's real-time clock. For reproducible simulations you'd want either:
    - tokio-test / manual time advancement (tokio::time::pause() + advance())
    - Or a custom time source injected into the engine

    PIT expiry, retransmission timers, measurement EWMA — all depend on wall clock. Without deterministic time, simulation runs aren't reproducible.

    4. Event Tracing / Packet Logging

    The tracing instrumentation is already there (structured spans per packet), but simulation wants machine-readable event logs: "packet X entered node N at face F at time T, action was Forward to face G."
     You'd want a simulation-specific tracing subscriber that captures a structured event stream for post-hoc analysis.

    5. Metric Collection

    Aggregate stats (throughput, latency distribution, cache hit rates, PIT occupancy) per node, per prefix, per time window. The MeasurementsTable has per-prefix RTT/satisfaction, but there's no
    simulation-level aggregation.

    Effort Estimate

    ┌────────────────────┬─────────────┬──────────────────────────┐
    │     Component      │ Complexity  │        Depends On        │
    ├────────────────────┼─────────────┼──────────────────────────┤
    │ SimFace / SimLink  │ Medium      │ Nothing — can start here │
    ├────────────────────┼─────────────┼──────────────────────────┤
    │ Topology builder   │ Small       │ SimFace                  │
    ├────────────────────┼─────────────┼──────────────────────────┤
    │ Deterministic time │ Medium-Hard │ Audit all timer usage    │
    ├────────────────────┼─────────────┼──────────────────────────┤
    │ Event tracing      │ Small       │ Existing tracing infra   │
    ├────────────────────┼─────────────┼──────────────────────────┤
    │ Metric collection  │ Medium      │ Event tracing            │
    └────────────────────┴─────────────┴──────────────────────────┘

    The SimFace + topology builder alone would already be a massive improvement over Mini-NDN. Deterministic time is harder but important for research reproducibility.

    Why This Could Be Genuinely Better Than Mini-NDN

    - Single process — no Mininet, no SSH, no PID management, no cleanup scripts
    - Programmatic topology — Rust code, not Python scripts calling subprocess
    - In-process debugging — attach one debugger to the whole simulation
    - Speed — no real network stack overhead, no serialization to localhost sockets
    - Deterministic replay (once time is sorted out)
    - Strategy testing — swap strategies per-node without recompilation (WASM tier)

    The bones are there. The main gap is the simulated link layer and time control. If this is something you're interested in pursuing, a ndn-sim crate with SimFace, SimLink, and a Simulation topology
    builder would be a natural next step.


Additional thoughts:
- This approach is along the lines of ndnsim.
- We should also have the application-oriented approach too like minindn.
- Quality of life tools like ui abstraction over experiement files and their design would be very helpful.
- minindn is able to have wifi interfaces via ieee80211_hw-something
