---
name: sim-test
description: Generate an ndn-sim test scenario for the ndn-rs simulation framework
user_invocable: true
---

The user wants to create a simulation test using the ndn-sim crate.

Steps:
1. Ask for: topology (number of nodes, link pattern), traffic pattern, what to measure
2. Read `crates/ndn-sim/src/lib.rs` and `crates/ndn-sim/src/topology.rs` for the simulation API
3. Generate a test file in `crates/ndn-sim/tests/` that:
   - Creates a `Simulation` with the requested topology
   - Configures `LinkConfig` with appropriate delay/loss/bandwidth
   - Sets up routes via `add_route()`
   - Starts the simulation
   - Runs the traffic pattern (express Interests, publish Data)
   - Asserts expected outcomes (Data received, latency bounds, cache hits)
4. Include comments explaining each step

The scenario description is provided as the argument (e.g., "3-node chain with 10ms links").
