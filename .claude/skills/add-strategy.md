---
name: add-strategy
description: Scaffold a new forwarding Strategy for ndn-rs
user_invocable: true
---

The user wants to create a new forwarding strategy for ndn-rs.

Steps:
1. Ask for: strategy name, brief description of forwarding behavior
2. Read `crates/ndn-strategy/src/lib.rs` for the Strategy trait
3. Read existing strategies as templates (BestRoute in `crates/ndn-strategy/src/best_route.rs`, Multicast in `crates/ndn-strategy/src/multicast.rs`)
4. Create the new strategy file in `crates/ndn-strategy/src/`:
   - Implement `Strategy` trait
   - `after_receive_interest()` -- the core forwarding decision
   - `after_receive_data()` -- optional measurement updates
   - `on_interest_timeout()` -- optional retry logic
5. Export from `crates/ndn-strategy/src/lib.rs`
6. Add a basic test

The strategy name is provided as the argument (e.g., "weighted-random", "adaptive-srtt", "geo-forwarding").
