---
name: trace-packet
description: Trace how a packet with a given name flows through the ndn-rs pipeline
user_invocable: true
---

The user wants to understand how a specific named packet would flow through the ndn-rs forwarding pipeline.

Steps:
1. Take the packet name and type (Interest or Data) as input
2. Walk through each pipeline stage and explain what would happen:

For Interest:
- TlvDecodeStage: Parse the Interest, extract name, check /localhost scope
- CsLookupStage: Would the CS have a match? (depends on name and CS state)
- PitCheckStage: Would PIT aggregate or create new entry? Nonce handling
- StrategyStage: FIB longest-prefix match result, which strategy applies, forwarding decision
- Dispatch: Which faces would receive the Interest

For Data:
- TlvDecodeStage: Parse the Data, extract name
- PitMatchStage: Which PIT entry matches? Which faces are in the in-records?
- ValidationStage: Would validation run? What trust schema applies?
- CsInsertStage: Would the data be cached? Admission policy
- Dispatch: Fan-out to all in-record faces

3. Reference actual source files for each stage in `crates/ndn-engine/src/stages/`
4. Note any special cases (scope violations, loop detection, Nack generation)

The packet name is provided as the argument (e.g., "/ndn/edu/ucla/data/v1").
