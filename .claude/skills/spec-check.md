---
name: spec-check
description: Check a specific ndn-rs feature against the NDN specification (RFC 8569/8609)
user_invocable: true
---

The user wants to verify whether a specific ndn-rs feature correctly implements the NDN specification.

Steps:
1. Read `docs/spec-gaps.md` for known gaps
2. Read the relevant source code for the feature in question
3. Reference RFC 8569 (NDN Forwarding) and RFC 8609 (NDN TLV) requirements
4. Compare the implementation against spec requirements
5. Report: what's correctly implemented, what's missing, what diverges intentionally

The feature or module name is provided as the argument (e.g., "pit", "interest-encoding", "nack-handling").
