#!/usr/bin/env bash
# Witness test for audit finding B.01 — NDNLPv2 link-layer reliability
# emits `Sequence` (0x51) where the spec requires `TxSequence` (0x0348).
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § B.01
# Severity:    BLOCKER
# Spec ref:    NDNLPv2 Link-Layer Reliability — TxSequence (0x0348) is
#              distinct from the fragmentation Sequence (0x51). Ack
#              headers (0x0344) reference TxSequence values.
# Witnesses:   Packets emitted by LpReliability::on_send carry 0x51
#              where the spec expects 0x0348. tcpdump on the ndn-fwd ↔
#              NFD link shows the field type; no Ack arrives from NFD.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail

cat >&2 <<'EOF'
SKIP: B.01 witness requires enabling link-layer reliability on both
      ndn-fwd and the NFD peer, then sniffing the wire to inspect the
      header TLV-TYPE bytes. This is expected state, not implemented
      yet in the harness:

  1. Add `reliability = true` to the relevant face in
     testbed/configs/ndn-fwd.toml (syntax to be wired up in Phase E
     remediation).
  2. Enable `ReliabilityOptions` on the corresponding NFD face
     (`nfdc face update <id> reliability on`).
  3. Generate sustained traffic so reliability's retransmit path
     fires (ndn-iperf with artificial loss via `tc netem`).
  4. Capture with tcpdump and filter for LpPacket headers:
       tshark -r capture.pcap -Y 'ndn.lp.tx_sequence || ndn.lp.sequence'
  5. Assert the presence of tlv-type 0x0348 (TxSequence). Current
     code emits 0x51 (Sequence), so this fails today.

The fix is trivial: change `LP_SEQUENCE` to `LP_TX_SEQUENCE` in
crates/foundation/ndn-packet/src/lp/encode.rs::encode_lp_reliable,
and change `extract_acks` in lp/fragment.rs to read 0x0348. The
hard part is the witness harness setup.
EOF
exit 2
