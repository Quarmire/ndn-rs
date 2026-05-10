#!/usr/bin/env bash
# backup.sh — capture the ndn-fwd state that's worth preserving.
#
# Streams a tar of the three docker volumes that hold non-derivable
# state to stdout. Cron-friendly; redirect to a timestamped file or
# pipe to your offsite backup tool.
#
#   ./backup.sh > ndn-fwd-backup-$(date +%F).tar.gz
#   ./backup.sh | aws s3 cp - s3://my-bucket/ndn-fwd/$(date +%F).tar.gz
#
# What's included:
#   ndn-fwd-config — the toml, the trust-anchor pem, signing identity.
#   ndn-fwd-pib    — the personal information base (issued certs, key chain).
#   ndn-fwd-acme   — the ACME cert cache (so a restore doesn't trigger
#                    Let's Encrypt rate limiting on first restart).
#
# What's NOT included:
#   ndn-fwd-run    — runtime sockets / pidfile, regenerated on startup.
#   PIT / CS       — in-memory; ephemeral by design.
#
# Restore: see `docs/wiki/src/operations/self-hosting.md`. The short
# version is `tar -xzf backup.tar.gz -C /var/lib/docker/volumes/` with
# the stack stopped.

set -euo pipefail

VOLUMES=(ndn-fwd-config ndn-fwd-pib ndn-fwd-acme)

# Spin up a throwaway alpine that has the named volumes mounted, tar
# them all up, and stream the tar to stdout. Doesn't require knowing
# the host's docker volumes path, doesn't require root.
docker run --rm \
  $(printf -- '-v %s:/state/%s:ro ' "${VOLUMES[@]/#/}" "${VOLUMES[@]}") \
  -v /tmp:/tmp \
  alpine:latest \
  tar -czf - -C /state .
