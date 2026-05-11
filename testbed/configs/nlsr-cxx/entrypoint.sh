#!/bin/bash
# G.04 witness entrypoint for nlsr-cxx container.
#
# Generates an ephemeral NLSR identity on first run, exports the
# self-signed cert for NLSR to publish, then starts NLSR.
# The identity is stored in the container's PIB (~/.ndn/pib.db),
# which is ephemeral — recreated each container start.
#
# NOTE: nfdc-side neighbor bootstrap (face + route to ndn-fwd-nlsr)
# is done from the nfd-nlsr container — see
# `testbed/configs/nfd-nlsr/entrypoint.sh`.  The `nlsr:latest` image
# is too minimal to ship `nfdc`, so we run the nfdc commands from
# the NFD container where they belong anyway.
set -e

ROUTER_NAME="/test/c-nlsr/%C1.Router/r1"
CERT_FILE="/var/lib/nlsr/router.cert"

mkdir -p /var/lib/nlsr

if ! ndnsec list 2>/dev/null | grep -qF "$ROUTER_NAME"; then
    echo "[entrypoint] generating NLSR identity for $ROUTER_NAME"
    ndnsec key-gen "$ROUTER_NAME"   # default key type is ECDSA (matches NLSR's trust rules)
fi

ndnsec cert-dump -i "$ROUTER_NAME" > "$CERT_FILE"
echo "[entrypoint] cert exported to $CERT_FILE"

exec nlsr -f /etc/ndn/nlsr.conf
