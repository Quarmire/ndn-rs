#!/bin/bash
# C.13 witness entrypoint for the ndncert-ca container.
#
# Generates an ephemeral CA identity on first run, then starts
# ndncert-ca-server.  The identity is stored in the container's PIB
# (~/.ndn/pib.db); it is recreated each container start.
#
# NDN_LOG=ndncert.challenge.pin=TRACE is set in the compose service so
# the witness script can extract the generated PIN from docker logs.
set -e

CA_NAME="/test/ndncert/CA"
CA_CONF="/config/ndncert-ca.conf"

# Wait for NFD to accept connections.
echo "[entrypoint] waiting for NFD at /run/nfd/nfd.sock …"
WAIT=0
while [[ $WAIT -lt 30 ]]; do
    if nfdc status >/dev/null 2>&1; then break; fi
    sleep 1
    WAIT=$((WAIT + 1))
done

if ! nfdc status >/dev/null 2>&1; then
    echo "[entrypoint] ERROR: NFD not ready after 30 s" >&2
    exit 1
fi
echo "[entrypoint] NFD ready"

# Generate CA identity if not already present.
if ! ndnsec list 2>/dev/null | grep -qF "$CA_NAME"; then
    echo "[entrypoint] generating CA identity for $CA_NAME"
    ndnsec key-gen "$CA_NAME"
fi

echo "[entrypoint] starting ndncert-ca-server with $CA_CONF"
exec ndncert-ca-server -c "$CA_CONF"
