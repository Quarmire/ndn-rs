# NDNCERT Enrollment

ndn-rs supports certificate issuance via the NDNCERT 0.3 protocol against
an upstream `ndncert-ca-server` (C++ reference implementation).

## Protocol overview

A certificate request follows three steps:

1. **NEW** — client sends a self-signed NDN Certificate (`CertRequest`) plus
   an ephemeral P-256 ECDH public key. The CA generates a shared AES-128-GCM
   session key and returns the CA's ECDH public key, a random salt, and the
   assigned `RequestId` (8 bytes).

2. **CHALLENGE** — client and CA exchange encrypted messages under the session
   key. The `pin` challenge requires two rounds:
   - Round 1 (trigger): client sends `SelectedChallenge = "pin"` with no
     parameters; CA generates a 6-digit PIN and responds with
     `status = CHALLENGE`, `challenge_status = "need-code"`.
   - Round 2 (submit): client sends the PIN code; CA validates and responds
     with `status = SUCCESS` and `IssuedCertName`.

3. **Cert fetch** — client expresses a plain Interest for the `IssuedCertName`
   returned in the CHALLENGE success response.

Both NEW and CHALLENGE Interests are signed with the requester's key.

## Running enrollment in the testbed

The testbed ships an `ndncert-ca` service for interop testing.

```bash
# Start the testbed
docker compose -f testbed/docker-compose.yml up -d nfd-ndncert ndncert-ca

# Run the witness (proves the full round-trip)
bash testbed/tests/audit/c13_ndncert_live_interop.sh
```

The CA is configured with:
- **prefix:** `/test/ndncert/CA`
- **challenge:** `pin` (no SMTP infra required)

## Using `enroll-ndncert` directly

`enroll-ndncert` is the enrollment helper binary built into the `interop`
container. Run it from a shell in the `interop` container:

```bash
docker exec -it interop bash
enroll-ndncert \
    --face-socket /run/nfd-ndncert/nfd.sock \
    --ca-prefix /test/ndncert/CA \
    --name /my/identity \
    --pin 123456
```

If `--pin` is omitted, the binary waits on stdin. The PIN appears in the
CA container logs when `NDN_LOG=ndncert.challenge.pin=TRACE` is set.

## CA configuration

```json
{
  "ca-prefix": "/test/ndncert/CA",
  "ca-info": "NDNCERT testbed CA (pin challenge)",
  "max-validity-period": "86400",
  "max-suffix-length": 5,
  "supported-challenges": [
    { "challenge": "pin" }
  ]
}
```

The CA generates an ephemeral identity via `ndnsec key-gen` on container
start. For a persistent CA, mount a PIB volume and pre-populate it.

## Spec references

- NDNCERT 0.3 protocol: `github.com/named-data/ndncert/wiki/NDNCERT-Protocol-0.3`
- C++ reference CA: `named-data/ndncert` (src/ca-module.cpp, src/challenge/challenge-pin.cpp)
- Audit finding C.13: `docs/notes/spec-compliance-audit-2026-04-20.md § C.13`
