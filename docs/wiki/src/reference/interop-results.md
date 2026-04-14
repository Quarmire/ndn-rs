# Interoperability Test Results

This page is automatically updated by the
[testbed CI workflow](https://github.com/Quarmire/ndn-rs/actions/workflows/testbed.yml)
on every push to `main` and weekly on Mondays.

The test matrix exercises ndn-rs against ndn-cxx, NDNts, NFD, and yanfd in both
consumer and producer roles. See [Interoperability Testing](../deep-dive/interop-testing.md)
for the full scenario descriptions and the compatibility challenges resolved along the way.

<!-- The section below is machine-generated. Do not edit manually. -->

*Last run: `20260414T215945Z` &nbsp;·&nbsp; 8 passed, 0 failed, 0 skipped*

| Scenario | Result | Description |
|----------|:------:|-------------|
| **ndn-fwd as Forwarder** | | |
| `fwd/cxx-consumer` | ✅ PASS | ndn-cxx consumer ← ndn-fwd → ndn-rs producer |
| `fwd/cxx-producer` | ✅ PASS | ndn-rs consumer ← ndn-fwd → ndn-cxx producer |
| `fwd/ndnts-consumer` | ✅ PASS | NDNts consumer ← ndn-fwd → ndn-rs producer |
| `fwd/ndnts-producer` | ✅ PASS | ndn-rs consumer ← ndn-fwd → NDNts producer |
| **ndn-rs as Application Library** | | |
| `app/nfd-cxx-producer` | ✅ PASS | ndn-rs consumer → NFD → ndn-cxx producer (with signature validation) |
| `app/nfd-cxx-consumer` | ✅ PASS | ndn-cxx consumer → NFD → ndn-rs producer (ndn-cxx validates signature) |
| `app/yanfd-ndnts-producer` | ✅ PASS | ndn-rs consumer → yanfd → NDNts producer |
| `app/yanfd-ndnts-consumer` | ✅ PASS | NDNts consumer → yanfd → ndn-rs producer |

