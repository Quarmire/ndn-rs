# NLSR — Named-data Link State Routing

NLSR is the link-state routing protocol used by the NDN testbed. `ndn-fwd` implements it via `NlsrProtocol` in the `ndn-routing` crate.

## Enabling NLSR

Add a `[routing.nlsr]` section to your `ndn-fwd.toml`:

```toml
[routing.nlsr]
enabled  = true
network  = "/ndn"
router   = "/ndn/mysite/%C1.Router/myrouter"
name_prefixes = ["/ndn/mysite/myrouter/data"]

[[routing.nlsr.neighbor]]
name      = "/ndn/othersite/%C1.Router/peerrouter"
face_uri  = "udp4://10.0.0.2:6363"
link_cost = 10.0
```

The `router` field is the full NDN name of this router (`<network><site><router-component>`). Set `name_prefixes` to the prefixes this router originates into the NLSR mesh.

The `face_uri` in each neighbor entry must match the `remote_uri()` of a face configured in `[[face]]`. Pre-create the face:

```toml
[[face]]
kind   = "udp"
remote = "10.0.0.2:6363"   # ndn-rs creates the UDP face on startup
```

## Configuration reference

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `false` | Enable NLSR. |
| `network` | `/ndn` | NDN network name prefix. |
| `router` | (required) | Full router name (`<network><site>/<router-component>`). |
| `name_prefixes` | `[]` | Prefixes this router advertises into the NLSR mesh. |
| `lsa_refresh_secs` | 1800 | LSA lifetime. |
| `hello_interval_secs` | 60 | Hello Interest send interval. |
| `hello_retries` | 3 | Retries before declaring a neighbor inactive. |
| `hello_timeout_secs` | 1 | Per-Hello-Interest timeout. |
| `adj_lsa_build_interval_secs` | 10 | Delay before rebuilding own AdjLSA after neighbor state change. |
| `routing_calc_interval_secs` | 15 | Routing recompute interval after LSDB change. |
| `permissive_validation` | `false` | Config knob for LSA validation bypass. See note below. |
| `max_faces_per_prefix` | 0 (no limit) | Maximum nexthop faces per FIB entry. |

### Neighbor fields (`[[routing.nlsr.neighbor]]`)

| Key | Default | Description |
|-----|---------|-------------|
| `name` | (required) | NDN name of the neighbor router. |
| `face_uri` | (required) | URI of the face to this neighbor, e.g. `udp4://10.0.0.2:6363`. |
| `link_cost` | 10.0 | Dijkstra link cost. |

## Sync protocol

NLSR uses PSync (full-sync) for LSA flooding. The PSync group prefix is `<network>/nlsr/LSA`.

## Trust and validation

**Current status:** LSA validation is not yet implemented. `NlsrProtocol` accepts all received LSAs regardless of the `permissive_validation` setting — the field is a declared knob with no runtime effect pending the LSA content fetch + validator wiring follow-up. Setting `permissive_validation = true` documents intent.

## Interop with C++ NLSR

The `testbed/docker-compose.yml` includes three services for the G.04 interop witness:

- `ndn-fwd-nlsr` — ndn-rs with NLSR at `172.30.0.30`, config at `testbed/configs/ndn-fwd-nlsr/ndn-fwd.toml`.
- `nfd-nlsr` — NFD sidecar at `172.30.0.14`, required by C++ NLSR for local forwarder access.
- `nlsr-cxx` — C++ NLSR at `172.30.0.13` (`ghcr.io/named-data/nlsr:latest`).

Run the witness:

```bash
# Set Docker host if using a remote engine (developer machines only):
export DOCKER_HOST=ssh://your-docker-host

bash testbed/tests/audit/g04_nlsr_interop.sh
```

The witness exits 0 once both sides converge within 90 s (verified 2026-05-08).

## LSA fetch on demand

When ndn-rs receives a PSync seq update from a remote NLSR node, it fetches
the corresponding LSA content via an NDN Interest:

```
/<network>/<router>/nlsr/LSA/<lsa-type>/<seq>
```

C++ NLSR serves LSA content at this prefix. ndn-rs decodes the Data payload
as an `Lsa` and installs it in the LSDB. Errors during fetch (timeout, Nack,
decode failure) are logged at `WARN` level with structured fields
`{router, lsa_type, seq, reason}`; the next PSync round retries automatically.

ndn-rs also serves its own LSAs under the same prefix so C++ NLSR can fetch
them. The serve path is `NlsrProtocol::lsa_io_task` / `serve_lsa_interest`
in `crates/protocols/ndn-routing/src/protocols/nlsr/protocol.rs`.

**Operator note:** LSA fetch can silently fail if the trust-anchor setup is
wrong. C++ NLSR validates received LSA Data against its configured trust
anchor. If ndn-rs is not signing LSA Data with a key that C++ NLSR trusts,
C++ NLSR drops the Data and the adjacency never forms. For the two-node
testbed witness, `permissive_validation` is set in C++ NLSR's config
(`security { validator { trust-anchor { type any } } }`), which bypasses
certificate chain validation. A production deployment must provision proper
NLSR certificates via NDNCERT.
