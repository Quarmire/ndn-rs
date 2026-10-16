# Adopting a namespace's trust context (`ndn-fwd adopt`)

A device does not join a network: it **adopts** a namespace's signed trust
context, after which it accepts Data under `/<ns>` signed by keys chaining to
the namespace root, under the namespace's schema. Adopting forms no link and
adds no route (design: `docs/specs/personal-namespace.md`
§9). It starts from an `ndn-trust://anchor` link (a QR code or a pasted URI)
that carries the namespace, the **expected fingerprint** (SHA-256 of the
namespace root's public key) and the context version, and optionally the signed
context itself.

| Link form | Size | How the context arrives |
|---|---|---|
| `anchor_uri` (inline) | ~2.8 kB | inside the link |
| `anchor_uri_fp` (fingerprint only) | ~125 B | fetched by name over this node's links and routes |

`ndn-fwd init --namespace <ns>` prints both.

## What is checked

Whatever the form, a context is adopted only if:

1. it is named `/<ns>/32=trust-context/v=<N>` for the link's namespace;
2. it is signed (Ed25519, ECDSA or RSA) by one of the anchors it lists, and
   the signature verifies under that anchor's key;
3. that anchor's fingerprint equals the expected fingerprint from the link;
4. its version is not below the version the link names (a fetched older
   context is refused as a downgrade), and not below a version the node
   already holds (anti-rollback).

## The forwarder problem, and expectations

Every `ndn-fwd` validates the Data it forwards. A device that holds nothing
for `/<ns>` cannot anchor the root-signed context Data, so its own forwarder
would drop the very context it is fetching.

While an adoption runs, the adopter registers an **expectation**
`{namespace, expected fingerprint, deadline}` with the forwarder's validator
(`Validator::expect_context`). Only a Data named
`<namespace>/32=trust-context/v=<N>` is affected: it is admitted iff checks
1–3 hold (trust path `ExpectedContext`), and dropped otherwise — so a forged
context never leaves the device's forwarder. Every other name, and
every name while no expectation is live, is validated exactly as before. The
expectation ends when the adoption returns, or at its deadline (30 s); an
expired one admits nothing. The forwarder keeps what it admitted, so the
adopter reuses that verified result instead of verifying the same bytes again,
and what it refused, so the user is told *why* nothing arrived.

## The daemon does the adoption

`ndn-fwd adopt <link> [-c <config>]` sends `security/context-adopt` (link in
`ControlParameters.Uri`) to the running daemon over its management socket.
The daemon:

1. reads the link (`ndn_cert::AnchorLink`);
2. adopts it with `ndn_identity::adopt_anchor_link_via_engine`: an inline
   context is checked directly; a fingerprint-only link registers the
   expectation, fetches the context over RDR (`ndn_cert::fetch_context`)
   through an in-process consumer face, and checks it;
3. adopts it into the keyring its validator uses (trusted at once);
4. stores the signed Data in `<pib_path>/contexts/` (loaded again at every
   start);
5. publishes it by name (unless `[security] serve_contexts = false`), so other
   devices can fetch it from this one.

The command is answered from a task of its own, so a slow fetch does not stall
other management clients. Refusals say why and what to do: no route toward a
node serving the context, a reply carrying a context the forwarder refused
(wrong fingerprint: another namespace or an impersonator), a downgrade, a link without
namespace or fingerprint.

Without a running daemon, an inline link is verified and stored in the PIB
(loaded at the next start); a fingerprint-only link is refused with an
explanation, since it needs the daemon and a route.

### Who may adopt

Changing what a node trusts is authorized by the **peer credentials** of the
process on the other end of the management socket (the socket itself is
world-writable so unprivileged `ndn-ctl` works): the daemon's own user,
root, or a member of a group listed in

```toml
[security]
trust_admin_groups = ["ndn"]   # default: none
```

Everyone else is refused with an explanation of how to grant access. The gate
is `ndn_mgmt::auth::authorize_trust_admin`; trust-changing verbs are listed in
`TRUST_ADMIN_VERBS`.

## Usage

```sh
# root device
ndn-fwd init --namespace /home/bob --device laptop --pib ~/.ndn/pib
ndn-fwd -c root.toml
# device (its config has a link to the root device or a relay, and a route
# for /home/bob over it — adoption does not create either)
ndn-fwd -c device.toml
ndn-fwd adopt 'ndn-trust://anchor/_QRwS_…' -c device.toml
#   namespace            = /home/bob
#   expected_fingerprint = 2637…1d00
#   source               = fetched by name
#   stored               = …/contexts/2f686f6d652f626f62.tc
#   published            = true
```

Apps with an embedded engine (ndn-mobile) call the same function:
`NdnEngine::adopt_context_link(link_uri)`.

## Code

| Part | Where |
|---|---|
| Fingerprint, self-consistency check | `ndn_security::{anchor_fingerprint, SignedTrustContext::open_signed}` |
| Expectations | `ndn-security/src/validator/expected.rs` |
| Link parsing, checks, adoption | `ndn_cert::{AnchorLink, adopt_anchor_link}` |
| Engine binding | `ndn_identity::adopt_anchor_link_via_engine` |
| Management verb, backend trait | `ndn-mgmt` `security/context-adopt`, `TrustContextMgmtBackend` |
| Daemon backend, publisher | `ndn-fwd` `context_adopt.rs`, `context_publisher.rs` |
| CLI | `ndn-fwd` `onboard.rs` (`run_adopt`) |

## See also

- [Trust-context publication (RDR)](./trust-context-publication.md)
- [Trust policies](./trust-policies.md)
