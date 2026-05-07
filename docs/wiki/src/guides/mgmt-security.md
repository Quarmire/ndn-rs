# Management Command Security

ndn-fwd requires key-backed signed Interests for privileged management
commands by default. This page explains how to configure trust anchors,
sign commands with `ndn-ctl`, and opt out for local dev setups.

## Background

NFD's command authenticator (Developer Guide §7) accepts only
key-backed signatures (Ed25519, ECDSA, RSA, BLAKE3) on command Interests.
DigestSha256 verifies integrity but does not establish key identity and is
treated as unsigned for authorization purposes.

ndn-fwd mirrors this behavior via the `[security.mgmt]` config section.

## Quick start

### 1. Generate an identity rig

```sh
cargo build -p ndn-tools --bins
./testbed/configs/identities/gen_identities.sh --pib /etc/ndn/pib
```

This creates two keys in `/etc/ndn/pib`:

| Identity      | Role                              |
|---------------|-----------------------------------|
| `/test`       | Self-signed root trust anchor     |
| `/test/admin` | Signing key for `ndn-ctl` commands |

### 2. Configure ndn-fwd

```toml
[security.mgmt]
require_signed_commands = true
trust_anchor_pib        = "/etc/ndn/pib"
```

Startup aborts if `trust_anchor_pib` is set but the PIB is missing or
contains no trust anchors. Fix by running `gen_identities.sh` or adding
`require_signed_commands = false` to opt out (see below).

### 3. Sign commands with ndn-ctl

```sh
# With key-backed signature — accepted when anchors are configured:
ndn-ctl --identity /test/admin --pib /etc/ndn/pib route add /ndn --face 1

# Without --identity — DigestSha256 only, rejected when require_signed_commands=true:
ndn-ctl route add /ndn --face 1
```

## Dev / single-host mode

For local testing without a provisioned identity, disable signing
enforcement:

```toml
[security.mgmt]
require_signed_commands = false
```

Unsigned and DigestSha256-signed commands are then accepted with a
warning logged at each dispatch.

## Trust anchor PIB layout

The PIB is a directory with two subdirectories:

```
pib/
  keys/
    <hash>/          # keyed by sha256(name)
      private.key    # 32-byte Ed25519 seed
      cert.ndnc      # NDNC-format certificate
      name.uri       # NDN name URI
  anchors/
    <hash>/          # same hash scheme
      cert.ndnc
      name.uri
```

`ndn-fwd` loads only the `anchors/` entries at startup; the `keys/`
entries are for `ndn-ctl --identity` signing.

## Add or remove trust anchors

```sh
# Mark an existing key as a trust anchor:
ndn-sec --pib /etc/ndn/pib anchor add /test/admin

# Remove a trust anchor (does not delete the key):
ndn-sec --pib /etc/ndn/pib anchor remove /test/old-key

# List all trust anchors:
ndn-sec --pib /etc/ndn/pib anchor list
```

Restart ndn-fwd after changing the PIB — trust anchors are loaded once
at startup.

## Default behavior and upgrades

As of 2026-05-07 the default for `require_signed_commands` is `true`.
Deployments that upgrade without adding `[security.mgmt]` will reject
all management commands. The options are:

- **Production**: add `trust_anchor_pib` pointing to a prepared PIB.
- **Dev / local**: add `require_signed_commands = false` explicitly.

See `docs/notes/spec-compliance-audit-2026-04-20.md § E.01` for full
audit history and the live witness at
`testbed/tests/audit/e01_signed_mgmt_ndn_fwd.sh`.
