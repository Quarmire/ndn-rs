# Security Identity and Key Management

`ndn-fwd` requires a signing identity to sign Data packets and management
responses.  This guide explains how identity is provisioned, what happens when
things go wrong, and how to manage keys with `ndn-sec`.

## Identity resolution at startup

When `ndn-fwd` starts, it resolves a signing identity in priority order:

1. **Configured identity** — `security.identity` in `ndn-fwd.toml` points to
   a key name in the PIB at `security.pib_path` (default: `~/.ndn/pib/`).
2. **Ephemeral identity** — if no identity is configured, or if the PIB fails
   to load, an in-memory Ed25519 key is generated.  The name is taken from:
   - `security.ephemeral_prefix` (config), or
   - `$HOSTNAME`, or
   - `pid-<pid>` as a last resort.

An ephemeral identity is never written to disk.  It is recreated on every
restart, so Data signed with it cannot be verified after the process exits.

### PIB error recovery

If an identity is configured but the PIB fails (missing directory, corrupt
key file, permission error), `ndn-fwd` behaves differently depending on how
it is running:

- **Interactive (TTY)**: an interactive menu is presented:
  ```
  PIB error: <description>
  Options:
    [1] Generate a new key at <pib_path>
    [2] Continue with ephemeral identity (not persisted)
    [3] Abort
  Choice:
  ```
- **Daemon (no TTY)**: the error is logged as a structured `tracing` event
  at `ERROR` level and the router falls back to ephemeral automatically.

## Checking identity status

```bash
# From CLI (requires a running router)
ndn-ctl security identity-status

# Programmatically (MgmtClient)
let resp = mgmt_client.security_identity_status().await?;
// "identity=/ndn/myhost/KEY/abc is_ephemeral=false pib_path=/var/lib/ndn/pib"
```

The dashboard **Security** tab always shows a banner:

- **Yellow** — ephemeral identity; data cannot be verified after restart.
  The banner links to the config tab to set a persistent identity.
- **Green** — persistent identity loaded from PIB.

## Managing keys with `ndn-sec`

```bash
# Generate a new anchor key
ndn-sec keygen --anchor /mynet/myhost

# Generate (skip if already exists — idempotent)
ndn-sec keygen --anchor --skip-if-exists /mynet/myhost

# List keys in the default PIB
ndn-sec list

# Use a custom PIB path
ndn-sec --pib /var/lib/ndn/pib list

# Export a certificate (DER)
ndn-sec export /mynet/myhost > myhost.ndnc
```

## NixOS

On NixOS, `/` is read-only and `DynamicUser = true` is incompatible with
persistent key storage.  The ndn-rs NixOS module handles this automatically:

```nix
services.ndn-fwd = {
  enable = true;
  identity         = "/mynet/myhost";   # key name
  pibPath          = null;              # defaults to /var/lib/ndn-fwd/pib
  generateIdentity = true;              # run ndn-sec keygen on every boot (idempotent)
};
```

With `generateIdentity = true`, the service runs:

```
ndn-sec --pib /var/lib/ndn-fwd/pib keygen --anchor --skip-if-exists /mynet/myhost
```

before starting `ndn-fwd`.  This is idempotent — if the key already exists
the step is a no-op.  Keys are persisted in
`/var/lib/ndn-fwd/pib/` (the `StateDirectory`), which survives reboots.

The module creates a stable `ndn-fwd` user and group to own the state
directory and run the service.

## Data validation and ContentStore admission

As of 2026-05-08, the ContentStore only admits Data that has passed the
validation stage (`ctx.verified = true`). The trust verdict flows through
`PacketContext` — the CS gate is independent of the admission policy
(FreshnessPeriod check) and runs first.

**Default validation profile:** `"default"`. When no `[security]` block is
configured, the router uses `AcceptSigned` validation: any Data with a valid
signature (DigestSha256 or stronger) is admitted; trust hierarchy is not
enforced. Configure a `[security]` block with `trust_anchor` or `trust_anchor_pib`
for full hierarchical validation.

**Dev/lab opt-out:** set `validator_enabled = false` to skip crypto verification.
All incoming Data is then treated as permissive-verified so it can reach the CS.
This removes the trust barrier — **use only in isolated environments.**

```toml
[security]
validator_enabled = false   # dev/lab only — no trust anchor required
```

Trust anchors and the validation profile are independent of `validator_enabled`.
Setting `validator_enabled = false` overrides `profile` to `"disabled"` for
the forwarding pipeline regardless of what `profile` says.

## Configuration reference

```toml
[security]
identity          = "/mynet/myhost"       # key name; omit for ephemeral
pib_path          = "~/.ndn/pib"          # path to FilePib directory
pib_type          = "file"                # "file" | "memory"
ephemeral_prefix  = "/ndn/ephemeral"      # name prefix for ephemeral identity
validator_enabled = true                  # false = dev/lab, no trust anchor needed
profile           = "default"             # "default" | "accept-signed" | "disabled"
```
