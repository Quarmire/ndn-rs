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
services.ndn-router = {
  enable = true;
  identity         = "/mynet/myhost";   # key name
  pibPath          = null;              # defaults to /var/lib/ndn-router/pib
  generateIdentity = true;              # run ndn-sec keygen on every boot (idempotent)
};
```

With `generateIdentity = true`, the service runs:

```
ndn-sec --pib /var/lib/ndn-router/pib keygen --anchor --skip-if-exists /mynet/myhost
```

before starting `ndn-fwd`.  This is idempotent — if the key already exists
the step is a no-op.  Keys are persisted in
`/var/lib/ndn-router/pib/` (the `StateDirectory`), which survives reboots.

The module creates a stable `ndn-router` user and group to own the state
directory and run the service.

## Configuration reference

```toml
[security]
identity         = "/mynet/myhost"       # key name; omit for ephemeral
pib_path         = "~/.ndn/pib"          # path to FilePib directory
pib_type         = "file"                # "file" | "memory"
ephemeral_prefix = "/ndn/ephemeral"      # name prefix for ephemeral identity
```
