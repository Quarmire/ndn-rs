# Dashboard extensions

The dashboard surfaces optional ndn-rs features as scoped, capability-gated
panels, kept separate from core engine state so the main model does not grow
with each one. A forwarder that does not implement the matching management
dataset shows the panel as unsupported.

## Network coding <span class="scope extension">extension</span>

The dashboard treats network coding as an optional ndn-rs extension surface,
displaying prefix, role, generation parameters, and capability state.
Non-ndn-rs forwarders show it as unsupported unless they implement the
matching management dataset. See [Network coding (FEC)](../guides/network-coding.md).

## Rate limit

Rate-limit cells are shown as scoped operational state: management-command
limits, face limits, and prefix limits. Compatible forwarders may expose
read-only cells; ndn-rs profiles can later enable mutation adapters behind the
same capability gate.

## Compute <span class="scope extension">extension</span>

Compute services appear as service names plus diagnostics. The extension
registry keeps compute separate from core engine state so service-specific
tools can be added without growing the main dashboard model. See
[In-network compute](../guides/in-network-compute.md).
