# When to use in-network compute

<div class="cds-callout extension">
<span class="cds-callout-title">Extension <span class="scope extension">extension</span></span>
In-network compute is an ndn-rs extension with no NDN community spec
behind it. Everything below is specific to ndn-rs, and the trust model for
computed results is yours to define.
</div>

In-network compute lets you name a *computation* — not just stored bytes —
and have it run where the inputs already are, with the result returned as
ordinary Data and cached like any other. It is a sharp tool with a narrow
sweet spot.

| You have… | Compute is… | Why |
|---|---|---|
| Large inputs near their source, a small result | **A good fit** | Move the function to the data instead of dragging the data to the function. |
| A result many consumers will ask for | **A good fit** | The computed Data caches; later requests are cache hits, not recomputation. |
| A simple fetch of existing data | **Not needed** | Plain Interest/Data already does this — don't add a moving part. |
| A one-off, unique-per-caller computation | **A poor fit** | Nothing to cache and nothing to amortise; the machinery buys you nothing. |
| Unclear trust in *who computed it* | **Premature** | A computed result is signed by the executor, not the original producer — settle what that signature means to you first. |

## How to decide

1. **Would plain fetch do?** Then use it. Compute earns its place only
   when computation-near-data or result-reuse is the point.
2. **Is the result cacheable and shared?** That is where the win is — many
   consumers, one execution.
3. **Do you trust the executor's signature on the result?** Decide this
   before deploying; it is a different trust question than fetching a
   producer's own Data ([Trust, first](../start/trust-first.md)).

The mechanics — naming functions, passing arguments, the result contract —
are in [In-network compute](../guides/in-network-compute.md).
