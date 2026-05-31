# Extender

You want to change how the stack behaves — a new forwarding strategy, a
new face over some bearer, a routing protocol — without forking the
engine. The engine exposes these as traits you implement and register.
This page points you at the seams.

Assumes [Why NDN is different](../start/why-ndn-is-different.md) and the
mechanics in [One packet, six depths](../start/one-packet-six-depths.md) —
strategies live at depth 4, faces at depth 5.

<div class="cds-callout success">
<span class="cds-callout-title">Your first win</span>
Implement the <code>Strategy</code> trait and register it on a prefix.
→ <a href="../guides/writing-a-strategy.md">Writing a strategy</a>.
The trait surface is the <a href="../api/extend.md">Extend tier</a>.
</div>

## Where to stop

You extend through traits, not by editing the engine. If a change needs a
core engine edit, that is a signal to reconsider the seam — the extension
points are designed so you should not have to.

<div class="cds-callout">
<span class="cds-callout-title">Three seams</span>
<code>Strategy</code> (how an Interest is forwarded), <code>Face</code>
(a link over a bearer), and <code>RoutingProtocol</code> (what fills the
FIB). Pick the one that matches your change; ignore the rest.
</div>

## The path

1. [Extend tier](../api/extend.md) — the trait surface: `Strategy`, `Face`, `RoutingProtocol`.
2. [Writing a strategy](../guides/writing-a-strategy.md) — the forwarding-decision seam.
3. [Implementing a face](../guides/implementing-a-face.md) — a transport + link service.
4. [Interest and Data lifecycle](../concepts/interest-data-lifecycle.md) — where your code runs in the pipeline.

<div class="cds-card-grid">
<a class="cds-card" href="../guides/writing-a-strategy.md">
<span class="cds-icon" style="--i:url(../images/icons/routing.svg)"></span>
<span class="cds-card-title">Writing a strategy</span>
<span class="cds-card-desc">The forwarding-decision seam, end to end.</span>
</a>
<a class="cds-card" href="../guides/implementing-a-face.md">
<span class="cds-icon" style="--i:url(../images/icons/faces.svg)"></span>
<span class="cds-card-title">Implementing a face</span>
<span class="cds-card-desc">A new bearer as a transport + link service.</span>
</a>
</div>
