# Operator

You want to run a node and watch traffic move through it — not write Rust.
Your job is to start the forwarder, point faces at peers, and read what it
reports. This page is the line from nothing to a running, observable node.

Assumes the one idea from [Why NDN is different](../start/why-ndn-is-different.md):
the forwarder moves named data, and any node may cache it.

<div class="cds-callout success">
<span class="cds-callout-title">Your first win</span>
Start <code>ndn-fwd</code> and see it forward a request.
→ <a href="../quickstart/running-the-forwarder.md">Running the forwarder</a>.
Then watch it live in the <a href="../guides/running-the-dashboard.md">dashboard</a>.
</div>

## Where to stop

Running and observing a node is a configuration job, not a programming
one.

<div class="cds-callout">
<span class="cds-callout-title">You do not need</span>
the client API, the engine internals, or strategy/face authoring. You need
the config knobs and the management surface. If you find yourself wanting
to change <em>how</em> forwarding decides, that is the
<a href="extender.md">Extender</a> path.
</div>

## The path

1. [Running the forwarder](../quickstart/running-the-forwarder.md) — start a node.
2. [ndn-fwd](../operations/ndn-fwd.md) — the binary, its flags, and faces.
3. [Config reference](../operations/config-reference.md) — every knob, by category.
4. [Logging](../operations/logging.md) — read what the node reports.
5. [Running the dashboard](../guides/running-the-dashboard.md) — watch faces, routes, and strategy live.

<div class="cds-card-grid">
<a class="cds-card" href="../operations/ndn-fwd.md">
<span class="cds-icon" style="--i:url(../images/icons/operator.svg)"></span>
<span class="cds-card-title">ndn-fwd operations</span>
<span class="cds-card-desc">Run, configure, and manage the forwarder.</span>
</a>
<a class="cds-card" href="../operations/performance.md">
<span class="cds-icon" style="--i:url(../images/icons/reliability.svg)"></span>
<span class="cds-card-title">Performance</span>
<span class="cds-card-desc">Throughput knobs and what moves the needle.</span>
</a>
</div>
