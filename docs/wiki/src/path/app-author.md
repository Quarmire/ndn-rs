# App author

You want to fetch and publish named data from your own program. You do
not need to run a forwarder, write a strategy, or learn the engine
internals — you need a client API and a trust policy. This page is the
shortest line to a working app.

Assumes the one idea from [Why NDN is different](../start/why-ndn-is-different.md):
you fetch a name, and what comes back is signed.

<div class="cds-callout success">
<span class="cds-callout-title">Your first win</span>
Connect a <code>Consumer</code> and call <code>fetch_object</code> to pull
a <code>Data</code> by name. → <a href="../quickstart/5-minute-app.md">Five-minute app</a>.
Publishing the other side is the <a href="../quickstart/10-minute-producer.md">ten-minute producer</a>.
</div>

## Where to stop

You can build a complete application without ever touching the
forwarder's internals.

<div class="cds-callout">
<span class="cds-callout-title">You do not need</span>
the PIT/FIB/Content Store internals, forwarding strategies, face types,
or routing. Those are the <a href="extender.md">Extender</a> path. The one
thing you <em>do</em> own is your trust policy — decide it deliberately:
<a href="../start/trust-first.md">Trust, first</a>.
</div>

## The path

1. [Five-minute app](../quickstart/5-minute-app.md) — fetch a `Data` by name.
2. [Ten-minute producer](../quickstart/10-minute-producer.md) — serve one.
3. [Trust, first](../start/trust-first.md) — choose the policy that decides what you accept.
4. [Building an application](../guides/building-an-app.md) — the fuller walkthrough.
5. [Develop tier](../api/develop.md) — the stable API surface, as reference.

<div class="cds-card-grid">
<a class="cds-card" href="../api/develop.md">
<span class="cds-icon" style="--i:url(../images/icons/app.svg)"></span>
<span class="cds-card-title">Develop tier reference</span>
<span class="cds-card-desc">Consumer, Producer, KeyChain — the application-facing API.</span>
</a>
<a class="cds-card" href="../start/trust-first.md">
<span class="cds-icon" style="--i:url(../images/icons/confidentiality.svg)"></span>
<span class="cds-card-title">Trust, first</span>
<span class="cds-card-desc">The one decision an app author can't skip.</span>
</a>
</div>
