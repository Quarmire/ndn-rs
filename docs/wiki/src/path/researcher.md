# Researcher

You want to observe what the engine does, measure it, and wire engines
together for experiments. The instrument surface lets you tap every packet
and inject behaviour without changing the engine — it is opt-in and looser
than the application or extension APIs by design.

Assumes [One packet, six depths](../start/one-packet-six-depths.md): you
are here to watch and measure that pipeline, not just use it.

<div class="cds-callout extension">
<span class="cds-callout-title">Extension <span class="scope extension">extension</span></span>
The instrument tier is gated behind the <code>experimental-instrument</code>
feature and is not part of any NDN community spec — it is an ndn-rs
research surface. Expect a looser stability promise than Develop or Extend.
</div>

<div class="cds-callout success">
<span class="cds-callout-title">Your first win</span>
Attach a <code>TapFace</code> and watch every packet cross it.
→ <a href="../api/instrument.md">Instrument tier</a>.
</div>

## Where to stop

The instrument tier is for measurement and experiments, not production
data paths. If your tap is shaping real traffic rather than observing it,
you have crossed into the <a href="extender.md">Extender</a> path
(a `Strategy` or `Face`), which carries a firmer contract.

## The path

1. [Instrument tier](../api/instrument.md) — `TapFace`, packet observation, wiring two engines.
2. [Interest and Data lifecycle](../concepts/interest-data-lifecycle.md) — the pipeline you are measuring.
3. [Performance](../operations/performance.md) — throughput knobs and how to benchmark.

<div class="cds-card-grid">
<a class="cds-card" href="../api/instrument.md">
<span class="cds-icon" style="--i:url(../images/icons/researcher.svg)"></span>
<span class="cds-card-title">Instrument tier</span>
<span class="cds-card-desc">Observe every packet; inject a strategy; wire two engines.</span>
</a>
<a class="cds-card" href="../operations/performance.md">
<span class="cds-icon" style="--i:url(../images/icons/reliability.svg)"></span>
<span class="cds-card-title">Performance</span>
<span class="cds-card-desc">Measure throughput and find what moves it.</span>
</a>
</div>
