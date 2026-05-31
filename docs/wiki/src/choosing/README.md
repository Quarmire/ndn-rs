# Choosing

The rest of the wiki documents features one at a time. These pages do the
opposite: they start from *your situation* and tell you which feature to
reach for — and, just as importantly, what it costs you.

Two rules run through all of them:

1. **Default to the simplest thing.** Plain signed Data over a UDP face
   with a static route covers more cases than newcomers expect. Add a
   capability only when a concrete need justifies its cost.
2. **Every capability has a cost.** More confidentiality, more throughput,
   more autonomy in routing — each buys something and charges something
   (key distribution, Linux-only code, convergence traffic, compute). The
   tables below put the charge next to the benefit so you can decide.

Anything marked <span class="scope extension">extension</span> is an
ndn-rs addition with no NDN community spec behind it — fine to use, but
know that you are leaving the standardised core. See
[Why NDN is different](../start/why-ndn-is-different.md) for that
distinction.

## The decisions

- [Confidentiality](./confidentiality.md) — who may *read* the data (signing already says who *wrote* it).
- [Faces & transports](./faces-and-transports.md) — which bearer a link runs over.
- [Routing & discovery](./routing-and-discovery.md) — how Interests find producers.
- [Reliability & throughput](./reliability-and-throughput.md) — surviving loss and going faster.
- [When to use in-network compute](./in-network-compute.md) — moving computation to the data. <span class="scope extension">extension</span>
