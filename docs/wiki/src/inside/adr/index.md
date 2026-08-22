# Architecture Decision Records

An ADR captures **one** significant, hard-to-reverse decision: the context that
forced it, the choice made, and the consequences accepted. It answers the
question a future contributor asks when they find something surprising — *"why
is it done this way?"* — without making them excavate the git history or
interrupt whoever wrote it.

ADRs are **immutable once accepted.** A decision that no longer holds is not
edited; a new ADR supersedes it, and the old one is marked `Superseded by
NNNN`. This is what makes the record trustworthy: it is a log of what was
decided *and when*, not a description of the current state (that is what the
rest of this book and the code are for).

## When to write one

Write an ADR when a decision:

- is expensive to reverse (a wire format, a public trait shape, a
  cross-crate boundary), **or**
- will look wrong to someone who doesn't know the context (why the PIT is
  uncapped, why verification is a type and not a function), **or**
- was contested — you chose A over a reasonable B and want the reasoning on
  record.

Do *not* write one for routine changes the code and tests already explain.

## Format

Copy an existing ADR. Keep it short — context, decision, consequences, and the
alternatives you rejected with one line each on *why*. Number sequentially;
never renumber. Status is one of `Proposed`, `Accepted`, `Superseded by NNNN`.

## The log

| # | Decision | Status |
|---|---|---|
| [0001](./0001-real-ndn-wire-format.md) | Target the real NDN wire format, not a private dialect | Accepted |
| [0002](./0002-type-enforced-verification.md) | Make data-centric verification compiler-enforced (`SafeData`) | Accepted |
| [0003](./0003-sans-io-seed-crates.md) | Share native + embedded logic through sans-IO seed crates | Accepted |
| [0004](./0004-virtualize-the-clock.md) | Virtualize the clock behind a runtime seam for determinism | Accepted |
| [0005](./0005-retire-audit-witness-suite.md) | Retire the audit-witness scripts in favour of nextest | Accepted |
| [0006](./0006-radio-foundation-boundary.md) | Draw the radio foundation boundary: backends + capability descriptors | Accepted |
| [0007](./0007-named-time-crate-boundary.md) | Named-time crate boundary: no_std core, stamp types, provenance-as-type | Accepted |
| [0008](./0008-naming-conventions.md) | Crate naming and grouping: role directories, the three `-core` senses, recorded debt | Accepted |
