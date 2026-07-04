# The Freeze — R14 fixed point

The kernel is baked into every implementation AND published as data written in
itself (D-49). These pins are the bridge: the hashes below were computed by
`ndn-bench freeze --pin` from the live encoder — decode ∘ encode is byte
identity (R13), and every implementation must refuse to run if its baked-in
kernel does not hash-match these values.

| artifact | canonical bytes | SHA-256 |
|---|---|---|
| V₀.2 (32 terms) | 4149 B | `568b95812f3de160d8b43c3acb168ba04ee49fd51276eaa55d74f3f650e24720` |
| IM₀ (implicit-manifest stratum) | 631 B | `39cfe0fb02b0cd6333cef7320e48545ba1c60ada2ddf1daf2c559ab5d2aca85a` |
| T₀ (terminal contract) | 311 B | `a7ac046135c87046cb77c4b8a55ae55fa9ee65301f10223a236f8ccabf8aa3c6` |

## Ceremony (knob #5 · D-18) — NOT YET PERFORMED

The genesis countersigning is a governance act no tool can perform. The slot:

- [ ] editor key signature over the three hashes above: `____________________`
- [ ] witness 1 (plural registry, channel A): `____________________`
- [ ] witness 2 (plural registry, channel B — MUST be channel-orthogonal to A): `____________________`

Until all three lines are filled, the freeze is *pinned* but not *ratified*.
This file states the difference instead of blurring it.
