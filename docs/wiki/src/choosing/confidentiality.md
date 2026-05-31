# Confidentiality

Signing answers *who wrote this*. Confidentiality answers *who may read
it*. They are separate decisions, and most NDN data needs only the first —
a public dataset is still fully secure when it is signed and unencrypted.
Reach for encryption only when the content itself must be hidden from
nodes that nonetheless carry or cache it.

| You want | Reach for | What it costs |
|---|---|---|
| Hide content from everyone without a shared key (point-to-point, or a group that already shares one) | **AEAD** symmetric encryption (`ndn-crypto-core`: `seal_in_place` / `open_in_place`, ChaCha20-Poly1305) | You own key distribution; no built-in policy or revocation; anyone with the key reads everything. |
| Let *many* consumers read by *attribute or policy* without per-recipient keys | **ABE** <span class="scope extension">extension</span> (`ndn-abe`: CP-ABE and multi-authority ABE) | Pairing crypto (BN-254) — larger ciphertext, slower; producer-side encryption only today; no in-stack delegation to weak devices. |

## AEAD — the simple floor

When the parties already share a secret (or you have an out-of-band way to
hand one over), AEAD is the cheap, obvious choice. The producer seals the
content; holders of the key open it. NDN's caching still works — caches
carry the ciphertext blindly. The catch is the part NDN does not solve for
you here: getting the key to the right readers, and rotating it. If "share
everything with everyone who has the key" matches your access model, stop
here.

## ABE — one-to-many by policy

When readership is defined by *what someone is* rather than *which key
they hold* — "any cardiologist in the west region" — attribute-based
encryption lets the producer encrypt once under a policy, and any consumer
whose attributes satisfy it decrypts. No per-recipient re-encryption, no
recipient list. The cost is real: BN-254 pairing operations are heavier
than symmetric crypto, ciphertexts are larger, and in ndn-rs this is a
producer-side capability — the `ndn-abe` crate — outside the spec-aligned
core.

<div class="cds-callout">
<span class="cds-callout-title">Known gap</span>
There is no in-stack primitive for a capable device to unwrap a content
key on behalf of a constrained one, and name-based access control (NAC)
is not implemented. If your design needs either, treat it as unbuilt
rather than assuming it is there.
</div>

## How to decide

1. **Does the content need hiding at all?** If authenticity is enough,
   sign and stop — see [Trust, first](../start/trust-first.md).
2. **Is readership a fixed group with a shared secret?** AEAD.
3. **Is readership defined by attributes/policy, one-to-many?** ABE, and
   budget for the pairing-crypto cost and the producer-only constraint.
