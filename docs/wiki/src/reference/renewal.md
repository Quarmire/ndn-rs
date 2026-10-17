# Certificate renewal (`ndn-fwd renew`)

A device that holds a current certificate from its namespace CA gets a new
one **for the same key** before the old one expires — without a new invite.
Certificates can therefore be short-lived: the CA's policy sets a lifetime
per role, and renewal keeps every renewable device enrolled.

## Concept

- **Proof of possession, not a token.** The device proves it holds the
  private key of a certificate the CA issued. An invite token is spent once;
  the key is what keeps the device enrolled.
- **Same key, same name.** Renewal re-certifies the key the certificate
  certifies; it never certifies a new key. A new key (a lost or rotated
  device key) is a new enrollment: an invite or an admin's device approval.
  The CA names a certificate after its key, so the renewed certificate
  replaces the old one under the same name.
- **Per-role terms.** `[ca] cert_validity_days` sets each role's lifetime;
  `[ca] renewable_roles` says which roles renew. Guests do not by default:
  guest access simply ends at expiry.

## What the CA refuses

| Situation | Why | What to do |
|---|---|---|
| The certificate expired | Renewal needs a *current* certificate: an expired key proves nothing the CA can still vouch for | A new invite (`ndn-fwd enroll`) |
| The key is revoked (at the CA or in the trust context) | A revoked key is never renewed, whichever certificate of it is presented | Enroll a new key with a new invite |
| The role is not in `renewable_roles` (guest by default) | The owner chose that access ends at expiry | A new invite, if the owner wants to extend it |
| The certificate was not issued by this CA, is for another key, or the proof does not verify | Renewal is for the holder of a certificate this CA issued | — |
| The CA's policy renews nothing | It does not offer the `renewal` challenge | — |

## Design

Renewal is an NDNCERT 0.3 exchange — NEW, then one CHALLENGE — whose challenge
is the CA's **built-in** `renewal` challenge (it needs the CA's record of the
certificates it issued and revoked, which a pluggable challenge handler does
not see). The CA offers it when its issuance policy renews
(`IssuancePolicy::offers_renewal`).

1. NEW carries the device's public key (as for an enrollment); the CA answers
   with a fresh, random request id.
2. CHALLENGE (`renewal`) carries `cert_name` and `signature`: the device's
   signature, with the certified key, over
   `"ndncert-renewal\n<request id>\n<cert name>"`. The CHALLENGE body is
   encrypted under the exchange's ECDH session key and the request id is new
   for every NEW, so a proof cannot be replayed into another exchange.
3. The CA checks that the certificate is one it issued for the requested
   key with the same public key, is valid now, that no certificate of that
   key is revoked, and that the signature verifies under the certificate's
   key. Then its issuance policy decides: `RolePolicy` issues for a renewable
   role, at that role's lifetime.
4. The CA answers with the new certificate **inline** in the (encrypted,
   never cached) CHALLENGE response. Because the renewed certificate keeps
   its name, a fetch by name could be answered from a content store with the
   old one.
5. The device checks the new certificate: it certifies the device key, is
   valid now and chains to the root of the namespace's trust context.

## Code

| Piece | Where |
|---|---|
| Protocol, device side: `renew_certificate`, `renewal_proof_message`, `RenewalError` | `ndn-cert/src/renewal.rs` |
| CA side: built-in `renewal` challenge (`CaState::verify_renewal`), inline issued cert | `ndn-cert/src/ca.rs`; `ChallengeResponseTlv::issued_cert` (TLV `0xB2`) in `ndn-cert/src/tlv.rs` |
| Per-role lifetime and renewability: `RolePolicy::with_validity` / `with_renewable`, `RoleTerms` | `ndn-cert/src/policy.rs` |
| Engine binding `renew_via_engine`, schedule `RenewBefore`, `backoff_delay`; `NdncertRenewer` for `start_renewal` | `ndn-identity/src/renewal.rs` |
| Daemon: `security/renew` verb and renewal timer | `ndn-fwd/binaries/ndn-fwd/src/renewal.rs` |
| CA config → `RolePolicy` | `ndn-fwd/binaries/ndn-fwd/src/ca.rs` (`role_policy`) |
| Config: `CertValidityDays`, `renewable_roles`, `RenewBeforeConfig` | `ndn-config/src/config.rs` |
| Mobile: `NdnEngine::renew_certificate`, `certificate_validity` | `ndn-mobile/crates/ndn-boltffi/src/{engine,identity_core}.rs` |

## Usage

On the root device (the CA):

```toml
[ca]
enabled = true
prefix = "/home/bob"
identity = "/home/bob/CA"
renewable_roles = ["admin", "member", "node"]   # the default

[ca.cert_validity_days]
default = 90
guest = 7
```

On a device:

```toml
[security]
renew_before = 0.333     # or "30d"; 0 = only `ndn-fwd renew`
```

The daemon renews every certificate the namespace CA issued to its keys
(`<pib>/keys/*/cert.data`) once `renew_before` of its lifetime is left,
stores the new one in the PIB, serves it by name and keeps signing with the
same key. A failed attempt is retried (about a minute, doubling up to an
hour; an hour after a refusal) and logged as a WARN with `days_left`; an
expired certificate is reported once, as an ERROR.

```sh
ndn-fwd renew -c device.toml      # renew now
ndn-ctl status                    # signing: … key=… valid_until=… days_left=…
```

`ndn-fwd renew` prints each certificate's previous and new expiry, or why it
was refused (and exits non-zero). On a phone, the host app calls
`certificate_validity()` to schedule (`renew_at_secs`) and
`renew_certificate(safebag, password)` to renew; it persists the returned
SafeBag in place of the old one.
