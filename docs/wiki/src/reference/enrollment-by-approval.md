# Enrolling by approval (`ndn-fwd approvals`)

Admin devices and relays (`node`) never enroll with a token alone: an admin
approves them. The person's view:

1. On the new device: "add this device" — scan the namespace's anchor QR and
   run `ndn-fwd enroll <anchor link> --role admin`. It shows a six-digit
   code, e.g. `482 913`.
2. On the CA host or on an admin device: `ndn-fwd approvals list` shows the
   request with the same code. The person checks the codes match — "yes,
   that's my device" — and runs `ndn-fwd approvals approve 482913`.
3. The new device receives its certificate by itself, also if it restarted
   in between.

The code is computed on both sides from the CA prefix, the requesting key and
the request id (SHA-256, 6 digits), so a matching code means the request the
admin approves is the one the device made with its key. An approval carries
the code the admin saw; the CA refuses it if it differs from the request's.

## Commands

```sh
# new device
ndn-fwd enroll '<anchor link>' --role admin|node [--device <name>] [--force]
ndn-fwd enroll '<invite link>' --role admin|node   # only when the namespace requires an invite as well
ndn-fwd enroll --status          # outgoing requests: pending, issued, denied, expired, failed

# CA host or admin device
ndn-fwd approvals list
ndn-fwd approvals approve <id|code>
ndn-fwd approvals deny <id|code> [--reason <text>]
```

`enroll` with `--role admin|node` and the namespace's anchor link opens an
approval request. The daemon adopts the context if it does not hold it yet
(checked against the link's expected fingerprint; a context already held
must be signed by that root), reads the policy from the context's
enrollment hint (below), generates the device key, makes one NDNCERT
exchange (`device-approval`) and answers:

```text
state            = pending (waiting for an admin's approval)
identity         = /home/bob/admin/tablet
key              = /home/bob/admin/tablet/KEY/…
ca               = /home/bob
request          = <16 hex>
code             = 482 913
expires          = 20261024T…Z
```

followed by hints for the admin (`ndn-fwd approvals list`, `ndn-fwd
approvals approve <code>`). Asking again while the request is pending
answers the same request; no second key is made. Once issued, the
certificate is installed exactly as after an
[invite enrollment](./enrollment-by-invite.md) (stored, the identity added
to those the node signs as — its other trusted prefixes and its node
identity unchanged, so an approval landing late in one prefix changes
nothing about another — issuer chain kept and served).

`enroll` refuses, saying what to do:

- an anchor link without `--role`: add `--role admin` or `--role node`;
- an anchor link for a role the namespace certifies by invite (member,
  guest): ask an admin for an invite (`ndn-fwd-tokens new --role <role>`);
- an anchor link when the namespace requires an invite *and* an approval:
  run `ndn-fwd enroll <invite link> --role <role>` instead. The invite is
  redeemed once, when the request is opened.

`enroll --status` lists the records in `<pib>/requests/`: identity, state
(`pending`, `issued`, `denied`, `expired`, `failed`), ca, request, code,
key, asked, and expires, certificate or reason.

`approvals list` prints per request: request, code, state, namespace,
device (role and name), key, created, expires and the copyable `approve`
command (pending) or kept_until (decided), decided_by and reason. A code
may be typed `482913`, `482 913` (quoted, or pasted unquoted as listed) or
`482-913`.

`approvals` picks its path per namespace:

- **On the CA host** (this daemon runs that namespace's CA): it decides on
  the CA's own records as the **local operator**, recorded as `the CA
  host's local operator uid N (user)` (from the kernel's peer credentials).
- **On another node** whose PIB holds a current, unrevoked admin
  certificate of a namespace whose CA runs elsewhere: it acts as that
  **admin key** — fetches `<ca>/CA/PENDING`, signs the decision, pushes it
  to `<ca>/CA/APPROVAL`. The CA records `admin key <key>` with the signed
  decision as evidence.
- A node with neither is refused (404) with what to do. `list` shows the
  rows it could fetch and a `# <ns>: unreachable (…); its requests are not
  shown — retry when it is up` line per namespace whose CA did not answer;
  it is refused (504) only when no namespace could be listed. A decision
  whose CA is unreachable is refused (504) naming it. The command waits up
  to 60 s.

A code that matches more than one pending request is refused; use the
request id.

## Across restarts

Both sides keep durable records. The CA keeps each request in
`approvals/` of its directory (`<pib>/ca/<hex of the trusted prefix>/`) until it is decided or expires (default 7 days, `[ca]
approval_request_ttl_days`). The device keeps its outgoing request in
`<pib>/requests/` and waits on it until issued, denied or expired — after a
restart too: its daemon reads `<pib>/requests/` at start.

## Waiting for the decision (held status)

While a request is pending, the device keeps one **status Interest**
outstanding at the CA, `/<ns>/CA/STATUS/<request id>` (lifetime 30 s). The
CA holds it until the request's record changes — an admin decides, or it
expires — and answers at once, or answers `pending` 2 s before the Interest
would expire; the device then sends the next one. So "yes, that's my
device" takes effect on the new device the moment it is recorded, and a
device waiting for days sends one small Interest per 30 s.

- **Approved**: the device runs the issuance exchange at once — a fresh
  NDNCERT NEW + CHALLENGE (`device-approval`, `request=<id>`), which issues
  the certificate — and installs it with no further action. The NEW and
  CHALLENGE answers are not signed by the CA, so nothing they say (a
  denial, an unreadable answer) ends the request, and neither does an
  issued certificate that fails its checks (the device may hold a stale
  trust context: refresh it): the key and the record are kept, the failure
  is logged with what to do, and the device asks again until the
  certificate is kept or a CA-signed status says denied or expired.
- **Denied / expired**: the record says why and what to do (expired: ask
  again), and the generated key is deleted. The device acts on such an
  answer only if it is signed by the CA's key under the namespace schema
  (only the CA key signs `/<ns>/CA/…`) and names its request and key; an
  unsigned or otherwise forged answer changes nothing (logged, asked again).
- **CA unreachable** (no answer, a Nack): the device asks again after a
  pause growing from 1 s to 60 s (logged once per outage). A CA that
  restarts loses the Interests it held; each device sends its next one when
  its Interest expires, so a decision made right after a CA restart reaches
  a device within one status lifetime (30 s).
- **The CA never answers**: a request still pending one day past its
  expiry ends on the device itself as `expired` ("the CA never answered
  before the request expired; ask again"), its key is deleted, and asking
  again sends a new request.
- **Limits**: the CA holds at most 4 status Interests per request and 1024
  in all; one more is Nacked (`Congestion`, logged at the CA with why) and
  the device backs off. The Interest is unsigned and carries no parameters,
  so relays aggregate identical ones; the answer has no FreshnessPeriod and
  the Interest is `MustBeFresh`, so no Content Store answers it with an old
  state.
- **Pending requests**: one key name has at most one pending request (a
  second, for another public key, is refused naming the waiting one: resume
  it, or have an admin deny it, or wait for its expiry); the CA holds at most
  256 pending requests (1024 / 4, the held-status budget), at most 32 under
  one prefix (the parent of the device's identity, e.g. `/<ns>/node`). A
  refused request records nothing: decide the waiting ones
  (`ndn-fwd approvals list`), then ask again.
- **Decisions**: a pushed decision is validated (signature, chain, admin
  role) before the CA looks at the request it names; a refusal never echoes
  the request's code or key.

A decided record stays at the CA one more TTL, so a device that was
offline still learns the outcome.

## Refusals

| Status | Meaning | What to do |
|---|---|---|
| 400 | bad link or parameters (not an anchor link, bad device name, malformed code) | scan the anchor QR again; fix the argument |
| 403 | refused by the trust check (decision or listing does not validate under the context: chain, schema, revoked), or the local user is not an operator; a command over `/localhop` or a non-local face | approve from an admin device holding a valid admin certificate, or as an operator on the CA host |
| 404 | no such pending request, or no CA here and no admin certificate for the namespace | `ndn-fwd approvals list`; ask again on the device if it expired |
| 409 | already decided; code matches several requests; another enrollment is running | read `enroll --status`; use the request id; wait for the running enrollment |
| 504 | CA unreachable | the node needs a link and route for `/<ns>` toward the CA; the device keeps asking |

A denial reaches the device with the admin's reason; `enroll --status` shows
it. Expiry says to ask again.

## Wire

| Packet | Name | Content |
|---|---|---|
| decision push | Interest `/<ns>/CA/APPROVAL`, unsigned | ApplicationParameters: decision Data wire, then the admin's certificate chain (cert first) |
| approval | Data `<requested key>/ndncert-approve/<request id>`, signed by the admin key | the code the admin saw |
| denial | Data `<requested key>/ndncert-deny/<request id>`, signed by the admin key | the reason |
| decision answer | CA-signed Data, JSON `outcome`: `recorded` (record) or `refused` (kind, reason) | |
| pending list | Interest `/<ns>/CA/PENDING`, signed by an admin key (`#pending`) | ApplicationParameters: the admin's certificate chain |
| list answer | CA-signed Data, JSON `listed` (pending, unexpired records) or `refused` | |
| status (device waits) | Interest `/<ns>/CA/STATUS/<request id>`, unsigned, `MustBeFresh`, lifetime 30 s; held by the CA | |
| status answer | CA-signed Data, no FreshnessPeriod, JSON `state`: `pending` (`request_id`, `key_name`, `expires_secs`), `approved`, `denied` (`reason`), `expired` (`reason`; also a request the CA holds no record of) | |
| issuance | NDNCERT `CHALLENGE` `device-approval`, params `request=<id>` (resume) / `token=<invite>` | pending answer carries `request`, `code`, `expires` |

The CA validates a decision under the namespace trust context: signature,
chain (certificates in the push plus the CA's own; each hop verified),
schema, revocation. The requester checks every answer is CA-signed under the
schema (a `DigestSha256` is not a signature: it is refused).

CA record fields: `request_id` (16 hex), `ca_prefix`, `key_name`,
`public_key_sha256`, `role`, `device`, `code`, `created_secs`,
`expires_secs`, `invite`, `state` (`pending`; `approved` with `by`,
`at_secs`; `denied` with `by`, `at_secs`, `reason`). `by` is the local
operator (`uid N (user)`) or the admin key with its signed decision as
evidence. The issued certificate's `device-approval` attestation leaf
carries `request_id`, `code`, `approver_kind` (`local-operator` |
`admin-key`), `approved_by`, `invite`, and for an admin key the signed
decision.

Management (local socket, operator peer credentials only, refused over
`/localhop`): `security/enroll` (answers `state: "pending"`),
`security/enroll-status`, `ca/list-approvals`, `ca/approve`, `ca/deny`.

## Config and policy

```toml
[ca]
approval_roles            = ["admin", "node"]  # issued only on an admin's approval
approval_requires_invite  = false              # also redeem one of this CA's invite tokens
approval_request_ttl_days = 7

[ca.require_attestation]
accept_local_operator = false  # under require_signed, count a local operator's approval
```

`ndn-fwd init` writes this policy into the trust context's enrollment hint
(`approval_roles`, and `require_all` for invite-also) and prints it, e.g.
`enrollment = admin, node by an admin's approval; member, guest by invite`.
The namespace CA enforces what the hint advertises, refuses to start when
`[ca]` says otherwise, and offers `device-approval` whenever approval roles
exist. Tokens admit member and guest only. With invite-also, the request
redeems a token once, when it is opened, and only after the request is
saved: a request the CA could not record leaves the invite unspent. Under
`require_signed`, a local
operator's approval carries no signature and counts only with
`accept_local_operator`.

## Namespaces initialized before this release

A revocation or a recovery kit carries the schema over verbatim, so an older
namespace keeps its old schema, which lacks the `#deny` and `#pending`
rules, and its CA refuses a remote listing or denial (a remote approval
needs the listing too). Its operator adds them on the root device with
`ndn-fwd schema update -c <the daemon's config>`: a new trust-context
version carrying the current generated schema and an enrollment hint that
states the policy the CA enforces (an older hint named no approval roles).
The command prints the rules added (`#deny`, `#pending`) and that nothing
was narrowed; the CA takes remote decisions and listings as soon as its
daemon holds the new version, with no restart, and other nodes get it at
their next refresh. See
[schema updates](./context-updates.md#schema-updates-ndn-fwd-schema-update).

## Anchor QR size

The anchor link with the context inline is about 2.8 KB for `/home/bob`
(2831 bytes measured), and each extra namespace character adds about 30 more.
One QR code holds at most 2331 bytes at the error-correction level every
ndn-rs renderer uses (M), so a QR of the anchor link carries the
fingerprint-only form (`anchor_uri_fp`): `ndn-trust-context build --qr`
switches to it on its own, and `ndn-fwd init` says which line to show. Share
the inline form (`anchor_uri`, `anchor_url`) as a link. See
[trust-envelope.md](../../../specs/trust-envelope.md) §5.6.

## In an app (ndn-mobile)

An app's embedded engine makes the same calls as the daemon, through the
`NdnEngine` FFI (identity feature):

```kotlin
// new device: ask, show the code, wait until it ends
var outcome = engine.requestEnrollment(filesDir, anchorUri, "node", "pixel", password)
// … Pending: show outcome.request.code; persist outcome.adoptedContext if set
// on a background thread / coroutine, at launch and while Pending:
outcome = engine.pollEnrollment(filesDir, requestId, 300u, password)  // returns at the decision
// Issued: persist identity.safebag + identity.issuers; Denied/Expired/Failed: show reason
engine.enrollmentRequests(filesDir)                                    // like `enroll --status`

// admin device (the loaded identity is an admin certificate of the namespace)
engine.listPendingApprovals(adminIssuers)
engine.approveRequest("482913", adminIssuers)
engine.denyRequest("482913", "not my device", adminIssuers)
```

- `request_enrollment(storage_dir, link_uri, role, device, persist_password)`
  takes the anchor link (or, for invite-also, the invite), adopts the
  context or checks the held one against the link's expected fingerprint,
  and refuses a role the context's hint does not put under approval,
  pointing to `enroll_with_invite`. The request is recorded under
  `<storage_dir>/requests/` (`RequestStore`) with the key sealed beside it
  under `persist_password` (password-encrypted PKCS#8); asking again while
  pending returns the same request. A refusal is
  `NdnError::EnrollmentFailed` (carrying a context adopted on the way).
- `poll_enrollment(storage_dir, request, wait_secs, persist_password)`
  resumes the request by id or key name, after a restart too, and waits on
  its held status up to `wait_secs`: it returns the moment the CA answers
  with a decision, else `Pending` when `wait_secs` end (`0`: look once,
  now). One blocking call with a caller-given bound rather than a separate
  wait function: the app decides how long its background work may block
  (its OS's background budget), stops waiting by not calling again (a held
  Interest left at the CA expires on its own within 30 s), and one call
  covers checking and waiting. Outcomes: `Pending` (with `detail` when the
  CA was unreachable), `Issued` (identity loaded, as after
  `enroll_with_invite`; the SafeBag replaces the sealed key and the issuer
  chain is kept under `<storage_dir>/issuers/`, so asking again reports it
  again), `Denied` / `Expired` / `Failed` with the reason (key deleted; a
  denial or expiry only from a CA-signed answer).
- `list_pending_approvals(issuers)`, `approve_request(target, issuers)`,
  `deny_request(target, reason, issuers)` act as the loaded identity; a
  non-admin, expired or revoked identity is refused on the device with why.
  `issuers` are the issuer certificates persisted with the admin identity
  (`NdnEnrolledIdentity::issuers`); the chain sent is built by
  `ndn_cert::approval::admin_chain`. Records are `NdnPendingApproval`, the
  same record `NdnDashboard` lists on a CA host.

## Code

| Part | Where |
|---|---|
| Records, code, store, decisions, held status | `ndn-cert` `approval.rs` (`ApprovalRecord`, `ApprovalStore`, `verification_code`, `poll_approval`, `request_status`, `ApprovalService::{hold_status, answer_status}`, `fetch_pending`, `push_decision`, `RequestStore`) |
| Challenge | `ndn-cert` `challenge/device_approval.rs` |
| Policy | `ndn-cert` `policy.rs` (`ApprovalPolicy`, `RolePolicy::with_approval`) |
| Engine binding | `ndn_identity` `NdncertCa::approvals` (holds each status Interest in its own task), `request_status_via_engine`, `poll_approval_via_engine`, `fetch_pending_via_engine`, `push_decision_via_engine` |
| Daemon | `ndn-fwd` `enroll.rs` (`spawn_status_watch`: one watch task per pending record) |
| Shared requester/approver helpers | `ndn-cert` `approval.rs` (`ca_prefix_of`, `admin_chain`, `RequestStore::outstanding` / sealed keys, `OutgoingState::ended`), `ApprovalPolicy::of_context` — used by the daemon and the app |
| Mobile | `ndn-boltffi` `identity_core/approval.rs`; `NdnEngine::{request_enrollment, poll_enrollment, enrollment_requests, list_pending_approvals, approve_request, deny_request}` |
