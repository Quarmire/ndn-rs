# Trust management: structured outcomes and refusal codes

Status: normative for ndn-rs management clients.

## Overview

The trust-admin, approval, invite, issued-certificate, link and root-device
operations of a device in a personal namespace answer with structured data,
never with a host's phrasing. Every refusal carries a stable machine
**code**, the status code it is answered with, whether retrying unchanged can
help, the class of the next step, named **parameters** (names, versions,
times, paths) and a neutral default sentence. Prose inside a successful
outcome (why a refresh failed, what changes at the next start, a note on an
approval listing) is a **detail**: a code, parameters and a neutral default
sentence.

A client (CLI, TUI, mobile app) words its own message from the code and
parameters — naming its own commands, buttons or screens — and falls back to
the neutral sentence for a code it does not know. Daemon answers never name a
host's commands (`ndn-fwd …`), command-line flags or configuration keys; a
parameter carries only facts (a path is a fact, a command is not).

The Rust catalogue is `ndn_cert::report::code` (re-exported by
`ndn-namespace` and `ndn-mgmt`); the refusal type is
`ndn_cert::report::TrustRefusal`, the detail type `ndn_cert::report::Detail`.

## Wire form

A management verb that refuses answers a ControlResponse whose status code is
the refusal's `status_code` and whose status text is the refusal as JSON:

```json
{
  "code": "context-not-held",
  "status_code": 404,
  "retry": false,
  "next": "adopt",
  "params": { "namespace": "/alice" },
  "reason": "no trust context is held for /alice; adopt the namespace first"
}
```

| Field | Type | Meaning |
|---|---|---|
| `code` | string, kebab-case | stable machine id (the tables below) |
| `status_code` | integer | `400` bad link or parameters, `403` refused by a trust check, the CA or the management gate, `404` nothing of that kind here, `409` conflicting state or another such command running, `500` local failure, `504` the network did not deliver |
| `retry` | bool | the same request, unchanged, can succeed later |
| `next` | string | the [next-step class](#next-step-classes) |
| `params` | object string→string | named facts; absent = empty |
| `reason` | string | neutral default sentence |

A client recognises a refusal by a status code ≥ 400 whose status text parses
as this object (`ndn_ipc::trust_refusal(&ControlResponse)`); any other
non-2xx text is an untyped error. A success stays JSON of the outcome (or a
TLV dataset).

A detail is the JSON object `{ "code": …, "params": { … }, "text": … }`
(`params` may be absent = empty).

## Next-step classes

| `next` | The person at the device can… |
|---|---|
| `none` | nothing: what was asked holds already, or the outcome is final |
| `retry-later` | ask again later, unchanged (busy, unreachable, slow) |
| `fix-request` | correct what was given (a link, a name, a parameter) and ask again |
| `get-invite` | get a (new) invite from an admin of the namespace |
| `adopt` | adopt the namespace on this device first (its anchor link) |
| `enroll` | enroll this device (first, or again) |
| `ask-admin` | have an admin approve or deny on an admin or root device |
| `refresh` | check the namespace's trust context for a newer version |
| `use-other-device` | do it on another device (the root device, an admin device) |
| `fix-local` | fix this device's own setup (key storage, configuration, permissions) |
| `provide-secret` | give the right secret (passphrase, PIN, recovery words) |
| `wait` | wait for what is under way (a pending approval, a busy device) |
| `other` | a step this client does not know (a newer peer): show `reason` |

A client that reads an unknown `next` value treats it as `other`.

## Trust-admin verbs

The verbs that change what a device trusts or holds, under
`/localhost/nfd/security/`. Every one is a trust change: management accepts
it only on the local management socket from a local operator (the daemon's
user, root, or a member of a configured trust-admin group, by the kernel's
peer credentials), never over `/localhop` (the **gate**, refusals below).
Each is the `ndn-namespace` operation of the same name over the host's
participant and key vault; a host without one (no trust-admin backend)
refuses with `not-at-runtime`.

| verb | ControlParameters | answer (JSON in the status text) |
|---|---|---|
| `context-adopt` | Uri: an `ndn-trust://anchor` link | `AdoptedContextInfo` |
| `enroll` | Uri: an `ndn-trust://invite` link, or an anchor link for a role certified on an admin's approval; Name: `/<ns>/<role>/<device>`; Flags `ENROLL_FORCE`: although already certified | `EnrollOutcome`, tagged `state`: `enrolled` (`EnrolledInfo`) or `pending` (`PendingEnrollInfo`) |
| `enroll-status` | — | list of `ndn_cert::OutgoingRequest` (its `state`; an ended one's `reason` is a detail) |
| `context-refresh` | Name: a namespace (absent: every held one) | list of `ContextRefreshInfo` (`detail` is a detail) |
| `context-update` | ContextData: a signed trust-context Data made on this device | one `ContextRefreshInfo` |
| `renew` | — | list of `RenewalInfo` (`detail` of a refused or failed one is a detail) |
| `memberships` | — | list of `MembershipInfo` (read only: any local client) |
| `identity-status` | — | `IdentityStatus` (read only: any client, unsigned) |

`identity-status` reports the node identity and why, every signing identity
and every root store:

```json
{
  "identity": "/home/bob/node/pi",
  "is_ephemeral": false,
  "pib_path": "/var/lib/ndn/pib",
  "key": "/home/bob/node/pi/KEY/%01",
  "valid_until": "20270101T000000Z",
  "days_left": 74.5,
  "node_identity_source": "pib-default",
  "signing_identities": [ { "identity": "/home/bob/node/pi", "key": "/home/bob/node/pi/KEY/%01" } ],
  "root_stores": [ { "namespace": "/home/bob", "kind": "os-keyring", "key": "/home/bob/KEY/root" } ]
}
```

`identity` is `null` when the node has none; `key`, `valid_until`,
`days_left` and `node_identity_source` (`configured`, `pib-default`,
`root-device`, `first-enrolled`, `ephemeral`) are `null` when the host does
not track its identities; `days_left` is negative once the certificate
expired.

**Wording.** A refusal's `reason` and a detail's `text` are neutral. The
library's sentences that quote what the person does next (adopt, enroll,
renew, decide approvals, fix the key storage) are rebuilt in a client's own
terms from the code and params by `ndn_namespace::HostWords::render` /
`render_detail`, with the client's phrases (`ndn-fwd`: its commands and
configuration keys; the app: its calls); the neutral sentence is the same
rendering with `HostWords::default()`. A refusal wrapping another names it
in `cause` and carries its params too.

### Gate and parameters

| code | status | retry | next | params | meaning |
|---|---|---|---|---|---|
| `not-at-runtime` | 404 | no | use-other-device | `operation` (`context-adopt`, `enroll`, `enroll-status`, `context-refresh`, `context-update`, `renew`, `memberships`, `approvals`, `ca-info`, `yubikey`) | this node does not do it at runtime (no backend) |
| `missing-parameter` | 400 | no | fix-request | `operation`, `parameter` (`Uri`, `Name`, `ContextData`), `expects` | a required parameter is missing |
| `trust-change-over-localhop` | 403 | no | use-other-device | `operation` (`<module>/<verb>`) | a trust change arrived over `/localhop`; trust changes are made on the node itself |
| `trust-change-unidentified` | 403 | no | fix-local | `daemon_uid`, `groups` (`, `-separated trust-admin groups; empty: none) | the face carries no caller identity (not the local management socket) |
| `trust-change-not-operator` | 403 | no | fix-local | `uid`, `daemon_uid`, `groups` | the caller is a local user who is no operator of this node |

Every other signed management command goes through the command gate: on the
local socket a local operator's unsigned command passes on its peer
credentials, anything else is decided by its signature against the node's
command trust anchors.

| code | status | retry | next | params | meaning |
|---|---|---|---|---|---|
| `command-not-operator` | 403 | no | fix-local | `uid`, `daemon_uid`, `groups`, `anchor_configured` (`true`/`false`) | an unsigned command from a local user who is no operator, where signed commands are required |
| `command-signer-unverifiable` | 403 | no | fix-request | — | a local operator's command is signed by a key, but no command trust anchor is configured to verify it: send it unsigned |
| `command-no-anchor` | 403 | no | fix-local | — | the command must be signed by a key a command trust anchor vouches for, and none is configured |
| `command-unsigned` | 403 | no | fix-request | — | no key-backed signature (unsigned or DigestSha256) where one is required |
| `command-signature-refused` | 403 | no | fix-request | `error` | the signature is invalid, or its signature time is missing, stale or replayed |
| `command-signer-pending` | 403 | yes | retry-later | — | the signing certificate is not resolved yet |
| `validation-disabled` | 404 | no | fix-local | — | `security/schema-*`: validation is disabled on this node, so it manages no trust schema |

`not-at-runtime` also answers `security/ca-info` on a node that runs no CA
(`operation` = `ca-info`) and `security/yubikey-*` in a build without
YubiKey PIV support (`operation` = `yubikey`).

### Adopt, refresh, update

| code | status | retry | next | params | meaning |
|---|---|---|---|---|---|
| `context-not-held` | 404 | no | adopt | `namespace` | no trust context of the namespace is held |
| `link-invalid` | 400 | no | fix-request | `error` | the anchor link is unreadable or incomplete |
| `context-unreachable` | 504 | yes | retry-later | `error`, `namespace`? | the trust context could not be fetched |
| `trust-change-in-progress` | 409 | yes | wait | `error` | another adoption or update of the namespace runs |
| `context-refused` | 403 | no | fix-request | `error`, `namespace`? | the context failed its checks (fingerprint, signature, version) |
| `different-root` | 403 | no | fix-request | `namespace`, `held`, `expected` (hex fingerprints) | the held context is signed by another root than the link expects; the held one stays |
| `context-superseded` | 409 | no | none | `namespace`, `version`, `now` | a newer version (`now`) was adopted meanwhile and is kept |
| `context-not-stored` | 500 | no | fix-local | `namespace`, `version`, `error`, `location` | the version holds for this run, storing it failed |
| `update-invalid` | 400 | no | fix-request | `error` | the update is not a trust-context Data |
| `update-refused` | 403 | no | fix-request | `namespace`, `held_version`, `error` | the update does not follow the held version |
| `context-changed-meanwhile` | 409 | no | fix-request | `namespace`, `now` | the held version changed while the update was checked |

### Enroll and enroll-status

| code | status | retry | next | params | meaning |
|---|---|---|---|---|---|
| `not-an-enroll-link` | 400 | no | fix-request | `error` | neither an invite nor an anchor link |
| `enroll-busy` | 409 | yes | wait | `namespace` | another enrollment in the namespace runs |
| `identity-invalid` | 400 | no | fix-request | `identity`, `namespace` | not `/<namespace>/<role>/<device>` in the link's namespace |
| `identity-outside-invite` | 400 | no | fix-request | `identity`, `prefix` (or `error`) | not `<device>` under the invite's identity namespace |
| `invite-for-another-role` | 400 | no | get-invite | `namespace`, `invite_role`, `role` | the invite admits another role, certified by invite |
| `role-by-invite` | 400 | no | get-invite | `namespace`, `role`, `policy` | an anchor link for a role certified by invite |
| `role-needs-invite-and-approval` | 400 | no | get-invite | `namespace`, `role` | an anchor link for a role certified only on an invite and an approval |
| `already-certified` | 409 | no | fix-request | `namespace`, `still_valid` (`, `-separated `<key> (valid until <ISO 8601>)`); when the newest version could not be confirmed `judged_version`, `judged_detail`, `cause` (the check's detail code) and its params | the device holds a valid certificate in the namespace (force to enroll another key) |
| `keys-unreadable` | 500 | no | fix-local | `error` | the key storage (or its admin keys) could not be read |
| `requests-unreadable` | 500 | no | fix-local | `error` | the request records could not be read or updated |
| `key-not-generated` | 500 | no | fix-local | `error`, `location`? | the device key could not be named (RNG) or generated |
| `invite-invalid` | 400 | no | get-invite | `error`, `namespace`? | the invite is unusable as given |
| `invite-refused` | 403 | no | get-invite | `error`, `adopted_namespace`?, `adopted_version`? | the CA refused the invite (spent, expired, unknown); a context adopted on the way stays adopted |
| `device-name-invalid` | 400 | no | fix-request | `error` | the device name is malformed |
| `device-name-taken` | 409 | no | fix-request | `error` | the CA certified that device name already |
| `ca-unreachable` | 504 | yes | retry-later | `error`, `adopted_*`? | the CA could not be reached, or its answer was not trusted |
| `ca-refused` | 403 | no | fix-request | `error`, `adopted_*`? | the CA refused the request |
| `request-expired` | 410 | no | enroll | `error` | the request expired at the CA |
| `request-denied` | 403 | no | enroll | `error` | an admin denied the request |
| `issued-certificate-refused` | 403 | no | refresh | `error` | the issued certificate failed its checks |
| `signing-failed` | 500 | no | fix-local | `error`, `ca`? | a device or admin key could not sign |
| `request-not-recorded` | 500 | no | fix-local | `request`, `code`, `error`, `location` | the CA holds the request, the device could not record it (its key was deleted) |
| `certificate-not-kept` | 500 | no | fix-local | `certificate`, `location`, `error`, `spent` (`invite`, `approval`) | the issued certificate could not be kept; nothing changed |

### Renew

| code | status | retry | next | params | meaning |
|---|---|---|---|---|---|
| `renewal-keys-unreadable` | 500 | no | fix-local | `error` | the certificates to renew could not be read |
| `nothing-to-renew` | 404 | no | enroll | `location` | no certificate a namespace CA issued is held |

### Details

| code | where | params | meaning |
|---|---|---|---|
| `refresh-source` | `ContextRefreshInfo.detail` | — | this device holds the root key: versions are made here |
| `refresh-current` | 〃 | `version` | the namespace serves the version held |
| `refresh-upstream-older` | 〃 | `offered`, `held`, `freshness_secs` | what answered is older than held |
| `refresh-behind` | 〃 | `answered`, `verified`, `by`, `freshness_secs` | what answered is older than a version known to exist |
| `refresh-unreachable` | 〃 | `error` | nothing answered for the newest version |
| `refresh-failed` | 〃 | `error` | the check failed or the update was refused |
| `context-updated` | 〃 | `version`, `signer`, `from`, `walked`?, `published`, `stored` or `cause` and its params, `ca_revoked`?, `ca_not_persisted`? | a newer version was adopted |
| `update-adopted` | 〃 (context-update) | `version`, `signer`, `held`, then as `context-updated` | a version made on this device was adopted |
| `update-already-taken` | 〃 (context-update) | `version`, `held`, `stored` | the version was taken before |
| `context-check-timed-out` | 〃 (`EnrolledInfo.context_check`) | `budget_secs`, `namespace` | enrollment's check of the context ran out of time |
| `renewal-revoked` | `RenewalInfo.detail` | `key` | the held context revokes the key |
| `renewal-key-unavailable` | 〃 | `key`, `error` | the key cannot sign |
| `renewal-refused` | 〃 | `error` | the CA refused for good |
| `renewal-failed` | 〃 | `error` | the attempt failed; it can be retried |
| `renewal-not-stored` | 〃 | `certificate`, `location`, `error` | the new certificate could not be stored |
| `next-start-unsigned` | `EnrolledInfo.at_next_start` | `identity` | the device started unsigned: it signs as the identity after a restart |
| `next-start-configured-identity` | 〃 | `configured`, `identity` | the configuration names the node identity; the new one is recorded as default |
| `next-start-routing-key` | 〃 | `key` | routing keeps the startup key until a restart; neighbours must trust `key` |
| `next-start-not-activated` | 〃 | `identity`, `error` | kept, but not taken into use now |
| `request-unanswered` | `OutgoingState` reason | `request`, `expired` | the CA never answered before the request expired |
| `request-ended` | 〃 | `error`, `key`?, `deleted`, `delete_error`?, `location`?, `cause`? and its params | the CA's signed answer (denied, expired) or a final failure ended it |
| `request-names-no-ca` | 〃 | — | the record names no valid namespace or CA |
| `request-names-no-key` | 〃 | — | the record names no valid namespace, CA, identity or key |
| `request-key-gone` | 〃 | `key`, `why` | the request's key is gone |

## Approvals

`/localhost/nfd/ca/{list-approvals,approve,deny}`: requests for an admin's
approval. On a CA host they are its CAs' records, decided by the local
operator the kernel attests (`uid 1000 (alice)`, recorded as the approver);
on an admin device also the pending requests of each namespace whose CA runs
elsewhere, listed and decided with its admin key. Trust changes: the gate
above applies.

| verb | ControlParameters | answer |
|---|---|---|
| `list-approvals` | — | TLV dataset `ndn_mgmt_wire::ApprovalListing`: the rows, and a note per namespace whose requests could not be listed |
| `approve` | Uri: the request id or the six-digit code | `ApprovalDecision` as JSON |
| `deny` | Uri: `<id or code>[:<reason>]` | `ApprovalDecision` as JSON |

`ApprovalDecision` is the request as decided: `request_id`, `key_name`,
`namespace` (the CA), `role`, `device`, `code`, `state` (`approved`,
`denied`), `approver`, `reason` (a denial's), `expires_secs` (until when the
CA keeps the record).

A listing note is a nested TLV `NOTE` (0xE6) beside the rows, with
`NOTE_CODE` (0xE8), one `NOTE_PARAM` (0xEA: `PARAM_NAME` 0xEC,
`PARAM_VALUE` 0xEE) per param, and `NOTE_TEXT` (0xF0, the neutral sentence).
The free-text note 0xE4 is retired; a decoder skips unknown TLVs.

| note code | params | meaning |
|---|---|---|
| `approvals-ca-unreachable` | `namespace`, `error` | the namespace's CA could not be asked; retry when it is up |
| `approvals-not-listed` | `namespace`, `error`, `cause` (the refusal code) and its params | the namespace's CA refused the listing |

A CA's own refusal of a decision or a listing (`ApprovalRefusal`, on the CA
host or sent back to an admin device) carries an approval code and params;
one from a CA that names no code (or one this build does not know) is the
generic code of its kind.

| code | status | retry | next | params | meaning |
|---|---|---|---|---|---|
| `nothing-to-approve` | 404 | no | use-other-device | — | this device runs no CA taking approval requests and holds no current admin certificate of another namespace |
| `approval-target-missing` | 400 | no | fix-request | — | approve / deny names no request |
| `approval-not-found` | 404 | no | fix-request | `target`? | no such request (generic) |
| `approval-unknown-target` | 404 | no | fix-request | `target` | neither a request id nor a six-digit code |
| `approval-no-code-match` | 404 | no | fix-request | `code` | no pending request shows the code |
| `approval-not-pending` | 404 | no | fix-request | `target`, `scope` (`local-and-administered`, `administered`), `unasked`? (`; `-separated) | no pending request shows it at the CAs asked; with `unasked` the status is the first unasked CA's |
| `approval-ambiguous` | 409 | no | fix-request | `code`, or `target` and `matches` (`, `-separated `<id> (<CA>)`) | several pending requests show it: decide by request id |
| `approval-conflict` | 409 | no | none | — | a conflicting decision (generic) |
| `approval-decided` | 409 | no | none | `request`, `state` | decided already; a decision is final |
| `approval-expired` | 409 | no | none | `request`, `expired` | expired undecided; the device must ask again |
| `approval-unauthorized` | 403 | no | use-other-device | `error` | the signer may not decide or list |
| `approval-bad-decision` | 400 | no | fix-request | `error` | the decision is malformed or names another request or key |
| `approval-not-recorded` | 500 | yes | retry-later | `error` | the CA could not record the decision; nothing changed |
| `approval-refused-by-ca` | the CA's | the CA's | the CA's | `ca`, `cause` (the CA's code) and its params, `error` (the CA's sentence) | the namespace's CA refused this admin device's listing or decision |
| `approval-ca-unreachable` | 504 | yes | retry-later | `ca`, `error` | the namespace's CA could not be asked |
| `approval-ca-bad-answer` | 502 | yes | retry-later | `ca`, `error` | the CA's answer was unreadable or untrusted |
| `approvals-unlisted` | first failure's | yes | retry-later | `notes` (`; `-separated note texts) | nothing at all could be listed |
| `signing-failed` | 500 | no | fix-local | `ca`, `error` | the admin key could not sign |
| `keys-unreadable` | 500 | no | fix-local | `error` | the admin keys could not be read |
| `not-at-runtime` | 404 | no | use-other-device | `operation` = `approvals` | the host has no approval backend |

## Links

The links module (`/localhost/nfd/links/*`, local operators only) lists this
device's QUIC links (`links/list`, the TLV dataset of
[ndn-link.md §14.10](ndn-link.md#1410-status-and-link-commands)) and runs
the link commands `links/connect`, `links/disconnect` and `links/mode` on a
configured link named by its label (ControlParameters Uri; the mode in
LocalUri). A command answers a detail as JSON in the status text; it refuses
with a refusal (the wire form above). `links/list` refuses the same way, as
a ControlResponse in place of the dataset.

Whatever the link library reports or refuses in words is a **link detail**
(`ndn_mgmt_wire::LinkDetail`, catalogue `ndn_mgmt_wire::link_code`): a code,
params, a neutral sentence and `causes`, the details its sentence quotes —
each cause's sentence appears verbatim in its parent's, in order, so a client
renders the causes it words in place (`LinkDetail::render`). In the dataset a
detail is a nested TLV (code 0x04E0, params 0x04E2, text 0x04E8, causes
0x04EA); the same sentence is the reason phrase of a link this device closes
and the text of a punch it refuses, so the other device reads it too. Six
codes stand in for a host's configuration and commands (a peer entry,
renewing a certificate, having the other device expect a key):
`direct-off-peer-entry`, `direct-refused-peer-entry`,
`expected-device-unconfirmed`, `unrecognized-key`,
`not-served-no-certificate` and `certificate-expired`; a client says them in
its own terms with `ndn_mgmt_wire::LinkWords` (ndn-ctl: `[[peer]]`,
`ndn-fwd renew`, `add [[peer]] key = "…"`; the app: its relay screen and
renewal). Details have no status, retry or next step (`—` below); what to do,
if anything, is in their meaning.

Params are strings. Names are NDN URIs, keys are hex SHA-256 fingerprints,
`reason` is a close code as `0xNN` (ndn-link.md §6.1), `version` a trust
context version, `error` the underlying error's text; a param shown `?` is
set only when it applies.

### Command refusals

| code | status | retry | next | params | meaning |
|---|---|---|---|---|---|
| `links-unknown-verb` | 404 | no | fix-request | `verb` | the links module has no such verb (it answers `list`, `connect`, `disconnect`, `mode`) |
| `links-not-running` | 404 | no | fix-local | — | this node runs no QUIC links: it has no key (security is disabled) |
| `link-label-missing` | 400 | no | fix-request | — | the command names no link (Uri empty) |
| `link-mode-invalid` | 400 | no | fix-request | `mode` (as given) | not `always`, `on-demand`, `on-demand:<idle seconds>` or `off` |
| `link-not-found` | 404 | no | fix-request | `label` | no link has this label (`links/list` shows the labels) |
| `link-not-configured` | 400 | no | fix-local | `label` | the device linked in and is not configured: it has no mode and is not dialled; configuring it as a device or relay to link with makes it controllable |
| `link-mode-missing` | 400 | no | fix-request | — | `links/mode` names no mode (LocalUri empty) |
| `link-idle-out-of-range` | 400 | no | fix-request | `idle_secs`, `min`, `max` | the idle close is outside `min..=max` seconds (10..=86400): shorter closes a link between the packets of one exchange |

### Command answers

| code | status | retry | next | params | meaning |
|---|---|---|---|---|---|
| `linking` | — | — | — | `label` | `links/connect`: the link is wanted now, whatever its mode, and dialled at once, until disconnected |
| `link-released` | — | — | — | `label` | `links/disconnect`: the link is no longer asked for; an `off` link closes now, an `on-demand` one once idle, an `always` link stays up (set its mode to off to close it) |
| `link-mode-set` | — | — | — | `label`, `mode` (`always`, `on-demand`, `off`), `idle_secs`? (on-demand) | `links/mode`: the link runs in this mode until the daemon restarts |

### Direct-path state (`direct` of a link)

| code | status | retry | next | params | meaning |
|---|---|---|---|---|---|
| `direct-up` | — | — | — | `remote` | a direct path to `remote` is up |
| `direct-ended` | — | — | — | `remote`, `relay`; cause | the direct path ended (cause: why); traffic goes through the relay until the next punch |
| `direct-ended-peer-punches` | — | — | — | `remote`, `peer`; cause | the direct path ended; the other device punches again |
| `direct-linked` | — | — | — | — | linked over a configured endpoint: no punch needed |
| `direct-waiting-for-relay` | — | — | — | `relay` | waiting for the link to the relay the punch goes through |
| `direct-off-peer-entry` | — | — | — | `peer` | this device's peer entry for `peer` turns direct paths off (host term) |
| `direct-off-policy` | — | — | — | `namespace`, `version` | the namespace's link policy turns direct paths off |
| `direct-off-roles` | — | — | — | `namespace`, `version`, `role`, `peer_role` | the namespace's role matrix pairs no direct path between these roles; traffic goes through the relay |
| `direct-full` | — | — | — | `up`, `max` | this device has `max` direct paths up already; traffic goes through the relay |
| `direct-members-first` | — | — | — | — | other members whose direct paths carried traffic more recently get the free direct paths first |
| `direct-punching` | — | — | — | `relay` | punching through the relay |
| `direct-peer-punching` | — | — | — | `peer` | the other device punches a direct path |
| `direct-peer-punches-again` | — | — | — | `peer`; cause | the last punch failed (cause); the other device punches again |
| `direct-repunching` | — | — | — | — | this device's network changed: punching again from its new address |

### Why a punch made no direct path (causes, or the `direct` detail)

| code | status | retry | next | params | meaning |
|---|---|---|---|---|---|
| `punch-relay-down` | — | — | — | — | the relay's link is down |
| `punch-no-socket` | — | — | — | `error` | no link socket to punch from |
| `punch-no-key` | — | — | — | `error` | this device has no usable link key |
| `punch-answer-not-validated` | — | — | — | `device`, `nack` | this device's forwarder cannot validate the other device's answer: it holds no trust context of its namespace or lacks its certificates |
| `punch-unrouted` | — | — | — | `device`, `nack` | nothing routes the punch request to the device now |
| `punch-unanswered` | — | — | — | `device`, `error` | the punch request got no answer (is the device running and linked to the relay?) |
| `punch-refused-by-peer` | — | — | — | `peer`, `reason`, `text` | the other device refused the direct path; `text` is its sentence (not reworded) |
| `punch-answer-unusable` | — | — | — | `peer`; cause (`answer-*`) | the other device's punch answer is not usable |
| `punch-socket-unbound` | — | — | — | `error` | the link socket has no address |
| `punch-unreachable` | — | — | — | `peer`, `socket` | the other device offered no address this device's link socket can reach |
| `punch-busy` | — | — | — | `max` | this device runs `max` punches at once already |
| `punch-ended` | — | — | — | — | the punch ended |
| `punch-no-probe` | — | — | — | `peer`, `secs`, `probed` | no probe arrived and no handshake completed: both networks drop unsolicited UDP or map each destination to another port |
| `punch-no-handshake` | — | — | — | `peer`, `heard`, `secs`, `probed` | probes arrived, but no QUIC handshake completed: the way back stays closed |
| `punch-nothing-to-dial` | — | — | — | `peer` | the other device offered no address this device dials |
| `punch-dials-failed` | — | — | — | `peer`; causes (`punch-dial-failed`) | every dial of the punch failed |
| `punch-dial-failed` | — | — | — | `address`; cause | one dial failed (cause: why) |
| `answer-empty` | — | — | — | — | the answer carries no content |
| `answer-malformed` | — | — | — | `error` | the answer does not decode |
| `answer-bad-key` | — | — | — | `error` | the key it names is not a link key |
| `answer-bad-signature` | — | — | — | `error` | its signature does not verify under the key it names |
| `answer-wrong-key` | — | — | — | `key`, `expected` | it is signed by another key than the one its relay listed |
| `answer-unconfirmed` | — | — | — | `peer` | this device holds no certificate in the other device's namespace yet and cannot confirm it |
| `answer-wrong-device` | — | — | — | `device`, `presented` | its certificate is not of the device punched |

### Why this device refused a punch (sent to the punching device)

| code | status | retry | next | params | meaning |
|---|---|---|---|---|---|
| `punch-clock` | — | — | — | `signed_at_ms`, `grace_secs`, `now_ms` | the request's signature time is too far from this device's clock: a replay, or a clock is off |
| `punch-replay` | — | — | — | — | the request repeats an earlier one (same nonce and time) |
| `punch-rate` | — | — | — | `burst`, `refill_secs` | too many punch requests from one key; punch again later |
| `punch-enrollment-only` | — | — | — | `device` | the punching device would be admitted on an enrollment link only, which no direct path carries: it enrolls first |
| `punch-sessions-full` | — | — | — | `max` | this device runs `max` punches at once already; punch again later |
| `punch-no-candidate` | — | — | — | — | the request offers no address |
| `punch-no-socket-for` | — | — | — | `address`, `error` | this device has no link socket for the address offered |

A punch refused for an admission reason carries that refusal's detail
(next section), or `direct-refused-peer-entry`, `direct-off-policy`,
`direct-off-roles`, `direct-full`.

### Why a link did not come up, or ended (`down` of a link, and its causes)

| code | status | retry | next | params | meaning |
|---|---|---|---|---|---|
| `down-links-in` | — | — | — | — | the device links in to this one (no endpoint to dial) |
| `down-standby-relay` | — | — | — | — | a standby relay, not needed now |
| `down-off` | — | — | — | — | its mode is off: it links when asked |
| `down-on-demand` | — | — | — | `idle_secs` | on demand and closed: it links on traffic or when the host is active |
| `down-dialling` | — | — | — | — | dialling |
| `dial-failed` | — | — | — | `retry_secs`; cause (`link-*`) | the last dial failed; dialled again after `retry_secs` |
| `peer-shutting-down` | — | — | — | — | the other device closed the link: it is shutting down |
| `link-no-key` | — | — | — | `error` | this device has no usable link key |
| `link-tls` | — | — | — | `error` | the TLS handshake failed |
| `link-connect` | — | — | — | `error` | the connection could not be made |
| `link-unexpected-key` | — | — | — | `expected`, `presented` | the other device presented another key than the one expected |
| `link-closed-by-peer` | — | — | — | `text`, `reason`? | the other device closed or refused the link; `text` is its sentence (not reworded) |
| `link-closed-here` | — | — | — | `reason`; cause (the refusal) or `text` | this device closed or refused the link |
| `link-protocol` | — | — | — | `error` | the other device broke the link protocol |
| `link-timeout` | — | — | — | — | the exchange timed out |
| `link-io` | — | — | — | `error` | an I/O error |

### Why this device refused a link (cause of `link-closed-here`; the close sentence)

| code | status | retry | next | params | meaning |
|---|---|---|---|---|---|
| `certificate-undecodable` | — | — | — | `error` | the certificate in the hello does not decode |
| `certificate-for-another-key` | — | — | — | `certificate`, `key` | the certificate is for another key than the handshake proved |
| `membership-undecodable` | — | — | — | `error` | a membership certificate in the hello does not decode |
| `membership-not-bound` | — | — | — | `certificate`, `error` | a membership is not shown by its certificate's key for this link (forged or replayed) |
| `binding-unavailable` | — | — | — | `error` | this device cannot bind its memberships to the link |
| `issuer-undecodable` | — | — | — | `error` | an issuer certificate in the hello does not decode |
| `key-revoked` | — | — | — | `key`, `namespace`, `version` | the key is revoked in the namespace |
| `issuer-revoked` | — | — | — | `issuer`, `namespace`, `version` | the certificate's issuer is revoked in the namespace |
| `root-collides` | — | — | — | `certificate`, `root`, `namespace` | the certificate chains to another root under a namespace this relay holds: the names collide |
| `not-expected-key` | — | — | — | `peer`, `expected`, `key` | this device expects another key for that peer |
| `not-expected-device` | — | — | — | `expected`, `devices` | this device expects another device here (`devices`: the ones proved, comma-separated) |
| `expected-device-unconfirmed` | — | — | — | `device`; cause (why not) | this device expects `device` and cannot confirm the peer is it; it links once it holds the device's namespace, or once its peer entry names the key (host term) |
| `role-may-not-link` | — | — | — | `namespace`, `version`, `role` | the namespace's link policy does not let this role link |
| `role-may-not-relay` | — | — | — | `namespace`, `version`, `role` | this device reaches others through the peer, and the policy does not let its role relay |
| `not-served-no-certificate` | — | — | — | `policy` (`listed`, `open`), `key`; cause `no-enrollment-link`? | a listed or open relay routes device names from certificates, and the hello carries none: enroll, or have the other device expect the key (host term) |
| `unrecognized-key` | — | — | — | `key`, `held`? (comma-separated); causes: why, `no-enrollment-link`? | the key is neither of a held namespace nor expected: enroll, or have the other device expect the key (host term) |
| `namespace-collides` | — | — | — | `namespace`, `bound_root`, `root` | the relay serves that namespace name for another root now |
| `quota-namespace-links` | — | — | — | `max`, `namespace`, `links` | the namespace's links at this relay are at its quota |
| `quota-links` | — | — | — | `max`, `links` | this relay's links of other namespaces are at its quota |
| `not-served-uncertified` | — | — | — | `device`, `namespace`, `own`?, `listed`?, `roots`? | the relay holds the namespace's trust context but no certificate in it, and does not serve it |
| `not-served-unlisted` | — | — | — | `listed`, `device`, `namespace`, `root`, `own`? | the namespace's root is not listed by this relay |
| `not-served-own` | — | — | — | `device`, `namespace`, `root`, `own`? | this relay serves its own namespaces only |
| `enrollment-links-full` | — | — | — | `links`, `from_source`, `max`, `max_per_source` | the relay's enrollment links are full; the device dials again by itself |
| `enrollment-possible` | — | — | — | `namespaces` | (appended to a not-served refusal) a device enrolls in these namespaces over this relay while its hello holds no certificate of another namespace |
| `path-not-taken` | — | — | — | `session` | the other device did not take the dialled direct path as one |
| `path-no-punch` | — | — | — | `session` | this device runs no such punch with the key (it ended) |
| `path-enrollment-only` | — | — | — | — | a direct path carries a full link only, and this device admits the peer on an enrollment link only |
| `direct-refused-peer-entry` | — | — | — | `peer` | this device's peer entry for `peer` turns direct paths off (host term) |
| `path-taken` | — | — | — | `session` | another path of the punch came up first |
| `link-exists` | — | — | — | — | a link between these two devices exists already |

### Why a certificate identifies nobody here (causes)

| code | status | retry | next | params | meaning |
|---|---|---|---|---|---|
| `no-certificate` | — | — | — | — | the hello carries no certificate |
| `not-device-certificate` | — | — | — | `certificate`, `namespace` | not a device certificate of the namespace |
| `certificate-expired` | — | — | — | `certificate` | outside its validity period: the device renews it (host term) |
| `certificate-unauthenticated` | — | — | — | `certificate`, `namespace` | not signed by a key of the namespace |
| `certificate-invalid` | — | — | — | `certificate`, `namespace`, `version`, `error` | does not validate in the held trust context |
| `certificate-chain-unknown` | — | — | — | `certificate` | its issuer chain was not sent and is not known here |
| `foreign-no-root` | — | — | — | `certificate` | of a namespace not held, and the hello carries no root to check it against |
| `foreign-root-no-namespace` | — | — | — | `root` | the root certificate names no namespace |
| `foreign-not-device-certificate` | — | — | — | `certificate`, `namespace`, `root` | not a device certificate of its root's namespace |
| `foreign-root-invalid-namespace` | — | — | — | `root` | the root names no valid namespace |
| `foreign-root-expired` | — | — | — | `root` | the root certificate is outside its validity period |
| `foreign-certificate-invalid` | — | — | — | `certificate`, `root`, `error` | does not validate against its root |
| `foreign-chain-incomplete` | — | — | — | `certificate`, `root` | the hello does not carry the whole chain to its root |
| `namespace-not-held` | — | — | — | `namespaces` | the peer entry expects a device, and the certificates are of namespaces this device does not hold |

### Why a relay admits no enrollment link (cause `no-enrollment-link`)

| code | status | retry | next | params | meaning |
|---|---|---|---|---|---|
| `no-enrollment-link` | — | — | — | causes (one per held namespace) | this relay admits no enrollment link either |
| `enrollment-links-off` | — | — | — | `namespace` | the namespace's link policy turns enrollment links off |
| `enrollment-no-ca` | — | — | — | `namespace` | its trust context names no CA to enroll at |
| `enrollment-role-may-not-relay` | — | — | — | `namespace`, `role` | its link policy does not let this relay's role relay |
| `enrollment-no-certificate` | — | — | — | `namespace` | this relay holds no certificate in it |
| `enrollment-no-namespace` | — | — | — | — | this relay holds no namespace |

### Relays and serving (`detail` of a relay, `serve`)

| code | status | retry | next | params | meaning |
|---|---|---|---|---|---|
| `relay-linked` | — | — | — | `cost` | linked; its routes have this cost |
| `relay-off` | — | — | — | — | its mode is off; it links when asked |
| `relay-down` | — | — | — | `standing_in`?; cause (last failure) | down, dialled again with backoff; `standing_in`: the relays standing in (none: this device is reached through no relay meanwhile) |
| `relay-chosen` | — | — | — | — | chosen; dialling |
| `relay-chosen-on-demand` | — | — | — | — | chosen; on demand, it links on traffic or when the host is active |
| `relay-down-not-needed` | — | — | — | `chosen`; cause (last failure) | down, and not needed while `chosen` more preferred relays are chosen |
| `relay-standby` | — | — | — | `chosen`, `count` | not needed: `chosen` more preferred relays are chosen (`count` wanted) |
| `serve-own` | — | — | — | — | this relay serves its own namespaces |
| `serve-listed` | — | — | — | `listed`, quotas? | its own namespaces and `listed` by root key |
| `serve-open` | — | — | — | quotas | every namespace, under quotas |

Quotas are the params `links_total`, `links_per_namespace`,
`interests_per_key` and `interests_per_namespace` (per second).

## Invites

A device that runs CAs (one per namespace it is the root of, `[[ca]]`) makes
invites at runtime through three trust-admin verbs. Like the approval verbs,
they are accepted only from a local operator on the management socket, never
over `/localhop`. Each CA keeps its invites durably in its own directory
(`<ca dir>/invites/`). The record holds a hash of the token, never the token,
so invites survive a restart. Every change is recorded before it takes
effect.

| verb | ControlParameters | success (status text, JSON) |
|---|---|---|
| `ca/invite-create` | `Uri`: `ndn_cert::InviteRequest` `{role, ttl_secs?, device?}`; `Name`?: the CA's namespace or prefix | `ndn_cert::CreatedInvite` `{id, ca, namespace, role, scope, created_secs, expires_secs?, device?, created_by, state, token, link}`. This is the only time the token is shown. |
| `ca/invite-list` | `Name`?: one CA (absent: every CA) | `[ndn_cert::CaInviteListing]` `[{ca, namespace, invites: [InviteEntry]}]`: outstanding invites, and those ended in the last 30 days, oldest first, with no token |
| `ca/invite-withdraw` | `Uri`: the invite id; `Name`?: the CA | the withdrawn `ndn_cert::InviteEntry` |

An `InviteEntry` is `{id, role?, scope?, created_secs, expires_secs?,
device?, created_by?, state, ended_secs?, redeemed_for?}`. `state` is
`outstanding`, `expired`, `redeemed` or `withdrawn`. `device` is a hint: the
invitee's default device name, not a constraint. A request that names no CA
goes to the device's only CA. Changes are announced on the trust stream as
`invite-created`, `invite-withdrawn` and `invite-redeemed` (see
Notifications).

Params are strings. Lists are `, `-separated.

| code | status | retry | next | params | meaning |
|---|---|---|---|---|---|
| `invite-no-ca` | 404 | no | use-other-device | — | this device runs no CA, so it makes no invites |
| `invite-several-cas` | 400 | no | fix-request | `namespaces`, `count` | this device runs several CAs and the request names none: name the namespace |
| `invite-ca-unknown` | 404 | no | fix-request | `requested`, `namespaces` | this device runs no CA of the namespace (or prefix) asked |
| `invite-request-invalid` | 400 | no | fix-request | `error` | the `Uri` of `invite-create` is not an invite request |
| `missing-parameter` | 400 | no | fix-request | `operation`, `parameter` (`Uri`), `expects` | `invite-create` without a request, or `invite-withdraw` without an id |
| `invite-role-unknown` | 400 | no | fix-request | `role` | not a role of the namespace layout |
| `invite-role-needs-approval` | 400 | no | fix-request | `role`, `namespace` | the role (admin, node) is certified only on an admin's approval, never by an invite |
| `invite-expiry-invalid` | 400 | no | fix-request | `ttl_secs` | the lifetime is zero, or beyond what a time can hold |
| `invite-device-invalid` | 400 | no | fix-request | `device`, `error` | the suggested device name is not a device name |
| `invite-unknown` | 404 | no | fix-request | `id` | this CA holds no invite with this id |
| `invite-already-redeemed` | 409 | no | none | `id`, `ended_secs`, `redeemed_for`? | nothing to withdraw (revoke the device it admitted instead) |
| `invite-already-withdrawn` | 409 | no | none | `id`, `ended_secs` | withdrawn already |
| `invite-not-recorded` | 500 | yes | fix-local | `error` | the CA could not record the change, so nothing changed |
| `invite-not-made` | 500 | yes | fix-local | `error` | no random token could be drawn |

When the CA's `token` challenge refuses a token, its NDNCERT denial text
starts with a stable code followed by `: ` (`ndn_cert::TokenDenial`, read
back with `TokenDenial::of_reason`). The codes are `invite-missing`,
`invite-unknown`, `invite-redeemed`, `invite-withdrawn`, `invite-expired`,
`invite-out-of-scope` and `invite-not-recorded`. The enrolling device reports
such a denial as `invite-refused` (Trust-admin verbs), with the denial in
`error`.

## Issued certificates

`ca/issued-list` lists the certificates each CA of a device issued: the
members of each namespace as its root device knows them. Like the invite
verbs it is a trust-admin verb, accepted only from a local operator on the
management socket, never over `/localhop`. It lists what the running CA
holds: the record in its own directory (`<ca dir>/issued/`,
`<ca dir>/revoked/`), loaded when it starts and written before every
issuance and revocation takes effect. The CA's own certificate and those
of earlier CAs of its identity are not listed.

| verb | ControlParameters | success (status text, JSON) |
|---|---|---|
| `ca/issued-list` | `Name`?: one CA, by namespace or prefix (absent: every CA) | `[ndn_cert::CaIssuedListing]` `[{ca, namespace, certificates: [IssuedEntry]}]`, CAs in the order the device runs them |

An `IssuedEntry` is `{certificate, key, identity, role?, device?,
valid_from, valid_until, revoked}`:

- `certificate`: the certificate's name; `key`: the key it certifies
  (`<identity>/KEY/<id>`); `identity`: the key name without `KEY/<id>`.
- `role` and `device`: the identity's role (`admin`, `member`, `node`,
  `guest`) and device name, when the identity follows the namespace's role
  layout `/<ns>/<role>/<device>`; absent otherwise.
- `valid_from`, `valid_until`: the validity period, ISO 8601 basic, UTC
  (`20261017T120000Z`).
- `revoked`: the CA revoked the certificate or its key, or the trust
  context version the device holds for the certificate's name revokes the
  certificate, its key, or a key on its issuer chain (the CA's key, the
  namespace root's).

Certificates are ordered by `identity`, then newest first (latest
`valid_from`), then by `certificate`. A renewed device has one entry per
certificate it was issued.

| code | status | retry | next | params | meaning |
|---|---|---|---|---|---|
| `issued-no-ca` | 404 | no | use-other-device | — | this device runs no CA, so it issued no certificates |
| `issued-ca-unknown` | 404 | no | fix-request | `requested`, `namespaces` | this device runs no CA of the namespace (or prefix) asked |

## Data inspection

`security/data-inspect` says what a device's own validator makes of the
Data under a name. The device fetches it like any app on it: one Interest
(CanBePrefix, not MustBeFresh) through its forwarder, so its content store
answers when it holds one and the FIB forwards it otherwise. It validates
the Data that answered with its validator — dispatched to the held trust
context whose namespace covers the name — walking the certificate chain to
a trust anchor and fetching the certificates it misses. The fetch and the
validation share the time the command gives. Read only, but the device
expresses Interests and fetches certificates on the caller's behalf, so the
verb is no public read: it goes through the command gate (a local operator
on the management socket, or a command signed by a key the command trust
anchors vouch for). Answered deferred.

| verb | ControlParameters | success (status text, JSON) |
|---|---|---|
| `security/data-inspect` | Name: the Data's name or a prefix of it; ExpirationPeriod?: how long to wait for the Data and its certificates, in milliseconds (absent: 4000; at most 60000) | `ndn_cert::report::DataInspection` |

```json
{
  "name": "/home/bob/photos/1/v=3/seg=0",
  "signature_type": "Ed25519",
  "signer": "/home/bob/member/phone/KEY/%01",
  "signed_at": "20261019T120000Z",
  "content_type": "Blob",
  "freshness_ms": 10000,
  "content_bytes": 4096,
  "valid_from": null,
  "valid_until": null,
  "namespace": "/home/bob",
  "verdict": "valid",
  "detail": { "code": "data-valid", "params": { "signer": "/home/bob/member/phone/KEY/%01", "namespace": "/home/bob" }, "text": "…" },
  "chain": ["/home/bob/member/phone/KEY/%01", "/home/bob/KEY/root"]
}
```

| field | type | meaning |
|---|---|---|
| `name` | string | the name of the Data that answered (the name asked for when the forwarder refused the Data) |
| `signature_type` | string | `Ed25519`, `EcdsaSha256`, `RsaSha256`, `HmacSha256`, `DigestSha256`, `DigestBlake3`, `Blake3Keyed`, or the SignatureType code in decimal; empty when the forwarder refused the Data |
| `signer` | string? | the KeyLocator name: the key (or certificate) that signed it |
| `signed_at` | string? | the SignatureTime, ISO 8601 basic UTC, when the signature carries one |
| `content_type` | string | `Blob`, `Link`, `Key`, `Nack`, `Manifest`, `PrefixAnn`, or the ContentType code in decimal; empty when the forwarder refused the Data |
| `freshness_ms` | integer? | the FreshnessPeriod |
| `content_bytes` | integer | the length of the Content |
| `valid_from`, `valid_until` | string? | a certificate's ValidityPeriod, ISO 8601 basic UTC; absent for Data that is no certificate, and for a bound the certificate does not set |
| `namespace` | string? | the held trust context whose namespace covers the name (the longest): the trusted prefix that vouches for it; absent when none covers it |
| `verdict` | string | `valid`, `invalid`, `pending` (a certificate on the chain could not be had in time), `unchecked` (the device validates nothing); a client reads an unknown value as unknown |
| `detail` | detail | why the verdict (codes below) |
| `chain` | list of string | the signing keys the validation walked, the signer's first, ending at the trust anchor; empty unless the chain was walked to its end |

A Data the device's forwarder refuses (its pipeline validates Data from
other devices) never reaches the inspection: the answer then carries only
the name asked for, the trusted prefix, and the refusal (`data-refused`);
the verdict is `invalid` for a final refusal and `pending` for
`unverifiable`. Data from a local producer is not validated on the way, so
the verdict is the inspection's own.

| code | where | params | meaning |
|---|---|---|---|
| `data-valid` | `DataInspection.detail` | `signer`, `namespace`? | the signature verifies and the chain reaches a trust anchor (verdict `valid`) |
| `data-digest-only` | 〃 | — | the Data carries a matching SHA-256 digest: intact, but no signer vouches for it (verdict `valid`) |
| `data-invalid` | 〃 | `error` | the Data fails validation: bad signature, revoked key, a signer the trust context does not authorize, an untrusted root, an expired certificate (verdict `invalid`) |
| `data-refused` | 〃 | `refusal` (`chain`, `revoked`, `bad-signature`, `schema`, `untrusted-root`, `context`, `unverifiable`), `final` (`true`/`false`) | the device's forwarder refused the Data that answered, so it was not kept to inspect (verdict `invalid`, or `pending` when not final) |
| `data-chain-incomplete` | 〃 | `certificate`? (the first one missing), `timeout_ms` | a certificate on the chain could not be had in time (verdict `pending`) |
| `data-unchecked` | 〃 | — | the device validates nothing: validation is disabled (verdict `unchecked`) |

| code | status | retry | next | params | meaning |
|---|---|---|---|---|---|
| `data-not-found` | 504 | yes | retry-later | `name`, `timeout_ms`, `nack`? (`no-route`, `congestion`, `duplicate`, `not-yet`, `unspecified`, or the NackReason code), `error`? | nothing under the name reached the device in time: no Data in its content store, none from the network |
| `missing-parameter` | 400 | no | fix-request | `operation` = `data-inspect`, `parameter` = `Name`, `expects` | no name was given |

## Root-device operations (library)

New versions of a namespace's trust context are signed where its root (or a
recovery kit) is unlocked — an operator's CLI, an app's admin screen — never
inside the running device, which holds public keys only. These operations
are the library `ndn_namespace::root`, called in process; they are no
management verbs, and their refusals never cross the wire. A refusal is a
`ndn_namespace::root::RootError`: a `TrustRefusal` with one of the codes
below, plus the failure underneath as its error source (a host that shows
error chains shows it, one that words codes ignores it).

| operation | library | does |
|---|---|---|
| init | `root::init::init` | a new namespace: its root in the chosen root store, its CA and admin identity, version 1 |
| revoke | `root::revoke::plan`, `revoke` | version `N+1` revoking the keys a device identity, key or certificate name designates |
| recovery kits | `root::kit::create`, `list`, `check`, `revoke` | a recovery key listed as a recovery anchor by `N+1` (24 words, a sealed file, a key on a second YubiKey); the kits held; a kit opened against the held version; `N+1` without it |
| recover | `root::recover::recover` | a replacement device becomes the root device with a kit: `N+1` signed by the kit, `N+2` by the new root |
| root key | `root::key::open`, `HeldRoots::status`, `move_to` | where each root key lives; moving one to another store |
| schema | `root::schema::load`, `view`, `Adopted::explain`, `root_of`, `plan_update`, `update` | the held schema as data; why a key may sign a name; `N+1` carrying the current generated schema |

**Namespaces.** A PIB can hold the roots of several namespaces, one root store
each. Every operation acts on one namespace and changes only its root, held
version and kits: the namespace the host names, else the only one whose root
the PIB holds — several and none named is `several-namespaces` (listing
them), one named whose root is not held is `other-namespace-root`. A
revocation acts on the namespace covering the name (the longest whose root
is held; one named must be that one, `revoke-other-namespace`), and so does
revoking a kit when no namespace is named. A recovery is refused only where
the PIB holds the root of that namespace (`already-root-device`); the roots
of others stay beside the recovered one.

**Plan, then secrets.** Each operation first checks whatever needs no key
(this is the root device, what the name designates, nothing to sign, the
running device uses the same PIB); a host may show the plan before going on.
Only then are secrets asked, through the host's `root::SecretSource`, with
what they are for as data (`SecretRequest { kind, purpose, confirm }`;
`confirm`: a new secret, ask twice). The library never reads a terminal or a
file for a secret; a secret is dropped (zeroed) after its one use and never
goes to the running device, which receives only the signed version.

**Hand-over.** The host's `root::RunningDevice` reaches the device that uses
the PIB; a daemon over its management socket is
`root::daemon::MgmtDevice`, the one implementation `ndn-fwd` and `ndn-tui`
share (it answers the `device-*` codes below, and keeps a refusal the daemon
answered coded, its sentence in the host's words). The library refuses a
device of another PIB (`device-other-pib`), hands each signed version over
with the retry and undo rules of `ndn_namespace::admin::hand_over`, and keeps
the version in the PIB for the device's next start when none runs. A
recovery needs the device running (`device-not-running`): it refreshes the
namespace by name first, so the recovery starts from the newest version (the
`newest-*` codes).

Params are strings. Names are NDN URIs, `pib` and `path` filesystem paths,
`namespaces` (and `namespace` where it lists those held) comma-separated
URIs, `secret` one of `root-passphrase`, `root-pin`, `kit-passphrase`,
`kit-pin`, `kit-words`, `store` a root store kind (`os-keyring`,
`sealed-file`, `yubikey-piv`, `file`), `error` the underlying failure's
text. A refusal that wraps another names it in `cause` and carries its
params too; a param shown `?` is set only when it applies.

| code | status | retry | next | params | meaning |
|---|---|---|---|---|---|
| `pib-unreadable` | 500 | no | fix-local | `pib` | the key storage could not be opened |
| `root-local-failure` | 500 | no | fix-local | `error` | a local failure (storage, encoding, crypto) stopped the operation |
| `not-root-device` | 409 | no | use-other-device | `pib`, `operation` | the PIB holds no namespace root: `operation` is done on the root device |
| `no-longer-root` | 409 | no | use-other-device | `key`, `namespace`, `version` | the PIB's root is no anchor of the held version (the namespace was recovered elsewhere) |
| `namespace-not-held` | 404 | no | adopt | `namespace`, `pib`? | no trust context of the namespace is held |
| `no-namespace-held` | 404 | no | adopt | `pib` | no trust context is held at all |
| `several-namespaces` | 400 | no | fix-request | `namespaces`, `count`, `pib`? | several roots (or held contexts) and none named: name the namespace |
| `other-namespace-root` | 409 | no | fix-request | `pib`, `namespace` (held), `requested`, `operation`? | the PIB holds the roots of other namespaces only |
| `root-bad-request` | 400 | no | fix-request | `error` | a name does not fit the namespace's role layout, or a needed part of the request is missing |
| `secret-unavailable` | 400 | no | provide-secret | `secret`? | the host could give no secret (none entered, entries differ, no way to ask) |
| `secret-needed` | 400 | no | provide-secret | `secret`, `key`, `store`, `location` | the root store needs a secret that was not given |
| `wrong-secret` | 403 | no | provide-secret | `secret`, `path` | the secret does not open the sealed root or kit |
| `bad-recovery-words` | 400 | no | provide-secret | `error` | the recovery words are not text, have an unknown word or fail their checksum |
| `keychain-unavailable` | 500 | no | fix-local | `reason` | no OS keychain is reachable |
| `no-default-root-store` | 400 | no | fix-request | `reason` | no root store chosen, and the default (the OS keychain) is not reachable: choose one |
| `keychain-entry-missing` | 500 | no | fix-local | `service`, `account`, `path` | the OS keychain lost the entry that seals the root |
| `token-in-use` | 409 | no | fix-request | `serial`, `holds` | the token holds the key a new one must not share a token with (the root, or the kit used) |
| `slot-in-use` | 409 | no | fix-request | `serial`, `slot`, `state` | generating in that slot would destroy the key it holds (or may hold) |
| `root-store-not-built` | 500 | no | use-other-device | `store`, `feature` | this build has no support for that root store |
| `token-failed` | 500 | yes | fix-local | `error` | the hardware token failed |
| `kit-token-too-old` | 400 | no | fix-request | `firmware` | the token's firmware cannot hold a recovery kit |
| `root-store-failed` | 500 | no | fix-local | `error` | the root store is unusable (descriptor, wrong key, storage) |
| `root-store-unmovable` | 400 | no | fix-request | `from`, `to`, `reason` | the root cannot be moved to that store |
| `root-not-unlocked` | 403 | no | provide-secret | cause | the root did not unlock; nothing was signed |
| `already-initialized` | 409 | no | fix-request | `namespace`, `pib`, `what` | the namespace is initialized in this PIB already; its root is replaced only when forced |
| `namespace-policy-refused` | 400 | no | fix-local | `error` | the stated namespace policy (enrollment, links, relays) is refused |
| `revoke-outside-namespace` | 400 | no | fix-request | `name`, `namespace` (held), `operation`? | the name (or recovery key) is outside every namespace whose root the PIB holds |
| `revoke-other-namespace` | 400 | no | fix-request | `name`, `namespace`, `requested` | the name is in `namespace`, not the one named |
| `revoke-namespace-ca` | 403 | no | fix-request | `name`, `namespace` | the name is the namespace CA's: devices are revoked one by one |
| `revoke-none-issued` | 404 | no | fix-request | `pib`, `name` | the namespace CA issued no certificate under that device name |
| `revoke-refused` | 403 | no | fix-request | `name`, `error` | the key may not be revoked (not of the namespace, or it covers an anchor) |
| `nothing-to-sign` | 409 | no | none | `version` | the held version has everything asked already |
| `not-a-kit` | 400 | no | fix-request | `path`, `reason` | the file is not a recovery kit |
| `kit-other-namespace` | 400 | no | fix-request | `kit`, `namespace`, `path`? | the kit recovers another namespace |
| `kit-not-an-anchor` | 403 | no | fix-request | `key`, `namespace`, `version` | the kit's key is no recovery anchor of the held version |
| `not-a-recovery-kit` | 404 | no | fix-request | `key`, `namespace`, `version` | the key named is no recovery kit of the held version |
| `kit-file-exists` | 409 | no | fix-request | `path` | a file exists where the new kit would be written |
| `kit-not-added` | 409 | no | other | cause, `removed`? | the kit was made but no version listing it was signed or taken: nothing changed, the kit file written was removed |
| `signer-not-an-anchor` | 403 | no | use-other-device | `key`, `namespace`, `version` | the signing key is no anchor of the held version |
| `already-root-device` | 409 | no | use-other-device | `pib`, `namespace`, `store` | a recovery into a PIB holding that namespace's root already |
| `ca-present` | 409 | no | use-other-device | `path` | a recovery into a PIB holding a CA identity of the namespace |
| `kept-kits-need-compromised` | 400 | no | fix-request | — | kits to keep are named only when the old root is compromised |
| `device-store-mismatch` | 409 | no | fix-request | `namespace`, `version`, `pib`, `stored`? | the running device holds `version` but its PIB stores another one (`stored`) or none |
| `held-context-invalid` | 500 | no | fix-local | `namespace`, `version` | the stored version does not verify under its own anchors |
| `newest-behind` | 409 | yes | refresh | `namespace`, `held_version`, `detail`; cause | a newer version exists than the one held: a recovery from it would fork the namespace |
| `newest-unconfirmed` | 504 | yes | retry-later | `namespace`, `held_version`, `detail`; cause | nothing answered: whether the held version is the newest is unknown (the person may vouch for it, `from_held`) |
| `recover-on-root-device` | 409 | no | none | `namespace` | the device holds the namespace's root: nothing to recover |
| `newest-failed` | 504 | yes | retry-later | `namespace`, `held_version`, `detail`; cause | the newest version could not be fetched |
| `newest-not-held` | 404 | no | adopt | `namespace` | the device holds no version and there is no expected fingerprint to adopt one with |
| `newest-not-adopted` | 403 | no | adopt | `namespace`, `status_code`, `reason` | adopting with the kit's expected fingerprint was refused |
| `device-not-running` | 409 | yes | fix-local | `address`, `error` | no device runs where the operation needs one |
| `device-unreachable` | 403 | no | fix-local | `address`, `pib`, `error` | the running device cannot be used (permissions) |
| `device-pib-unknown` | 500 | yes | retry-later | `address`, `error` | the running device did not say which PIB it uses |
| `device-other-pib` | 409 | no | fix-request | `address`, `device_pib`, `pib` | the running device uses another PIB than the one worked on: a version made here must not go there |
| `device-failed` | 500 | yes | retry-later | `address`, `error`, `status_code`?, `reason`? | an exchange with the running device failed (`status_code`, `reason`: a refresh it refused) |
| `hand-over-refused` | 409 | no | other | `version`, `status_code`, `device_code`, `reason` | the running device answered that it did not take the version (`device_code`: its refusal's code) |
| `hand-over-unreadable` | 500 | no | wait | `version`, `error`, `answer` | the device's answer could not be read; it may have taken the version |
| `hand-over-failed` | 504 | yes | wait | `version`, `failure` | handing the version over failed without an answer; it may still be taken |
| `hand-over-unanswered` | 504 | yes | wait | `version`, `waits` | the device never answered; it may still take the version |
| `version-not-stored` | 500 | no | fix-local | `error` | no device runs, and the version could not be kept for its next start |
| `version-not-taken` | 409 | no | other | `version`, `held_version`; cause | the signed version was not taken: nothing changed (what was made for it is undone) |
| `hand-over-unknown` | 504 | yes | wait | `version`, `held_version`; cause; the operation's: `keys` and `name` (revoke), `key` (kit), `namespace` (schema), `root_key`, `ca_key`, `device_key`, `pib` (recover) | whether the device took the version is not known; it may still. Asking again once it is idle settles it |
| `schema-not-generated` | 500 | no | fix-local | `namespace`, `error` | the namespace's schema could not be generated |
| `schema-narrowing` | 409 | no | fix-request | `namespace`, `version`, `what` (`rules`, `link`, `relays`), `removed` (`; `-separated) | the update narrows what devices may do; it is signed only with consent to narrow |
| `schema-unreadable` | 500 | no | fix-local | `blob`, `format` (`lvs`, `native`), `error` | a schema blob of the held context cannot be read (one of the blobs of a schema view) |
| `no-context-governs` | 404 | no | adopt | `name` | no held trust context governs the name |

## Notifications

A client follows what changes on a device — approvals arriving and decided,
invites, the trust-context versions it keeps, its membership in each trusted
prefix (adopted, enrolled, renewed, revoked, root changed), its requests for
an admin's approval ending, renewals failing, links — by subscribing to two
change-notification streams instead of polling the listing verbs. There is
one trust stream: every trust change of the device, whatever made it, is
one event on it. The JSON types are `ndn_cert::report::TrustEvent` and
`ndn_mgmt_wire::events::LinkEvent`; the daemon side is
`ndn_mgmt::MgmtEvents`, the client side `ndn_ipc::events`.

### Streams

| Stream | Prefix | Events |
|---|---|---|
| trust | `/localhost/nfd/security/notifications` | approvals and invites at this node's CAs; trust-context versions, memberships, requests ended, renewals failed of this node |
| links | `/localhost/nfd/links/notifications` | link states |

Each is an NFD-style notification stream: event number `N` is the Data
`<prefix>/seq=N` (SequenceNumber name component), unsigned
(`DigestSha256`), its content one JSON object. A subscriber sends a
`MustBeFresh` Interest for `<prefix>/seq=N`; the daemon answers at once when
it holds event `N`, else holds the Interest for its lifetime (at most 60 s)
until event `N` is published. An unanswered Interest is sent again for the
same `N`.

Sources of the trust stream, in one daemon: the device's own changes
(`ndn_namespace::Participant::events`, forwarded from the trust-admin
backend's `TrustAdminMgmtBackend::trust_events`), and each CA it runs (its
approval store's and invite store's observers and its issuance observer,
`CaState::set_issued_observer`, publish directly). Each
change is published once, by the code that made it: a version kept is told
by the keeping (whichever way it came), an enrollment by the installation of
its certificate, a request ended by what ended it (the CA's answer, its
expiry, a failed issuance).

### Sequence numbers, ring and resync

- Events are numbered consecutively. A stream's first event of a daemon run
  is numbered after the run's start time in microseconds, so numbers never
  repeat across restarts.
- The daemon keeps the newest 100 events of each stream.
- When a subscriber asks for an event the stream does not hold — dropped
  from the ring, from an earlier run (below this run's start), or beyond the
  next one — the daemon answers, at the requested name,
  `{"kind":"resync","next":N}`: the subscriber lists the state again
  through the management verbs, then asks for event `N`. Events published
  between the resync and the listing are delivered again; every event
  carries a state, so applying one twice is harmless.
- A new subscriber asks for event `0` and starts with a resync.
- Inside the daemon, a source that falls far behind (a few hundred events)
  loses the oldest; the stream logs how many. A subscriber cannot tell this
  gap from a quiet period, which is why the listing verbs stay the state of
  record and a resync re-reads them.

`ndn_ipc::events::EventSubscription::<TrustEvent | LinkEvent>` does this:
`next()` yields `Notice::Event { seq, event }` in order or
`Notice::Resync { next }`. A long-poll holds its management connection's
receive lock, so a subscription uses a connection of its own
(`EventSubscription::connect(socket)`), not the one commands are sent on.

An app embedding the library (ndn-mobile) gets the same events from
`Participant::events` without a stream; its membership watch
(`watch_memberships`) hands on the `membership-changed` events with the
same fields.

### Event objects

Every object has a `"kind"`. A kind's fields are only ever added (a client
ignores fields it does not know); a change of meaning takes a new kind, and
a client skips kinds it does not know (`Unknown` in the Rust types). Enum
values a client does not know read as `unknown`. Optional fields (`?`) are
absent when empty. Names are NDN URIs; times ISO 8601 UTC.

Trust stream:

| `kind` | Fields | When |
|---|---|---|
| `approval-requested` | `ca`, `request`, `role`? | a device asked a CA of this node for an admin's approval |
| `approval-decided` | `ca`, `request`, `decision`: `approved` \| `denied` | a request at a CA of this node was decided (here or by an admin device) |
| `invite-created` | `ca`, `id`, `role`? | a CA of this node made an invite |
| `invite-withdrawn` | `ca`, `id` | an invite was withdrawn before it was used |
| `invite-redeemed` | `ca`, `id`, `role`? | a device redeemed an invite |
| `certificate-issued` | `ca`, `certificate`, `role`? | a CA of this node issued a certificate (by invite, on an admin's approval, or a renewal) |
| `context-updated` | `namespace`, `held_version`?, `version`, `how`: `adopt` \| `refresh` \| `update` \| `sync`, `revoked`? | this node now holds `version` of the namespace's trust context |
| `membership-changed` | `namespace`, `relation`, `change`, `version`, `key`?, `revoked`?, `replaced_version`?, `valid_until`?, `request`? | this node's membership in the namespace changed |
| `enrollment-ended` | `namespace`, `identity`, `request`, `state`: `denied` \| `expired` \| `failed` | this node's request for an admin's approval ended without a certificate |
| `renewal-failed` | `key`, `state`: `refused` \| `failed`, `code`? | a renewal of this node's certificate failed; the current one stays in use until it expires |

Fields:

- `ca`: the CA's prefix. `request`: the request id (`ca/list-approvals`,
  `security/enroll-status`). `id`: the invite id (`ca/invite-list`).
  `role`: the role the key asks for, the invite grants or the certificate
  certifies, when it follows the namespace layout.
- `certificate-issued`: `certificate` is the issued certificate's name
  (`<key>/NDNCERT/<version>`); the CA serves it, so it is no secret. It is
  told once the CA recorded it; who it certifies and its validity are read
  through `ca/issued-list`. An approval's certificate is issued when the
  device next asks after the decision, so it follows `approval-decided`.
- `context-updated`: `held_version` is the version held before (absent for
  a namespace new to the node). `how`: `adopt` — from an anchor link
  (`security/context-adopt`, on the way to an enrollment, or an app's
  envelope); `refresh` — fetched from upstream (`security/context-refresh`
  or the periodic check); `update` — handed over by a tool that signed it on
  this device (`security/context-update`: a revocation, a recovery kit, a
  recovery, a schema update); `sync` — pushed over the namespace's sync
  group. `revoked`: the key or certificate names the new version revokes
  that the held one did not. One event per version kept: the versions a
  refresh walked through to reach the newest are stored and served, not
  told; a version refused, or one no newer than the held one, is not told.
- `membership-changed` (always after the `context-updated` of the same
  version when a version caused it): `relation` after the change:
  `following` \| `member` \| `owner` (as `security/memberships`).
  `change`:

  | `change` | When | Fields set |
  |---|---|---|
  | `adopted` | the namespace's trust context was adopted: the node follows it | — |
  | `enrolled` | the node holds a certificate in the namespace now | `key`, `valid_until`; `request` when the enrollment waited for an admin's approval |
  | `renewed` | a certificate of the node's key in the namespace was renewed | `key`, `valid_until` |
  | `revoked` | a version revokes the chain of the key the node signs the namespace's Data with | `key`, `revoked` (the key or certificate name on the chain) |
  | `root-changed` | another root signs the namespace (a recovery); adding or removing a recovery kit is no root change | `replaced_version` |

  `version` is the version of the trust context held after the change.
- `enrollment-ended`: `identity` is the identity asked for. An approved
  request ends in `membership-changed` `enrolled` (with `request`), not
  here. `denied` / `expired` delete the request's key; `failed`: approved
  but the certificate could not be kept, or the request could not go on.
  Why: `security/enroll-status`.
- `renewal-failed`: `refused` — the CA refused, renewing again does not
  help; `failed` — it may work later and is retried. `code`: the detail
  code `security/renew` reports for it.

Links stream:

| `kind` | Fields | When |
|---|---|---|
| `link-changed` | `label`, `key`? (hex fingerprint), `device`?, `paths` (kinds up: `direct` \| `link` \| `relay`), `direct` (direct-path state), `mode`?, `relay`? (relay state), `asleep`, `down`? (its `links/list` code) | a link appeared or its state changed: its state now |
| `link-gone` | `label`, `key`? | a link is no longer listed |

The daemon reads its links each second and publishes the links whose state
changed; timers, counters, addresses and texts are not events (`links/list`).

### What is never carried, and why the streams are not gated

The streams are served to every local face: the forwarder answers every
Interest for a name with the same Data (PIT aggregation, the content store),
so a producer cannot keep one local subscriber's events from another. They
therefore carry only identifiers and states — never a verification code, an
invite token, a key or device name of a pending request at a CA, a denial's
reason or any other free text, an approver's identity, a refusal's words or
any secret. A client words each event itself from its kind and fields and
reads the details through the verbs gated to local trust administrators:
`ca/list-approvals` (who asks, the code), `security/enroll-status` (why a
request ended), `ca/invite-list`, `ca/issued-list`, `security/memberships`,
`links/list`, and `security/identity-status` / `security/context-refresh`
for the versions held.
