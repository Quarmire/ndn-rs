# NDNCERT extensions: device approval, renewal, invite tokens

- **Status:** Draft
- **Scope:** What ndn-rs adds to, or does differently from, NDNCERT v0.3 so
  that an independent requester, approver or CA (for example NDNts or
  python-ndn) interoperates with ndn-rs. It covers:
  - enrollment by an admin's **approval**: the `device-approval` challenge,
    the approval request record, the verification code, and the three
    endpoints `<ca>/CA/STATUS/<id>`, `<ca>/CA/PENDING` and `<ca>/CA/APPROVAL`;
  - the `renewal` challenge;
  - the `token` challenge and the invite token string;
  - how the trust context's EnrollmentHint and CaEndpoint select the CA and
    the challenge.

  It covers flows F2 (add a device) and F10 (rotate keys) of
  [personal-namespace.md](personal-namespace.md).
- **Baseline:** NDNCERT v0.3 (named-data/ndncert,
  `docs/NDNCERT-protocol-0.3`). Whatever this document does not change is
  NDNCERT v0.3 as implemented by ndn-rs. Only the deltas listed here are
  normative.
- **Out of scope:** the trust-context format, validation and EnrollmentHint
  octets ([trust-context.md](trust-context.md)); the `ndn-trust://invite`
  envelope that carries a token ([trust-envelope.md](trust-envelope.md));
  enrollment links over QUIC ([ndn-link.md](ndn-link.md)); refusal Nacks
  ([local-refusal.md](local-refusal.md)); recovery
  ([recovery-kit.md](recovery-kit.md)). Mgmt verbs, CLI output and on-disk
  stores are informative only.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174)
when, and only when, they appear in all capitals, as shown here.

## 1. Terminology

- **Namespace** `<ns>`: an NDN name prefix owned by one person, e.g.
  `/home/bob`. Device keys follow the role layout
  `<ns>/<role>/<device>/KEY/<key-id>`. The role is one of `admin`, `member`,
  `node`, `guest`.
- **Trust context**: the signed, versioned Data that carries the
  namespace's anchors, schema, CA endpoints, EnrollmentHint and revocations
  ([trust-context.md](trust-context.md)).
- **CA prefix** `<ca>`: the prefix under which a CA serves its NDNCERT
  names `<ca>/CA/…`. The namespace CA has identity `<ns>/CA` and CA prefix
  `<ns>`.
- **Root device**, **adopt**, **enroll**, **invite**, **link**, **relay**,
  **route**, **recovery kit**: as in
  [personal-namespace.md](personal-namespace.md).
- **Approval**: an admin's decision to certify one requesting key.
- **Approval request**: the CA's durable record of one requesting key that
  waits for an approval (§6.2).
- **Request id** (approval request id): 16 lowercase hex characters naming
  an approval request. It is not the same thing as the NDNCERT request id.
- **NDNCERT request id**: the 8-byte `RequestId` of one NEW→CHALLENGE
  session (NDNCERT v0.3). Its **hex form** is its 16 lowercase hex
  characters.
- **Verification code**: six decimal digits that both the requester and the
  approver show (§7).
- **Admin key**: a key `<ns>/admin/<device>/KEY/<k>` with a current
  CA-issued certificate that chains to the namespace root under the
  context's schema and is not revoked.
- **Expected fingerprint**: as in [trust-envelope.md](trust-envelope.md).
- **URI form** of a Name: the canonical NDN URI that ndn-rs prints (§3.6).

Byte strings are shown in lowercase hex. "TLV" means NDN TLV with VAR-NUMBER
type and length. JSON means RFC 8259 text, UTF-8, with no whitespace between
tokens.

## 2. Overview (informative)

```
requester (new device)                 CA <ca>                     approver (admin device)
  NEW + CHALLENGE(device-approval) ──▶ open record, id, code
  ◀── status 2, {request, code, expires}
  shows code                                                        
  <ca>/CA/STATUS/<id>  (held) ───────▶ holds until decided
                                       ◀── <ca>/CA/PENDING (signed Interest) ── lists
                                       ── CA-signed list ──────────────────────▶ shows code
                                       ◀── <ca>/CA/APPROVAL (decision Data) ─── signs
                                       record approved
  ◀── STATUS answer {"state":"approved"} (CA-signed)
  NEW + CHALLENGE(device-approval, request=<id>) ─▶ issue
  ◀── status 3, IssuedCertName; fetch certificate
```

An approval binds to a key, not to an NDNCERT session. The CA keeps one
durable record per requesting key. The requester runs a fresh NEW→CHALLENGE
exchange for every poll and names the request it resumes. Either side may
restart in between. A local operator of the CA host may also decide; that
path is local to the CA and has no wire format.

## 3. Deltas common to every challenge

### 3.1 Names and session

1. NDNCERT names are `<ca>/CA/INFO`, `<ca>/CA/NEW`,
   `<ca>/CA/CHALLENGE/<RequestId>` and `<ca>/CA/REVOKE` as in v0.3. The
   `<RequestId>` component is a GenericNameComponent holding the 8 raw
   bytes. Because a CHALLENGE Interest carries ApplicationParameters, its
   last component is the ParametersSha256DigestComponent.
2. **Endpoint dispatch.** A CA MUST select the endpoint by the exact
   GenericNameComponent that follows `<ca>` / `CA` (itself a
   GenericNameComponent), never by a substring or prefix of the URI, and
   MUST check what follows it:

   | Endpoint | After the endpoint component |
   |---|---|
   | `INFO` | anything (version, segment) |
   | `NEW`, `REVOKE`, `PENDING`, `APPROVAL` | nothing, or only the ParametersSha256DigestComponent |
   | `CHALLENGE` | the RequestId, then optionally the ParametersSha256DigestComponent |
   | `STATUS` | the request id, and nothing after it (§8.1) |

   A `NEW` or `CHALLENGE` name with anything else after the endpoint is
   answered with ErrorCode 1 (§3.5). Any other name under `<ca>` that
   matches no endpoint, such as `<ca>/CA/APPROVALX` or
   `<ca>/CA/APPROVAL/x`, is not an endpoint (§3.5, last paragraph).
3. Each NEW and CHALLENGE Interest is a signed Interest (NDN packet format
   v0.3), signed by the key being certified. The KeyLocator names that key.
   The cert request in NEW is self-signed and named
   `<key>/cert-request/v=<ms>`.
4. A requester SHOULD send a cert request whose ValidityPeriod is empty
   (`NotBefore` equal to `NotAfter`). The CA then applies its policy
   lifetime. If the window is non-empty, the CA issues
   `min(requested, policy, max_validity)`.
5. A CA keeps a session from NEW for 60 s. After a CHALLENGE that answers
   status 2, it keeps the session for the RemainingTime it advertised. At
   every NEW it drops expired sessions.
6. A CA built on ndn-rs signs every NEW, CHALLENGE, STATUS, PENDING and
   APPROVAL answer with its CA key, failure answers (§3.5) included. The
   KeyLocator is the CA certificate name, and the answer has no
   FreshnessPeriod. The ndn-rs requester does **not** validate the NEW and
   CHALLENGE answers, so it never treats them as final (§6.6). It MUST
   validate STATUS, PENDING and APPROVAL answers (§8–§10).
7. The CA names an issued certificate `<key>/NDNCERT/v=<version>` (issuer
   component `NDNCERT`, VersionNameComponent). Every certificate of a key,
   renewals included, therefore has its own name. A requester SHOULD fetch
   it with a ForwardingHint of `<ca>`.

### 3.2 Status codes

The CA uses status `2` for every challenge that waits for more: another
round, or an admin's decision. It never sends status `1`. A requester MUST
treat `1` and `2` alike: the session needs another round.

Failure after the session is open is status `4` in the encrypted CHALLENGE
response, with these ErrorCodes:

| Cause | ErrorCode |
|---|---|
| challenge denied, or issuance policy denied after the challenge | 7 (OutOfTries) |
| approval request expired or gone (`device-approval`) | 8 (OutOfTime) |
| another request for the same single-key identity is being certified, or the identity is held by another key | 5 (NameNotAllowed) |

A NEW or CHALLENGE the CA cannot process gets the unencrypted failure
answer of §3.5 instead. Either way, a requester MUST read ErrorCode 8 as
"expired" and ErrorCode 5 as a refusal of the requested name. ndn-rs reads
7 as "denied" and the request-format codes (1–4, 6, 9) as a refusal of the
request that keeps its code; it reads any other value as "denied". None of
these answers is final (§6.6). ErrorInfo is human-readable text with what
to do. It has no grammar.

### 3.3 Challenge parameters

- **CHALLENGE request plaintext.** `SelectedChallenge (0xA1)` followed by
  zero or more `ParameterKey (0x85)` / `ParameterValue (0x87)` pairs. Both
  keys and values are UTF-8. ndn-rs emits the pairs sorted by key in byte
  order. A receiver MUST accept any order. Elements of any other type are
  ignored.
- **CHALLENGE response plaintext**: `Status (0x9B)`, then
  `ChallengeStatus (0xA3)`, `RemainingTries (0xA5)`, `RemainingTime
  (0xA7)`, `IssuedCertName (0xA9, containing a Name TLV)`, `ErrorCode
  (0xAB)`, `ErrorInfo (0xAD)`, each when present, then the response
  parameters as ParameterKey / ParameterValue pairs. Response parameters
  are an ndn-rs addition: the CA returns them with status 2.
- Status, RemainingTries, RemainingTime and ErrorCode are
  NonNegativeIntegers (NDN packet format v0.3: 1, 2, 4 or 8 octets,
  big-endian). ndn-rs writes Status, RemainingTries and ErrorCode in 1
  octet and RemainingTime in 4. A reader MUST accept every valid width and
  MUST refuse the response when one of them has another width. ndn-rs
  saturates a RemainingTries above 255 to 255 and a RemainingTime above
  2³² − 1 s to 2³² − 1, and refuses a Status or ErrorCode above 255.
- A parameter value that is not a JSON string on the producer side (for
  example `issuers`, §11.2) is written as its compact JSON text.

### 3.4 Offered challenges

The NEW response lists the CA's configured challenges in configuration
order. A namespace CA whose context advertises approval roles also offers
`device-approval` when it is not configured (§4.2). The CA appends
`renewal` when its issuance policy renews any role. A requester MUST select
only an offered challenge. A CHALLENGE whose SelectedChallenge was not
offered, or differs from the first one of the session, is answered with
ErrorCode 4 (§3.5).

### 3.5 Failure answers

A CA MUST answer a NEW or CHALLENGE that it cannot process with a Data
whose Content is exactly one `ErrorCode (0xAB)` followed by one `ErrorInfo
(0xAD, UTF-8)`: unencrypted, with no Status, as NDNCERT v0.3 does (the
v0.3 requester reads only those two elements and refuses any other
critical one). The Data is named and signed as every answer (§3.1 item 6).
ndn-rs uses these ErrorCodes:

| Cause | ErrorCode |
|---|---|
| NEW or CHALLENGE name not of the form of §3.1 item 2 | 1 (BadInterestFormat) |
| malformed NEW body, cert request, ECDH key, CHALLENGE envelope or plaintext; a handler's malformed-request error | 2 (BadParameterFormat) |
| unknown or expired NDNCERT session; unoffered or changed challenge type; a failure of the CA itself (storage, signing, RNG) | 4 (InvalidParameters) |
| the CA's namespace policy refuses the key name in NEW | 5 (NameNotAllowed) |
| a challenge handler's denial or expiry raised as an error | 7 or 8 |

For a failure of the CA itself, ErrorInfo says only to ask again later; the
CA logs the detail. A requester MUST look for a top-level ErrorCode in
every NEW and CHALLENGE answer before decoding it otherwise (a NEW answer
and a CHALLENGE envelope never carry one), and read it as in §3.2. The
ndn-rs requester thus reports a policy refusal of the name in NEW as "name
refused".

An Interest under `<ca>` that nothing answers (no endpoint, §3.1 item 2,
and no issued certificate) gets a Nack `NoRoute`.

### 3.6 URI form

Several byte strings below contain a Name in URI form. The URI form is `/`
followed by the components joined with `/`. Each component is written as
follows:

- A GenericNameComponent (type 8) is written as its value. Bytes that are
  ASCII letters, digits, `-`, `.`, `_`, `~` are written as is. Every other
  byte is written `%XX` with uppercase hex. A value made only of periods
  (or empty) gets three extra periods.
- A ParametersSha256DigestComponent is written
  `params-sha256=<64 lowercase hex>`. An ImplicitSha256DigestComponent is
  written `sha256digest=<64 lowercase hex>`. A KeywordNameComponent is
  written `keyword=<escaped>`.
- A Segment, ByteOffset, Version, Timestamp or SequenceNum component whose
  value is a minimal NonNegativeInteger is written `seg=`, `off=`, `v=`,
  `t=` or `seq=`, followed by the decimal value.
- Every other component is written `<type decimal>=<escaped>`.

The root Name is `/`.

## 4. Enrollment policy

### 4.1 Where a device enrolls

1. An invite ([trust-envelope.md](trust-envelope.md)) names the CA prefix
   in its CaPrefix field. The device enrolls there.
2. With only an anchor link, the CA prefix is the first CaEndpoint of the
   held trust context. If that endpoint's last component is the
   GenericNameComponent `CA`, that component is dropped. A context with no
   CaEndpoint gives the namespace itself.

### 4.2 Meaning of the EnrollmentHint

The octets are defined in [trust-context.md](trust-context.md) §3.3.7. Its
meaning here:

- `approval_roles` lists the roles whose certificates the namespace CA
  issues **only** on an admin's approval through `device-approval`. A hint
  with an empty role list (contexts made before the hint carried roles)
  means the default, `admin,node`.
- `require_all` set (`invite_also`): a request for an approval role must
  also redeem an invite token when the request is opened (§6.3).
- `ndn-fwd init` writes `token,device-approval;admin,node`, with
  `require_all` clear.
- A namespace CA MUST enforce exactly what the newest context it holds
  advertises. ndn-fwd refuses to start the CA when its configuration states
  something else.

### 4.3 Which challenge a requester uses

For identity `<ns>/<role>/<device>`, with role R:

| R in approval roles | `require_all` | Link held | Challenge | Token parameter |
|---|---|---|---|---|
| yes | clear | invite or anchor | `device-approval` | none |
| yes | set | invite | `device-approval` | the invite's token |
| yes | set | anchor | refused locally | — |
| no | — | invite whose role = R | `token` | the invite's token |
| no | — | anchor, or invite of another role | refused locally | — |

### 4.4 Issuance by role (namespace CA)

The namespace CA's issuance policy decides after the challenge:

- A `device-approval` attestation admits any role. For an approval role
  with `require_all`, the attestation must also say that an invite was
  redeemed (`invite: true`, §11.4).
- A `renewal` attestation admits the certificate's role if that role is
  renewable. By default every role except `guest` is renewable.
- A `token` attestation admits `member` when the token is unscoped or
  scoped inside `<ns>/member`. It admits `guest` only when scoped inside
  `<ns>/guest`. It never admits an approval role.
- No other challenge admits any role.
- One key per device identity: the CA refuses to certify a new key for
  `<ns>/<role>/<device>` while it holds an unrevoked certificate of that
  identity for another key. A `device-approval` attestation overrides
  this. The refusal (ErrorCode 5) comes before the challenge runs, so a
  token is not spent.

## 5. Invite tokens and the `token` challenge

### 5.1 Token string

```abnf
invite-token = [ role "-" ] secret [ "-until" expiry ]
role         = "member" / "guest" / "admin" / "node"   ; case-sensitive
secret       = 1*VCHAR                                 ; generated: 2*HEXDIG lowercase
expiry       = 1*DIGIT                                 ; Unix seconds, decimal, fits u64
```

`ndn-fwd-tokens new` mints `<role>-<32 lowercase hex>` (16 random bytes by
default). With `--ttl` it appends `-until<now + ttl>`.

A reader derives:

- **Role**: split the token at its **first** `-`. If the left part equals
  exactly one of the four role names and the right part is non-empty, that
  is the role. Otherwise the token has no role.
- **Expiry**: split the token at its **last** occurrence of `-until`. If
  there is none, the token does not expire. If the right part is
  non-empty, all ASCII digits, and fits a u64, that is the expiry.
  Otherwise the expiry is **malformed** and the reader MUST refuse the
  token: it is never read as a token that does not expire.
- **Validity**: a token with an expiry is valid while `now < expiry`, in
  Unix seconds; at the expiry second it has expired. The CA and the
  invitee apply the same boundary.

The whole string, suffix included, is the token. A CA MUST match it
byte-exactly.

Producers MUST NOT emit a `secret` that contains `-until`.

### 5.2 CA rules

1. A namespace CA MUST refuse to load an `admin-…` or `node-…` token. It
   MUST scope a token with no role to `<ns>/member`. It MUST scope a
   `member-…` or `guest-…` token to `<ns>/<role>`. A CA that is not a
   namespace CA scopes role tokens the same way and leaves other tokens
   unscoped.
2. A token with an expiry is redeemable while the CA clock is before the
   expiry (§5.1). A CA MUST NOT load a token whose expiry is malformed;
   ndn-rs skips it with a warning, so it is never redeemable.
3. A token is single-use. The CA removes it atomically on redemption. If
   the CA has durable storage, it records the redemption before approving.
   A recorded token is never accepted again, even if it is still
   configured. An ndn-rs CA records the redemption as the hex of
   SHA-256(`"ndncert-token-redemption/v1"` 0x00 ‖ token), which is
   informative.
4. The token is refused when its scope is not a prefix of the requested key
   name. A scope or expiry refusal does not spend the token.

### 5.3 `token` challenge (ndn-rs addition)

- Challenge type `token`. One CHALLENGE round. Parameter `token` holds the
  token.
- If redeemed, the CA continues to issuance (§4.4). The attestation leaf
  has kind `token` and, for a scoped token, the evidence `token_scope`
  holding the scope in URI form.
- If refused, status 4 with ErrorCode 7. ErrorInfo is one of: `token
  expired`, `token is scoped to <scope>; requested name is outside it`,
  `invalid or already-redeemed token`, `missing 'token' parameter`.

### 5.4 Invitee checks

Before sending anything, an invitee MUST refuse an invite whose token has
expired by its own clock (§5.1: at or after the expiry second) or whose
expiry is malformed. It MUST also refuse an invite whose token role
differs from the invite's identity namespace role. A token with no role
counts as `member`.

## 6. The `device-approval` challenge

### 6.1 CHALLENGE request

Challenge type `device-approval`. Parameters:

| Key | Value | When |
|---|---|---|
| `request` | request id (16 lowercase hex) | when resuming a known request; OPTIONAL |
| `token` | invite token (§5.1) | when `require_all` applies to the role; only the opening poll redeems it |

The first poll for a new key carries no parameter. Its plaintext is
`SelectedChallenge` alone.

The CA chooses the record as follows:

1. With `request`, it uses that record. The record's key name (URI form)
   and SHA-256 of its public key must equal those of this NDNCERT session.
   If not, the CA refuses (status 4, code 7). If the CA holds no such
   record, or the record is pending past its expiry, the reply is status 4,
   code 8.
2. Without `request`, it uses the record for the same key name and the same
   public-key digest, whatever its state. If that record is pending past
   its expiry, the CA removes it and continues with step 3.
3. Otherwise it opens a new record (§6.3).

The CA then answers from the record's state:

| Record | Response |
|---|---|
| pending | status 2; ChallengeStatus text; RemainingTries 1; RemainingTime 60; parameters `request` = request id, `code` = verification code (§7), `expires` = decimal Unix seconds |
| approved | the CA continues to issuance with the attestation of §11.4: status 3 and IssuedCertName, or the issuance refusal |
| denied | status 4, code 7, ErrorInfo names the approver and the reason |

The NDNCERT session of a pending answer is never reused. Each poll is a
new NEW→CHALLENGE exchange.

### 6.2 Approval request record

A CA MUST keep, durably, per request: request id; CA prefix (URI); key name
(URI); hex SHA-256 of the public key; role and device (when the key follows
the role layout); verification code; created and expires times (Unix
seconds); whether an invite was redeemed; and the state. The state is
pending, approved (by whom, when) or denied (by whom, when, reason). The
JSON form is in §11.3.

- The request id is 8 random bytes in lowercase hex. It MUST be unique
  among the CA's records. The bytes MUST come from a working RNG: a CA
  whose RNG fails refuses to open the request (§6.3) and never falls back
  to a fixed id. The same holds for the NDNCERT request id, salt and IV,
  and for new key ids.
- A pending record expires `ttl` after it is created. `ttl` is policy (in
  ndn-fwd, `[ca] approval_request_ttl_days`, default 7, never 0).
- When a request is decided, its `expires` becomes `decision time + ttl`:
  the CA keeps the decision that long so that a requester that was offline
  still learns it.
- The CA prunes a decided record after its `expires`, and a pending record
  `ttl` after its `expires`. Until a pending record is pruned, it is
  reported as expired.

### 6.3 Opening a request

A CA MUST refuse to open a request (status 4, code 7, nothing recorded) in
these cases:

- a live pending request exists for the same key name with another public
  key;
- `MAX_PENDING` = 256 live pending requests exist;
- `MAX_PENDING_PER_PREFIX` = 32 live pending requests exist under the same
  parent of the key's identity. For example `/ns/role/device/KEY/x` counts
  under `/ns/role`;
- `require_all` applies and `token` is missing or not live (unknown,
  redeemed or expired). The token's scope is not checked here: the admin's
  approval decides the role;
- the CA cannot draw a random request id (§6.2). The invite is not spent.

When an invite is required, the CA MUST record the request durably
**before** it redeems the token. If the redemption then fails, it MUST
remove the record. A storage failure therefore never spends the invite.

### 6.4 Approved: issuance

The approved poll goes through §3.1 item 7 and §4.4. The CA does not
re-check the decision Data at issuance; it trusts its record.

### 6.5 Who decides

- **A local operator of the CA host.** Authenticated by the host (ndn-fwd:
  kernel peer credentials on the management socket; refused over
  `/localhop`). No wire format. The record names the operator as
  `uid <n> (<user>)`.
- **An admin key**, through §10.

### 6.6 What may end a request on the requester

The requester MUST NOT delete its key or end a request because of a NEW or
CHALLENGE answer. Those answers are not validated (§3.1 item 6): a denial,
an expiry, a refusal or an unreadable answer is not final. Only a STATUS
answer validated under §8.3 saying `denied` or `expired` ends a request.
Two other events also end it: the requester's own key fails to sign, and
the overdue rule of §14.

## 7. Verification code

Inputs:

- `C`: the CA prefix in URI form (§3.6), UTF-8. The CA uses its own prefix.
  The requester uses the CA prefix it enrolled at (§4.1), for example
  `/home/bob`, without `/CA`.
- `K`: the requesting public key as the CA decodes it from the cert
  request's Content. For a 44-byte Ed25519 SubjectPublicKeyInfo (prefix
  `302a300506032b6570032100`), `K` is the 32-byte raw key. Otherwise `K` is
  the Content bytes unchanged.
- `I`: the request id, 16 ASCII characters.

```
input  = "ndncert-approval-code/v1" || 0x00 || C || 0x00 || SHA-256(K) || 0x00 || I
digest = SHA-256(input)
n      = uint32_big_endian(digest[0..4]) mod 1000000
code   = decimal(n / 1000, 3 digits, zero-padded) || " " || decimal(n mod 1000, 3 digits, zero-padded)
```

- The code is not a secret.
- A requester MUST compute the code itself from its own key. If the CA's
  `code` parameter differs, the requester MUST refuse the answer: the CA
  holds another key's request under that name.
- A typed code is normalized as follows: remove every space and `-`. The
  result must be exactly 6 ASCII digits, and is then shown as
  `ddd ddd`.

## 8. `<ca>/CA/STATUS/<request id>`

### 8.1 Interest

- The name is `<ca>` / `CA` / `STATUS` / `<request id>`: three
  GenericNameComponents after `<ca>`, the last one holding the request id
  as UTF-8. Nothing follows it.
- MustBeFresh. Unsigned, with no ApplicationParameters, so relays aggregate
  identical status Interests.
- InterestLifetime: `STATUS_LIFETIME` = 30 s while waiting, or
  `STATUS_PROBE_LIFETIME` = 4 s while probing (§14). A lifetime of at most
  `STATUS_ANSWER_MARGIN` = 2 s asks for an immediate answer.

### 8.2 CA behaviour

- **Hold.** `hold = min(lifetime, MAX_STATUS_HOLD + STATUS_ANSWER_MARGIN) −
  STATUS_ANSWER_MARGIN`, with `MAX_STATUS_HOLD` = 60 s. The result is
  floored at 0. An absent lifetime counts as 4 s.
- The CA answers as soon as the record is no longer pending (decided,
  expired or pruned), when the hold ends, or at once when the CA stops. At
  each of those points the answer carries the record's state at that time.
- **Immediate checks.** A STATUS Interest whose hold is 0 (lifetime at
  most `STATUS_ANSWER_MARGIN`) is answered at once with the record's state
  and takes no held slot. A CA does not rate-limit them per request: each
  costs one signature, as does the answer for an unknown request id, which
  no per-request limit can bound; Interest rate limits belong to the
  forwarder.
- **Limits.** The CA holds at most `MAX_HELD_PER_REQUEST` = 4 status
  Interests per request and `MAX_HELD_STATUS` = 1024 in total. Beyond
  that, it answers a held one with Nack `Congestion`.
- A CA that serves no approvals answers with Nack `NoRoute`.
- **Answer Data.** Its name equals the Interest name. Content is the
  `RequestStatus` JSON of §11.1. It has no FreshnessPeriod and is signed by
  the CA key. An unknown request id answers `expired`.

### 8.3 Requester checks

A requester MUST accept a STATUS answer only if all of these hold:

1. its name equals the Interest name;
2. it validates to the namespace root under the context's schema. Only the
   CA key may sign `<ns>/CA/<…>` Data
   ([trust-context.md](trust-context.md) §6);
3. its `request_id` equals the request id asked about;
4. its `key_name`, when present, equals the requester's key name.

Otherwise it MUST ignore the answer and ask again.

## 9. `<ca>/CA/PENDING`

### 9.1 Interest

- The name is `<ca>/CA/PENDING`, followed by the
  ParametersSha256DigestComponent.
- MustBeFresh. It MUST be a signed Interest (NDN packet format v0.3) signed
  by an admin key, with SignatureNonce and SignatureTime. ndn-rs writes an
  8-octet SignatureNonce and the SignatureTime in milliseconds. An
  approver MUST sign every listing Interest afresh: a retransmitted wire is
  refused as a replay (§9.2).
- The KeyLocator names the admin key, or one of its certificates.
- ApplicationParameters: the concatenated Data wires of the admin's
  certificate chain. The admin certificate comes first, then each issuer
  certificate up to, and including, the first self-signed one. The CA uses
  at most 6 of them.

### 9.2 CA checks and answer

The CA walks the chain with its own CA certificate plus the supplied
certificates and nothing else. The maximum depth is 8. The walk verifies
every hop. The schema rule `#pending: <ns>/"CA"/"PENDING"/_ <= #admin` must
admit the Interest name. Neither the trust context nor the CA may revoke
the signer's key.

Then the CA applies the NDN signed-Interest freshness rule. All of these
must hold, else the answer is `refused`, kind `unauthorized`:

1. SignatureTime and SignatureNonce are present;
2. SignatureTime is within `LISTING_SIG_TIME_GRACE` = 120 s of the CA's
   clock, either way;
3. the CA has not seen the same (SignatureNonce, SignatureTime) from the
   same KeyLocator before.

The CA records the pair only for an Interest whose chain verified. ndn-rs
remembers 64 pairs per signer key and 256 signer keys, least recently used
first out, in memory. A captured listing Interest can therefore be
replayed only within the window, and only to a CA that restarted, or that
evicted the pair, since it answered it.

- **Answer Data.** Named as the Interest, with no FreshnessPeriod, signed
  by the CA key. Content is a `ListingAnswer` (§11.2):
  - `listed`: the pending, unexpired records, oldest first (by
    `created_secs`, then request id);
  - `refused`: kind `unauthorized`, with a reason.
- The approver MUST validate the answer to the namespace root before it
  uses it.
- `listed` reveals the same records to every admin key that asks within
  the rules above (Decision Q9: only live pending records).

## 10. Decisions and `<ca>/CA/APPROVAL`

### 10.1 Decision Data

| Field | Approve | Deny |
|---|---|---|
| Name | `<key>/ndncert-approve/<request id>` | `<key>/ndncert-deny/<request id>` |
| Content | the verification code as shown (`ddd ddd`), UTF-8 | the reason, UTF-8 (empty → "no reason given") |
| MetaInfo | none | none |
| SignatureInfo | the admin key's SignatureType; KeyLocator = admin key name | same |

- `<key>` is the requesting key name, in its Name components. `ndncert-approve`
  and `ndncert-deny` are GenericNameComponents. `<request id>` is one
  GenericNameComponent holding the request id as ASCII.
- Schema rules: `#approve: <ns>/_/_device/"KEY"/_/"ndncert-approve"/_ <=
  #admin` and `#deny: <ns>/_/_device/"KEY"/_/"ndncert-deny"/_ <= #admin`.
- For the same record and key, the decision Data is deterministic with a
  deterministic signature scheme (Ed25519).

### 10.2 Push Interest

- The name is `<ca>/CA/APPROVAL`, followed by the
  ParametersSha256DigestComponent. MustBeFresh. **Unsigned.**
- ApplicationParameters: the decision Data wire, followed by the admin
  certificate chain (as in §9.1).
- The decision Data is the authority. The Interest is only its carrier.

### 10.3 CA checks, in order

1. The first TLV element decodes as Data. Its name ends `ndncert-approve`
   or `ndncert-deny`, then the request id, with at least one component
   before them. Failure gives `bad-request`.
2. The KeyLocator is present. The chain validates under the held trust
   context, as in §9.2 (supplied certificates at most 6, depth at most 8,
   the `#approve`/`#deny` rule, revocation by the context and by the CA).
   Failure gives `unauthorized`. No refusal reveals the record's code or
   key before this step succeeds.
3. The record exists. Failure gives `not-found`.
4. The record's key name equals `<key>` in URI form. Failure gives
   `bad-request`.
5. For an approval, the normalized Content (§7) equals the record's code.
   Failure gives `bad-request`.
6. The record is pending and not expired. A decision is final; failure
   gives `conflict`.
7. The CA records the decision durably. Failure gives `storage`. On
   success, the approver is recorded as `admin-key`: the signer's key name,
   and as evidence the base64url (no padding) of the decision Data wire.
   Every held STATUS Interest for the request is then answered.

**Answer Data.** Named as the Interest, signed by the CA key. Content is a
`DecisionAnswer` (§11.2): `recorded` with the record as it now stands, or
`refused`.

### 10.4 Accepted signature types (normative)

A CA MUST verify decisions and PENDING Interests only with asymmetric
signature types of the signer certificate's key: SignatureSha256WithEcdsa
(3) or Ed25519 (5). A CA MUST refuse DigestSha256 (0),
SignatureHmacWithSha256 (4), and keyed or unkeyed BLAKE3 (6, 7). ndn-rs
refuses 0, 4, 6 and 7 for every signer resolved through a certificate or
trust anchor (`TrustError::NotPublicKeySignature`); it also accepts
SignatureSha256WithRsa (1).

## 11. JSON encodings

All objects are JSON. Field order is as shown. Readers MUST NOT depend on
the order and MUST ignore unknown fields.

### 11.1 RequestStatus (STATUS content)

Tagged by `state`:

```json
{"state":"pending","request_id":"<id>","key_name":"<uri>","expires_secs":<u64>}
{"state":"approved","request_id":"<id>","key_name":"<uri>"}
{"state":"denied","request_id":"<id>","key_name":"<uri>","reason":"<text>"}
{"state":"expired","request_id":"<id>","reason":"<text>"}
```

`approved` means that the next poll (§6.1, with `request`) issues the
certificate.

### 11.2 ListingAnswer and DecisionAnswer

Tagged by `outcome`:

```json
{"outcome":"listed","records":[<ApprovalRecord>,…]}
{"outcome":"recorded","record":<ApprovalRecord>}
{"outcome":"refused","kind":"<kind>","reason":"<text>"}
```

`kind` is one of `not-found`, `conflict`, `unauthorized`, `bad-request`,
`storage`.

### 11.3 ApprovalRecord

```json
{"request_id":"…","ca_prefix":"<uri>","key_name":"<uri>","public_key_sha256":"<64 hex>",
 "role":"admin"|null,"device":"laptop"|null,"code":"ddd ddd","created_secs":<u64>,
 "expires_secs":<u64>,"invite":<bool>,"state":"pending"|"approved"|"denied", …}
```

State fields, flattened into the record:

- `approved` adds `"by":<Approver>,"at_secs":<u64>`.
- `denied` adds `"by":<Approver>,"at_secs":<u64>,"reason":"…"`.
- Approver is tagged by `kind`:
  - `{"kind":"local-operator","who":"uid 1000 (alice)"}`
  - `{"kind":"admin-key","key":"<uri>","evidence":"<base64url Data>"}`

`role`, `device` and `invite` MAY be absent: absent means `null`, `null`,
`false`.

### 11.4 Attestation of an approved request

When the CA embeds attestations in the certificate (AdditionalDescription,
`emit_attestations`), an approved request gives one leaf:

```json
{"combinator":"Single","leaves":[{"kind":"device-approval","performed_at":<u64>,
 "handler_name":"device-approval","evidence":{"approved_by":"…","approver_kind":"admin-key"|"local-operator",
 "code":"ddd ddd","request_id":"…"[,"invite":true]}[,"signature":"<evidence>"]}]}
```

`signature` is present only for `admin-key`, and holds the decision Data
evidence. A leaf for `local-operator` claims no signature.

## 12. Who signs what

| Packet | Signed by | Verified by | Accepted signer |
|---|---|---|---|
| NEW / CHALLENGE Interest | requesting key | not validated | — |
| NEW / CHALLENGE Data | CA key | not validated by ndn-rs requester | — |
| STATUS Interest | unsigned | — | — |
| STATUS Data | CA key | requester (§8.3) | CA key under `<ns>/CA/KEY/<k>` per schema |
| PENDING Interest | admin key | CA (§9.2), freshness included | `#admin` key, current, unrevoked |
| PENDING Data | CA key | approver | CA key |
| APPROVAL Interest | unsigned | — | — |
| decision Data (in APPROVAL) | admin key | CA (§10.3) | `#admin` key, current, unrevoked |
| APPROVAL Data | CA key | approver | CA key |
| issued certificate | CA key | requester: certifies its key, valid now, chains to the root | — |

## 13. Constants and limits

| Name | Value | Who |
|---|---|---|
| NEW→CHALLENGE window | 60 s | CA |
| `POLL_SESSION_SECS` (RemainingTime of a pending answer) | 60 s | CA |
| `DEFAULT_REQUEST_TTL` | 7 days (`[ca] approval_request_ttl_days`) | CA |
| `STATUS_LIFETIME` | 30 s | requester |
| `STATUS_PROBE_LIFETIME` | 4 s | requester |
| `STATUS_ANSWER_MARGIN` | 2 s | CA |
| `MAX_STATUS_HOLD` | 60 s | CA |
| `MAX_HELD_PER_REQUEST` | 4 | CA |
| `MAX_HELD_STATUS` | 1024 | CA |
| `MAX_PENDING` | 256 | CA |
| `MAX_PENDING_PER_PREFIX` | 32 | CA |
| `LISTING_SIG_TIME_GRACE` (PENDING SignatureTime window) | 120 s | CA |
| PENDING replay record | 64 pairs per signer key, 256 keys | CA (ndn-rs) |
| certificates taken from a PENDING/APPROVAL push | 6; chain depth 8 | CA |
| `OUTGOING_EXPIRY_GRACE` | 86400 s | requester |
| retry pause | 1 s doubling to 60 s | requester |

## 14. Requester behaviour (normative where marked)

1. **Open.** Generate the key. Run one poll (§6.1) without `request`, with
   `token` if required. The CA answers pending; the requester MUST check the
   code (§7). The requester SHOULD then keep `(namespace, ca prefix,
   identity, key name, request id, code, expires)` durably. The pending
   answer is final for this step. A failure answer (§3.5) to the poll is
   read as in §3.2 and is not final: for example a refused name asks for
   another device name.
2. **Wait.** Keep one STATUS Interest outstanding (§8), with lifetime
   `STATUS_LIFETIME`.
   - When it answers `pending`, update `expires` and send the next one.
   - If the answer came sooner than `hold(lifetime)/2` (the CA stopped, or
     an aggregated Interest of another device was answered), or there was
     no answer, a Nack or an untrusted answer, the requester SHOULD pause
     and switch to `STATUS_PROBE_LIFETIME`. The pause starts at 1 s and
     doubles up to the cap. The requester returns to `STATUS_LIFETIME`
     after a timely pending answer.
   - A requester that waits with a deadline (an app) MAY shorten the
     lifetime to the time left, but not below `STATUS_ANSWER_MARGIN`.
3. **Approved.** Run a poll with `request = <id>` and no token. On status 3,
   fetch the certificate and check it: it certifies the requester's key, is
   valid now, and chains to the namespace root. Store it. If the poll still
   answers pending, keep waiting and never loop fast.
4. **Denied / expired.** Only from a validated STATUS answer (§6.6): end the
   request and delete the key.
5. **Overdue.** A pending request more than `OUTGOING_EXPIRY_GRACE` past its
   `expires` (when known, i.e. non-zero) MAY be ended locally as expired.

## 15. Renewal challenge

### 15.1 Exchange

- Challenge type `renewal`. The CA offers it when its issuance policy
  renews any role (§3.4).
- The NEW cert request MUST carry the key name and public key of the
  certificate being renewed. Renewal never certifies a new key.
- The requester sends it to the CA prefix named by the certificate's
  KeyLocator `<prefix>/CA/KEY/<id>[/…]`, with `/CA/KEY/…` dropped. After a
  recovery that CA prefix may be served by a later CA key.
- One CHALLENGE round. Parameters:

| Key | Value | Required |
|---|---|---|
| `cert_name` | URI form (§3.6) of the certificate being renewed | yes |
| `signature` | base64url without padding of the proof signature (§15.2) | yes |
| `certificate` | base64url without padding of the certificate's Data wire | for a CA that did not issue it |
| `issuers` | JSON array text of base64url-without-padding Data wires of the issuer certificates of its chain, nearest first | for a CA that did not issue it; `[]` allowed |

ndn-rs always sends all four. A CA uses at most 8 issuers. It accepts
`issuers` as JSON array text, or as a native array when the parameter is
built in process.

### 15.2 Proof message

```
message = "ndncert-renewal" || 0x0A || H || 0x0A || N
```

- `H` is the **hex form of this exchange's NDNCERT request id**: lowercase
  hex of the `RequestId` from the NEW response, which is also the value of
  the CHALLENGE name component.
- `N` is the URI form (§3.6) of the certificate name, the same string as
  `cert_name`.
- There is no terminator.
- `signature` is the signature of `message` by the certificate's key:
  - Ed25519: 64 octets;
  - ECDSA P-256 with SHA-256: DER.

  The CA tries exactly those two algorithms.

The request id is fresh for every NEW, and the CHALLENGE plaintext is
encrypted under the session key, so a proof cannot be replayed into another
exchange.

### 15.3 CA checks

The CA approves only if all of these hold:

- `cert_name` parses.
- The certificate is one the CA issued and still serves. Otherwise it must
  be the carried `certificate`, issued by an earlier CA key of the same CA
  identity (`<prefix>/CA/KEY/<other>`), not revoked by the context, and
  chaining through a certified key (not a digest) to an anchor of the held
  context under its schema. The chain uses only the carried issuers, to
  depth 8.
- The certificate's key name equals the requested key name.
- The certificate's public key equals the requested one.
- No certificate of that key is revoked at the CA.
- The certificate is valid now.
- The proof verifies.

Failure gives status 4, code 7. On success the CA:

- applies the issuance policy, which checks that the role is renewable;
- serves from then on the earlier CA certificates the chain went through;
- issues `<key>/NDNCERT/v=<new version>` with the attestation leaf kind
  `renewal` and the evidence `certificate` holding `cert_name`.

A requester MUST refuse a renewal whose IssuedCertName equals the renewed
certificate's name.

## 16. Security considerations

- **Signature types.** See §10.4. A symmetric MAC (HMAC-SHA256, keyed
  BLAKE3) keyed with a certificate's key is a forgery anyone can make, as
  the key is public in the certificate; a digest names no signer. ndn-rs's
  signature dispatch refuses both for a public-key signer
  (`verify_by_sig_type`), and its Interest validation refuses a
  DigestSha256 Interest.
- **The verification code** has 20 bits of entropy and is not
  authentication. Its only use is to let a person bind the request they see
  to the device in their hand. The authority is the admin's signature over
  a name that contains the requesting key.
- **NEW and CHALLENGE answers** are not validated by the requester, so they
  can never end a request (§6.6). A forged pending answer can at worst
  delay the requester. A forged code is caught by §7.
- **PENDING** reveals key names, device names and codes to admin keys
  only. A captured listing Interest is refused when replayed (§9.2), except
  within 120 s of its signing by a CA that has since forgotten it.
- **Failure answers** (§3.5) are unencrypted and not validated by the
  requester. A forged one can at worst make the requester ask again, as a
  forged pending answer can.
- **Request flooding** is bounded by `MAX_PENDING` and
  `MAX_PENDING_PER_PREFIX`. Held STATUS Interests are bounded by the hold
  limits.

## 17. Test vectors

All values come from ndn-rs functions (Provenance below). Ed25519 keys come
from 32-byte seeds (RFC 8032). The signatures are deterministic.

### V1 Verification code

| Item | Value |
|---|---|
| `C` | `/home/bob` (Name TLV `070b0804686f6d650803626f62`) |
| key seed | `01` × 32 |
| `K` (raw Ed25519) | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |
| SHA-256(`K`) | `34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e` |
| `I` | `8f3a5c7e9b1d2f40` |
| input (84 octets) | `6e646e636572742d617070726f76616c2d636f64652f7631002f686f6d652f626f620034750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e0038663361356337653962316432663430` |
| digest | `06fd7d6350ab1396639574148695ef0d894ac40516da23118ab164dc6a31de4f` |
| `n` | `0x06fd7d63` = 117276003; mod 10⁶ = 276003 |
| code | `276 003` |

Same `C` and `I` with key seed `09` × 32 gives `646 544`. Same key and `C`
with `I` = `8f3a5c7e9b1d2f41` gives `246 131`.

Normalization: `482913`, `482 913` and `482-913` all give `482 913`;
`48291`, `4829134` and `48a913` give none.

### V2 Renewal proof

| Item | Value |
|---|---|
| NDNCERT request id | `5a17c309e2448b01` (hex form `5a17c309e2448b01`) |
| certificate | `/home/bob/member/phone/KEY/1a2b3c4d5e6f7081/NDNCERT/v=1760000000000` |
| certificate Name TLV | `07440804686f6d650803626f6208066d656d626572080570686f6e6508034b455908103161326233633464356536663730383108074e444e43455254360800000199c82cc000` |
| message (100 octets) | `6e646e636572742d72656e6577616c0a356131376333303965323434386230310a2f686f6d652f626f622f6d656d6265722f70686f6e652f4b45592f316132623363346435653666373038312f4e444e434552542f763d31373630303030303030303030` |
| key seed | `02` × 32; public key `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Ed25519 signature | `9e81175142b3e9c6a6fa45c0527beb0680e0d0ebffa2767a9fc16149335c44a5d76ff1ded791f2668892a63f760acadc35d2eb5a0d590a56d936661575106f06` |
| `signature` parameter | `noEXUUKz6cam-kXAUnvrBoDg0Ov_onZ6n8FhSTNcRKXXb_He15HyZoiSpj92CsrcNdLrWg1ZClbZNmYVdRBvBg` |

Parameter TLVs for `cert_name`, `issuers` = `[]` and `signature`, in
ndn-rs order (the real exchange also carries `certificate`, which sorts
between `cert_name` and `issuers`):

```
8509636572745f6e616d6587432f686f6d652f626f622f6d656d6265722f70686f6e652f4b45592f31613262
3363346435653666373038312f4e444e434552542f763d31373630303030303030303030850769737375657273
87025b5d85097369676e617475726587566e6f455855554b7a3663616d2d6b5841556e7672426f4467304f765f
6f6e5a366e38466853544e63524b5858625f4865313548795a6f6953706a3932437372634e644c725767315a43
6c625a4e6d5956645242764267
```

### V3 Invite token

| Item | Value |
|---|---|
| role, secret | `member`, `00112233445566778899aabbccddeeff` |
| expiry | 1767225600 |
| token (55 octets) | `member-00112233445566778899aabbccddeeff-until1767225600` |
| hex | `6d656d6265722d30303131323233333434353536363737383839396161626263636464656566662d756e74696c31373637323235363030` |
| role / expiry read back | `member` / 1767225600 |

| Token | Role | Expiry |
|---|---|---|
| `member-00112233445566778899aabbccddeeff` | member | none |
| `guest-3fa2` | guest | none |
| `admin-ab` | admin | none |
| `member-` | none | none |
| `-abc` | none | none |
| `friend-abc` | none | none |
| `Member-abc` | none | none |
| `abcdef` | none | none |
| `member-ab-until` | member | malformed: refused |
| `member-ab-until12x` | member | malformed: refused |
| `member-ab-until1-until2` | member | 2 |
| `ab-until99` | none | 99 |

### V4 `device-approval` CHALLENGE plaintexts

- First poll: `a10f6465766963652d617070726f76616c`.
- Poll with `request` = V1 `I` and `token` = V3 token:
  `a10f6465766963652d617070726f76616c8507726571756573748710386633613563376539623164326634308505746f6b656e87376d656d6265722d30303131323233333434353536363737383839396161626263636464656566662d756e74696c31373637323235363030`.
- Pending response with ChallengeStatus shortened to `waiting` (the real
  text is a sentence), RemainingTries 1, RemainingTime 60, `code` =
  `276 003`, `expires` = `1760604800`, `request` = V1 `I`:
  `9b0102a30777616974696e67a50101a7040000003c8504636f6465870732373620303033850765787069726573870a31373630363034383030850772657175657374871038663361356337653962316432663430`.
- Denied (`no`): `9b0104ab0107ad026e6f`.
- Expired (`gone`): `9b0104ab0108ad04676f6e65`.
- Unencrypted failure answer (§3.5), ErrorCode 5, ErrorInfo `no`:
  `ab0105ad026e6f`.

### V5 Names (CA prefix `/home/bob`)

| Name | TLV |
|---|---|
| `/home/bob/CA/STATUS/8f3a5c7e9b1d2f40` | `07290804686f6d650803626f62080243410806535441545553081038663361356337653962316432663430` |
| `/home/bob/CA/PENDING` (before the digest) | `07180804686f6d650803626f6208024341080750454e44494e47` |
| `/home/bob/CA/APPROVAL` (before the digest) | `07190804686f6d650803626f62080243410808415050524f56414c` |

| Interest lifetime | hold |
|---|---|
| absent | 2 s |
| 1 s, 2 s | 0 |
| 3 s | 1 s |
| 4 s | 2 s |
| 30 s | 28 s |
| 62 s, 100 s | 60 s |

### V6 Decision Data

Record: key `/home/bob/admin/laptop/KEY/0123456789abcdef`, request id V1
`I`, code `276 003`. Admin key `/home/bob/admin/phone/KEY/00aa11bb22cc33dd`,
seed `03` × 32, public key
`ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1`.

- Approve (220 octets), name
  `/home/bob/admin/laptop/KEY/0123456789abcdef/ndncert-approve/8f3a5c7e9b1d2f40`:
  `06da07540804686f6d650803626f62080561646d696e08066c6170746f7008034b4559081030313233343536373839616263646566080f6e646e636572742d617070726f766508103866336135633765396231643266343015073237362030303316371b01051c3207300804686f6d650803626f62080561646d696e080570686f6e6508034b45590810303061613131626232326363333364641740596c430c31c0203abd7a99132e504fd0863de8c810b1237146dc84f2bfa43465e9e383e45a446972369c72000fc7fc6e378b77a13969a6b2013a4099cb076c08`.
- Deny, reason `not mine`:
  `06d807510804686f6d650803626f62080561646d696e08066c6170746f7008034b4559081030313233343536373839616263646566080c6e646e636572742d64656e7908103866336135633765396231643266343015086e6f74206d696e6516371b01051c3207300804686f6d650803626f62080561646d696e080570686f6e6508034b4559081030306161313162623232636333336464174072501414f2dc9755831a345a77be317b4436db37ae0bd884daf12c1523c2c61cc90b52c6bdf3ba9c701d10fe55d60dcb4d8e6b10671a7c1da13f8fcc67836802`.

### V7 JSON

```
{"state":"pending","request_id":"8f3a5c7e9b1d2f40","key_name":"/home/bob/admin/laptop/KEY/0123456789abcdef","expires_secs":1760604800}
{"state":"expired","request_id":"8f3a5c7e9b1d2f40","reason":"R"}
{"request_id":"8f3a5c7e9b1d2f40","ca_prefix":"/home/bob","key_name":"/home/bob/admin/laptop/KEY/0123456789abcdef","public_key_sha256":"34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e","role":"admin","device":"laptop","code":"276 003","created_secs":1760000000,"expires_secs":1760604800,"invite":false,"state":"denied","by":{"kind":"local-operator","who":"uid 1000 (alice)"},"at_secs":1760000100,"reason":"not mine"}
{"outcome":"refused","kind":"unauthorized","reason":"R"}
```

### Provenance

On 2026-10-18, a throwaway example program in `ndn-cert` (since deleted)
called the functions below against the working tree and printed the
values:

- `verification_code` and `normalize_code`;
- `renewal_proof_message`, `Ed25519Signer::from_seed` and
  `encode_challenge_parameters`;
- `role_token`, `token_with_expiry`, `token_role` and `token_expiry`;
- `ChallengeResponseTlv::encode`, `decision_data` and `decision_name`;
- `status_name` and `status_hold`;
- `serde_json` over the record types.

Independent re-computation, in plain Python with `hashlib` and an RFC 8032
reference Ed25519:

- the V1 input bytes, digest and code;
- the V2 message bytes and Ed25519 signature;
- the public keys for seeds `01`, `02` and `03`;
- the signature over the V6 approve Data's signed region (Name through
  SignatureInfo);
- the base64url of the V2 signature;
- the V3 hex.

The same program probed a live `CaState` + `ApprovalService` for Bug 1.

The failure answer of V4 and the two malformed rows of V3 were written
from the TLV and grammar rules by hand; the unit tests
`error_content_roundtrips_and_is_told_apart` (`ndn-cert/tlv.rs`) and
`malformed_token_expiry_fails_closed` (`ndn-cert/roles.rs`) check them.

## 18. Open questions

1. **Code input uses the URI form of the CA prefix.** A stack whose URI
   printer differs (uppercase vs lowercase `%XX`, `8=` prefixes, typed
   components) computes another code. A `v2` could hash the Name TLV
   instead. Until then, the URI form is fixed by §3.6.
   **Recommendation:** keep `v1` (URI form, §3.6) as the only code input
   now; changing it changes every code shown, so a `v2` input
   (`ndncert-approval-code/v2`, hashing the Name TLV of `C`) needs a
   CHALLENGE response parameter that names the version and a transition
   in which requester and approver both show the version they used. Do it
   only when a second stack prints URIs differently.

### Decisions

- **Q2 Deadline-bounded checks.** A STATUS Interest with a hold of 0 is
  answered at once and takes no held slot; there is no per-request rate
  limit (§8.2). Each answer costs one signature, the same as the answer
  for an unknown request id, which no per-request limit can bound, and
  immediate checks no longer crowd out the held ones of the same request.
- **Q3 Failure answers for NEW and CHALLENGE.** The CA answers them with
  the unencrypted v0.3 ErrorCode + ErrorInfo Content (§3.5), and the
  requester reads it (§3.2), so a policy refusal of the name reaches the
  requester as "name refused". This is the v0.3 wire format, so v0.3
  requesters read it too.
- **Q4 PENDING freshness.** The CA applies the NDN signed-Interest rule to
  PENDING (§9.2): SignatureTime within 120 s and a bounded record of
  (SignatureNonce, SignatureTime) per signer key. A captured listing can
  no longer be replayed for as long as the admin certificate is valid.
  The record keeps no strict SignatureTime order, so two listings signed
  in one millisecond are both accepted.
- **Q5 Expiry boundary.** A token is valid while `now < until`, on the CA
  and on the invitee (§5.1). The invitee already refused at `now >=
  until`; the CA now refuses at the expiry second instead of one second
  later, and reads the `-until` second itself rather than a TTL counted
  from when it loaded the token.
- **Q6 Malformed expiry.** A `-until` suffix that is not a decimal u64 is
  refused, by the CA (the token is not loaded) and by the invitee (the
  invite is refused). Failing closed costs nothing: no producer emits
  such a token.
- **Q7 Endpoint dispatch.** The CA matches the exact component after
  `<ca>/CA` and checks the components after it (§3.1 item 2).
  `<ca>/CA/APPROVALX` reaches no handler.
- **Q8 Integer widths.** Status, RemainingTries, RemainingTime and
  ErrorCode decode as NonNegativeIntegers of 1, 2, 4 or 8 octets; any
  other width refuses the response (§3.3). This is the NDN packet
  format's rule, so ndn-rs reads any v0.3 CA.
- **Q9 Decided record listing.** Intended. The CA host's local listing
  (its operator, on the host) shows every record, decided ones included,
  as the record of who decided what. The remote PENDING listing serves
  deciding, so it shows only live pending records and reveals no decided
  history to other admin devices (§9.2).

## 19. Known deviations in ndn-rs (informative)

These are defects of the implementation as of this draft. An independent
implementation follows the normative text and SHOULD NOT copy them.

1. **Algorithm confusion in signature verification** (fixed). The chain
   walk used to verify SignatureHmacWithSha256 (4) and keyed BLAKE3 (7)
   using the signer certificate's public key as the MAC key, so a decision
   Data or a PENDING Interest MAC'd with an admin's public key was
   accepted. `verify_by_sig_type` now refuses MAC and digest types for a
   public-key signer.

## Appendix A. Code references (non-normative)

Paths are relative to the workspace root. `ndn-cert` =
`ndn-rs/crates/security/ndn-cert/src`.

| Claim | Code |
|---|---|
| Endpoint, component and parameter constants; timing; limits; `LISTING_SIG_TIME_GRACE`, replay record; `POLL_SESSION_SECS`; `DEFAULT_REQUEST_TTL` | `ndn-cert/approval.rs:77-158` |
| Per-prefix pending group | `ndn-cert/approval.rs:134-139` |
| ApprovalRecord, ApprovalState, Approver JSON | `ndn-cert/approval.rs:160-238` |
| Verification code, normalization | `ndn-cert/approval.rs:254-281` |
| RefusalKind names | `ndn-cert/approval.rs:290-312` |
| Status of unknown / expired record | `ndn-cert/approval.rs:431-460` |
| Listing order, pending filter, prune rule | `ndn-cert/approval.rs:462-510` |
| Opening / resuming a record; limits; request id drawn before the invite; invite redeemed after durable save | `ndn-cert/approval.rs:518-633` |
| Decision recording, final, expiry reset, wake STATUS | `ndn-cert/approval.rs:654-713` |
| Decision check order, evidence base64url | `ndn-cert/approval.rs:725-791` |
| PENDING authorization, then freshness (`check_listing_fresh`) | `ndn-cert/approval.rs:799-886` |
| RequestStatus JSON | `ndn-cert/approval.rs:919-936` |
| STATUS name, parse (n+3 components), hold | `ndn-cert/approval.rs:962-992` |
| Code / id lookup | `ndn-cert/approval.rs:1058-1091` |
| Decision name parse | `ndn-cert/approval.rs:1094-1107` |
| Walk validator, 6 supplied certs, depth 8 | `ndn-cert/approval.rs:1111-1132` |
| Admin Data validation, revocation | `ndn-cert/approval.rs:1134-1170` |
| Answer JSON enums; handlers; PENDING replay record; immediate STATUS (`status_now`); held-STATUS limits | `ndn-cert/approval.rs:1203-1324` |
| Answer when decided / deadline / stopping | `ndn-cert/approval.rs:1332-1385` |
| Decision Data construction | `ndn-cert/approval.rs:1389-1422` |
| Approver checks CA answer chain | `ndn-cert/approval.rs:1454-1479` |
| PENDING Interest (signed, MustBeFresh, chain params) | `ndn-cert/approval.rs:1490-1517` |
| APPROVAL Interest (unsigned, MustBeFresh) | `ndn-cert/approval.rs:1523-1552` |
| CA prefix from context | `ndn-cert/approval.rs:1565-1578` |
| Admin chain building, ≤ 6 | `ndn-cert/approval.rs:1586-1615` |
| Unsigned answers never final; `PolicyDenied` → name refused | `ndn-cert/approval.rs:1680-1706` |
| Poll: params, code check, expires | `ndn-cert/approval.rs:1717-1794` |
| STATUS Interest and answer checks | `ndn-cert/approval.rs:1807-1861` |
| Outgoing grace 86400 s, overdue | `ndn-cert/approval.rs:1882-1897` |
| Request id = 8 random bytes hex, RNG failure an error | `ndn-cert/approval.rs:2070-2076` |
| `device-approval` handler: params, record → response, pending parameters, attestation | `ndn-cert/challenge/device_approval.rs:26-231` |
| Invite needed beside approval (live check, redeem later) | `ndn-cert/challenge/device_approval.rs:72-112` |
| Renewal constants and proof message | `ndn-cert/renewal.rs:66-95` |
| Renewal CA prefix from KeyLocator | `ndn-cert/renewal.rs:102-111` |
| Renewal requester: params, same-name refusal | `ndn-cert/renewal.rs:217-334` |
| CA renewal verification | `ndn-cert/ca.rs:317-412` |
| Earlier-CA certificate path | `ndn-cert/ca.rs:425-517` |
| Proof algorithms (Ed25519, ECDSA) | `ndn-cert/ca.rs:1317-1331` |
| `issuers` parsing, ≤ 8 | `ndn-cert/ca.rs:1338-1366` |
| Offered challenges incl. `renewal` | `ndn-cert/ca.rs:291-305` |
| Session cleanup; 60 s window | `ndn-cert/ca.rs:217-221,669-756,1333-1334` |
| CHALLENGE handling, status/error mapping, unoffered or changed type → ErrorCode 4 | `ndn-cert/ca.rs:760-1003` |
| `refused()` helper | `ndn-cert/ca.rs:1410-1416` |
| Issued name `<key>/NDNCERT/v=` | `ndn-cert/ca.rs:1195-1224,1265-1276` |
| NDNCERT request id random bytes, RNG failure an error | `ndn-cert/ca.rs:1381-1385` |
| Response signer KeyLocator = CA cert name | `ndn-cert/ca.rs:612-617` |
| TLV numbers, parameter codec, plaintext, response encode / decode, status codes | `ndn-cert/tlv.rs:44-121,420-589` |
| NonNegativeInteger fields (1, 2, 4, 8 octets); failure answer `ErrorTlv` | `ndn-cert/tlv.rs:541-562,591-657` |
| ErrorCode values | `ndn-cert/protocol.rs:76-86` |
| CertError → ErrorCode / ErrorInfo (CA); ErrorCode → CertError (requester) | `ndn-cert/error.rs:46-126` (`ndncert_error_code`, `ndncert_error_info`, `from_ca_failure`) |
| Salt, IV and ids from the RNG (`fill_random`) | `ndn-cert/ecdh.rs:43-72` |
| Requester: cert request, request id hex, failure answers, status handling | `ndn-cert/client.rs:91-153,229-293` |
| Requester: run / one round / challenge name | `ndn-cert/client.rs:396-508` |
| Certificate fetch with ForwardingHint | `ndn-cert/client.rs:526-541` |
| Responses not validated; failure answer read (`refuse_if_failure`) | `ndn-cert/client.rs:614-634` |
| Producer dispatch by exact component, failure answers, Nacks, held and immediate STATUS | `ndn-rs/crates/security/ndn-identity/src/ca.rs:327-475` (`handle_interest`, `ca_endpoint`, `only_params_digest`, `answer_or_failure`) |
| Token grammar, malformed expiry, `now < until` | `ndn-cert/roles.rs:303-359` (`token_expiry`, `MalformedTokenExpiry`, `token_expired`) |
| Device-key parse, role names | `ndn-cert/roles.rs:67-101,259-301` |
| Schema rules `#approve`, `#deny`, `#pending` | `ndn-cert/roles.rs:414-422` |
| TokenStore: redemption hash, live, consume, scope | `ndn-cert/challenge/token.rs:88,107,228,246` (`token_hash`, `live_at`, `is_live`, `check_and_consume`) |
| `token` challenge | `ndn-cert/challenge/token.rs:296` (`impl ChallengeHandler for TokenChallenge`) |
| CA token loading rules (role scope, untagged → member, admin/node refused, `-until` second as expiry, malformed refused) | `ndn-cert/challenge/token.rs:170-206` (`TokenStore::add_invite_tokens`) |
| ApprovalPolicy, hint mapping, RolePolicy issuance | `ndn-cert/policy.rs:368,399,536` (`ApprovalPolicy`, `from_hint`, `impl IssuancePolicy for RolePolicy`) |
| CA enforces the advertised approval policy | `ndn-cert/ca_policy.rs:274-300` (`ApprovalPolicy::reconcile`) |
| Invite checks (expiry `token_expired`, malformed refused, role) | `ndn-cert/invite.rs:90-155` (`InviteLink::from_envelope`) |
| Token minting (16 bytes hex, `-until`) | `ndn-fwd/binaries/ndn-fwd-tokens/src/main.rs:140-142,184-187,247-255` |
| CA: TTL ≠ 0, namespace CA, policy from context | `ndn-fwd/binaries/ndn-fwd/src/ca.rs:99-201` |
| CA: challenge set, implied `device-approval`, invite requirement | `ndn-fwd/binaries/ndn-fwd/src/ca.rs:597-695` |
| Requester routing table, CA prefix choice | `ndn-rs/crates/security/ndn-namespace/src/enroll.rs:395-430` (`route`) |
| Opening and recording a request | `ndn-rs/crates/security/ndn-namespace/src/enroll.rs:626-731` (`enroll_by_approval`) |
| Status wait, retry 1→60 s, probing, deadline lifetimes (ndn-fwd and ndn-mobile) | `ndn-rs/crates/security/ndn-namespace/src/approval_wait.rs:44-45,137-292` (`wait_for_decision`) |
| Issue on approval | `ndn-rs/crates/security/ndn-namespace/src/approval_wait.rs:334-427` |
| Approver: admin credential selection, listing, local-first decide, remote push | `ndn-rs/crates/security/ndn-namespace/src/approver.rs:72-146,152-273` |
| URI form | `ndn-rs/crates/core/ndn-foundation-types/src/name.rs:539-638` |
| Public-key bytes (SPKI unwrap) | `ndn-rs/crates/security/ndn-security/src/cert_cache.rs:34-37`; `ndn-rs/crates/security/ndn-security/src/spki.rs:31-60` |
| Cert-request Content is SPKI | `ndn-rs/crates/security/ndn-security/src/manager.rs:556-565` |
| Signed Interest SignatureNonce / SignatureTime | `ndn-rs/crates/core/ndn-packet/src/encode/interest.rs:388-405` |
| Signature dispatch (public-key types only; MAC and digest types refused) | `ndn-rs/crates/security/ndn-security/src/verifier.rs:26-102` |
| Interest chain validation | `ndn-rs/crates/security/ndn-security/src/validator/chain.rs:183-232` |
| New key ids from the RNG, failure an error | `ndn-rs/crates/security/ndn-security/src/cert_name.rs:62-72` (`new_key_name`) |
| Local listing shows all records, remote only pending (Decision Q9) | `ndn-rs/crates/security/ndn-namespace/src/approver.rs:161`; `ndn-cert/approval.rs:1278-1280` |
