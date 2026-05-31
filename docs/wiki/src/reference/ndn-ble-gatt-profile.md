# NDN over Bluetooth LE — GATT profile

**Status:** Draft / experimental. This page documents the GATT profile and
framing rules ndn-rs implements, written normatively so other implementations
can interoperate. The ndn-rs implementation has not been validated on
hardware against a second implementation; treat the conformance language as the
*intended* contract, not a proven one.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted
as in RFC 2119.

## 1. Scope

This profile carries NDN packets (Interest, Data, Nack) between two peers over a
single BLE GATT connection. One peer is the GATT **server** (NDN peripheral),
the other the GATT **client** (NDN central). It reuses the service and
characteristic UUIDs established by NDNts `@ndn/web-bluetooth-transport` and
`esp8266ndn`, and adds an optional capability characteristic and a framing
self-negotiation procedure so the two historical framings interoperate.

## 2. GATT service

A conformant peripheral MUST expose one primary GATT service:

| Element | UUID | Properties |
|---|---|---|
| NDN service | `099577e3-0788-412a-8824-395084d97391` | primary |
| **CS** — client→server | `cc5abb89-a541-46d8-a351-2f95a6a81f49` | Write Without Response |
| **SC** — server→client | `972f9527-0d83-4261-b95d-b1b2fc73bde4` | Notify |
| **Framing capability** (optional) | `099577e3-0788-412a-8824-395084d97392` | Read |

- The central writes outbound packets to **CS** (Write Without Response).
- The central subscribes to **SC** notifications for inbound packets.
- The peripheral MUST advertise the service UUID so a central can filter on it.

The central role is reachable from a Web Bluetooth browser; the peripheral role
is not (the Web Bluetooth API exposes no GATT-server surface).

## 3. Framings

Each ATT write/notification carries one *frame*. Two framings are defined; they
share the same UUIDs and are distinguished by the first octet of the frame.

### 3.1 NDNLPv2 (framing id `0x01`)

Each frame is exactly one NDNLPv2 `LpPacket` (TLV-TYPE `0x64` = 100), as defined
by the NDN Link Protocol v2. A frame therefore begins with the octet `0x64`.
Packets larger than the link MTU are carried as multiple `LpPacket` fragments
with `Sequence`/`FragIndex`/`FragCount`; reassembly is the NDNLPv2 reassembly
buffer's responsibility. This framing carries the full NDNLPv2 feature set
(Nack, PIT token, congestion marks, per-hop reliability).

### 3.2 NDNts 1-byte header (framing id `0x02`)

A lightweight fragmentation used by NDNts `@ndn/web-bluetooth-transport` and
`esp8266ndn`:

- A packet that fits in one frame is sent **bare**, with **no** header octet —
  i.e. the frame begins with the packet's own TLV-TYPE (`0x05` Interest,
  `0x06` Data, …).
- A fragmented packet prepends a 1-octet header to each fragment:
  - first fragment: `0x80 | (seq & 0x7F)`
  - continuation fragments: `seq & 0x7F`
  - `seq` starts at 0 and increments modulo 128 per fragment.
- The receiver concatenates fragment payloads starting at a first-fragment
  header until the buffered bytes form a complete TLV (TLV-TYPE + TLV-LENGTH +
  value). This framing carries no NDNLPv2 fields.

### 3.3 First-octet disambiguation

A receiver MAY infer the framing of a connection from the first frame:

| First octet | Framing |
|---|---|
| `0x64` | NDNLPv2 |
| `0x80`–`0xFF` | NDNts (first fragment) |
| any other (`0x05`, `0x06`, …) | NDNts (bare packet) |

This is unambiguous for the first frame of a connection. The value `0x64` can
recur as an NDNts continuation header (`seq == 100`), but only mid-stream after
a first fragment, by which point the framing is already latched.

## 4. Fragmentation and MTU

The usable frame payload is the negotiated ATT_MTU minus 3 (ATT opcode +
handle). The default 23-octet ATT_MTU is too small for practical NDN packets;
implementations SHOULD negotiate an ATT_MTU of at least 185. A sender MUST NOT
emit a frame larger than the usable payload; it MUST fragment per the framing in
use (§3). Where the negotiated MTU is not exposed to the sender (e.g. Web
Bluetooth), the sender SHOULD fragment at a conservative payload of 244 octets.

## 5. Framing negotiation

The two framings are not wire-compatible. Peers select one per connection
without manual configuration as follows.

### 5.1 Peripheral (responder)

A peripheral MUST be able to receive either framing. On the first inbound CS
write of a connection it SHOULD detect the framing per §3.3, latch it for that
central, and use the **same** framing for all SC notifications to that central
("mirror"). A peripheral serving multiple centrals MUST track framing per
central.

### 5.2 Central (initiator)

A central speaks first and therefore cannot detect the peer's framing from
traffic. It SHOULD determine the framing as follows:

1. If the application forced a framing, use it.
2. Otherwise, after connecting, attempt to read the **framing capability**
   characteristic (§2):
   - If present, interpret its first octet as a framing id (§3) and use that
     framing.
   - If **absent** (characteristic not found), the peer is a legacy peer that
     predates this characteristic; the central MUST assume **NDNts** (`0x02`).
   - If present but unreadable, the central SHOULD assume **NDNLPv2** (`0x01`).

Because only peers implementing this profile expose the capability
characteristic, its absence is a reliable signal for the NDNts framing across
the deployed ecosystem; no probing or dual transmission is required.

### 5.3 Framing capability characteristic

A peer that prefers NDNLPv2 SHOULD expose the framing capability characteristic
as a read-only characteristic whose value is a single octet equal to its
preferred framing id (`0x01` for NDNLPv2). A static cached value is sufficient;
no dynamic read handler is required. Peers implementing only the NDNts framing
MAY omit it.

## 6. Conformance

- A peripheral MUST expose the service with the CS and SC characteristics
  (§2), MUST accept either framing (§5.1), and SHOULD expose the framing
  capability characteristic when it prefers NDNLPv2.
- A central MUST write to CS and subscribe to SC, and SHOULD follow §5.2 to
  select a framing.
- An implementation supporting only the NDNts framing remains conformant for
  interop with NDNts/esp8266ndn peers; it simply omits the capability
  characteristic and the NDNLPv2 framing.

## 7. Interoperability notes

- The service/characteristic UUIDs and the NDNts 1-byte framing are taken from
  NDNts `@ndn/web-bluetooth-transport` and `esp8266ndn`'s `BleServerTransport`;
  this profile is backward compatible with them (they appear as NDNts-framing
  peers that omit the capability characteristic).
- The framing capability characteristic and the NDNLPv2 framing on this profile
  are ndn-rs additions proposed here for standardization.

## 8. ndn-rs implementation

| Element | Location |
|---|---|
| Profile constants, listener, per-central faces | `crates/ndn-face-native/src/l2/bluetooth/` |
| Framing codec + detection | `crates/ndn-face-native/src/l2/bluetooth/framing.rs` |
| Native central (Linux `bluer`, macOS/Windows `btleplug`) | `…/bluetooth/central/` |
| Browser central (Web Bluetooth) | `crates/ndn-face-webble/` |

See [Face transports → Bluetooth LE](./face-transports.md#bluetooth-le) for the
operator-facing `ble://` / `[listeners.ble]` surface.
