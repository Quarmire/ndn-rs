/// Minimal NDN TLV encoder/decoder for browser-based management.
///
/// Implements just enough TLV to encode Interest packets and decode
/// Data packets carrying ControlResponse payloads.

// ── TLV type constants ──────────────────────────────────────────────────────

export const Type = {
  // Packet types
  INTEREST:     0x05,
  DATA:         0x06,
  // Interest fields
  NAME:         0x07,
  NAME_COMPONENT: 0x08,
  NONCE:        0x0a,
  INTEREST_LIFETIME: 0x0c,
  CAN_BE_PREFIX: 0x21,
  MUST_BE_FRESH: 0x12,
  // Data fields
  META_INFO:    0x14,
  CONTENT:      0x15,
  SIGNATURE_INFO: 0x16,
  SIGNATURE_VALUE: 0x17,
  CONTENT_TYPE: 0x18,
  FRESHNESS_PERIOD: 0x19,
  // NDNLPv2
  LP_PACKET:    0x64,
  LP_FRAGMENT:  0x50,
  // Management
  CONTROL_RESPONSE: 0x65,
  STATUS_CODE:  0x66,
  STATUS_TEXT:  0x67,
  CONTROL_PARAMETERS: 0x68,
  FACE_ID:      0x69,
  COST:         0x6a,
  STRATEGY:     0x6b,
  FLAGS:        0x6c,
  ORIGIN:       0x6f,
  URI:          0x72,
  LOCAL_URI:    0x81,
  CAPACITY:     0x83,
  COUNT:        0x84,
  FACE_PERSISTENCY: 0x85,
};

// ── Encoder ─────────────────────────────────────────────────────────────────

export class TlvEncoder {
  constructor() {
    this.parts = [];
  }

  /** Write a VarNumber (type or length). */
  writeVarNum(n) {
    if (n < 253) {
      this.parts.push(new Uint8Array([n]));
    } else if (n <= 0xffff) {
      const b = new Uint8Array(3);
      b[0] = 253;
      b[1] = (n >> 8) & 0xff;
      b[2] = n & 0xff;
      this.parts.push(b);
    } else if (n <= 0xffffffff) {
      const b = new Uint8Array(5);
      b[0] = 254;
      b[1] = (n >> 24) & 0xff;
      b[2] = (n >> 16) & 0xff;
      b[3] = (n >> 8) & 0xff;
      b[4] = n & 0xff;
      this.parts.push(b);
    } else {
      throw new Error(`VarNumber too large: ${n}`);
    }
  }

  /** Write raw bytes. */
  writeBytes(data) {
    if (data instanceof Uint8Array) {
      this.parts.push(data);
    } else if (typeof data === 'string') {
      this.parts.push(new TextEncoder().encode(data));
    } else {
      this.parts.push(new Uint8Array(data));
    }
  }

  /** Write a NonNegativeInteger in shortest big-endian form. */
  writeNonNegInt(n) {
    if (n <= 0xff) {
      this.parts.push(new Uint8Array([n]));
    } else if (n <= 0xffff) {
      this.parts.push(new Uint8Array([(n >> 8) & 0xff, n & 0xff]));
    } else if (n <= 0xffffffff) {
      this.parts.push(new Uint8Array([
        (n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff,
      ]));
    } else {
      const hi = Math.floor(n / 0x100000000);
      const lo = n >>> 0;
      this.parts.push(new Uint8Array([
        (hi >> 24) & 0xff, (hi >> 16) & 0xff, (hi >> 8) & 0xff, hi & 0xff,
        (lo >> 24) & 0xff, (lo >> 16) & 0xff, (lo >> 8) & 0xff, lo & 0xff,
      ]));
    }
  }

  /** Write a TLV element: type, length, value. */
  writeTlv(type_, value) {
    const valueBytes = value instanceof Uint8Array ? value : new TextEncoder().encode(value);
    this.writeVarNum(type_);
    this.writeVarNum(valueBytes.length);
    this.parts.push(valueBytes);
  }

  /** Write a TLV with NonNegativeInteger value. */
  writeTlvInt(type_, n) {
    const enc = new TlvEncoder();
    enc.writeNonNegInt(n);
    this.writeTlv(type_, enc.toBytes());
  }

  /** Write a nested TLV using a builder callback. */
  writeNested(type_, fn_) {
    const inner = new TlvEncoder();
    fn_(inner);
    this.writeTlv(type_, inner.toBytes());
  }

  /** Concatenate all parts into a single Uint8Array. */
  toBytes() {
    let totalLen = 0;
    for (const p of this.parts) totalLen += p.length;
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const p of this.parts) {
      result.set(p, offset);
      offset += p.length;
    }
    return result;
  }
}

// ── Decoder ─────────────────────────────────────────────────────────────────

export class TlvDecoder {
  constructor(data) {
    this.data = data instanceof Uint8Array ? data : new Uint8Array(data);
    this.offset = 0;
  }

  get remaining() { return this.data.length - this.offset; }
  get eof() { return this.offset >= this.data.length; }

  /** Read a VarNumber. */
  readVarNum() {
    const first = this.data[this.offset++];
    if (first < 253) return first;
    if (first === 253) {
      const v = (this.data[this.offset] << 8) | this.data[this.offset + 1];
      this.offset += 2;
      return v;
    }
    if (first === 254) {
      const v = (this.data[this.offset] << 24) | (this.data[this.offset+1] << 16) |
                (this.data[this.offset+2] << 8) | this.data[this.offset+3];
      this.offset += 4;
      return v >>> 0;
    }
    throw new Error('8-byte VarNumber not supported in JS');
  }

  /** Read a NonNegativeInteger of `len` bytes. */
  readNonNegInt(len) {
    let v = 0;
    for (let i = 0; i < len; i++) {
      v = v * 256 + this.data[this.offset++];
    }
    return v;
  }

  /** Read the next TLV element, returning { type, length, value, valueOffset }. */
  readTlv() {
    const type_ = this.readVarNum();
    const length = this.readVarNum();
    const valueOffset = this.offset;
    const value = this.data.slice(this.offset, this.offset + length);
    this.offset += length;
    return { type: type_, length, value, valueOffset };
  }

  /** Peek at the next TLV type without consuming. */
  peekType() {
    const saved = this.offset;
    const type_ = this.readVarNum();
    this.offset = saved;
    return type_;
  }
}

// ── Convenience functions ───────────────────────────────────────────────────

/** Decode a Name from TLV bytes (expects outer type 0x07). */
export function decodeName(bytes) {
  const dec = new TlvDecoder(bytes);
  const tlv = dec.readTlv();
  if (tlv.type !== Type.NAME) throw new Error(`Expected Name (0x07), got 0x${tlv.type.toString(16)}`);
  const components = [];
  const inner = new TlvDecoder(tlv.value);
  while (!inner.eof) {
    const comp = inner.readTlv();
    components.push(new TextDecoder().decode(comp.value));
  }
  return '/' + components.join('/');
}

/** Decode a Name from raw component TLV bytes (no outer Name TLV). */
export function decodeNameComponents(bytes) {
  const components = [];
  const dec = new TlvDecoder(bytes);
  while (!dec.eof) {
    const comp = dec.readTlv();
    components.push(new TextDecoder().decode(comp.value));
  }
  return '/' + components.join('/');
}

/** Encode an NDN name string like "/localhost/nfd/faces/list" to TLV bytes. */
export function encodeName(nameStr) {
  const parts = nameStr.split('/').filter(Boolean);
  const enc = new TlvEncoder();
  enc.writeNested(Type.NAME, (w) => {
    for (const part of parts) {
      w.writeTlv(Type.NAME_COMPONENT, part);
    }
  });
  return enc.toBytes();
}
