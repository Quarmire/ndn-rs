/// NDN management client over WebSocket.
///
/// Connects to an ndn-router's WebSocket face, sends NFD management
/// Interest packets, and decodes Data responses.

import { TlvEncoder, TlvDecoder, Type, encodeName, decodeName, decodeNameComponents } from './tlv.js';

export class NdnClient {
  constructor() {
    this.ws = null;
    this.connected = false;
    this.pending = new Map(); // nonce -> { resolve, reject, timer }
    this.onStatusChange = null; // callback(connected: bool)
    this._reconnectTimer = null;
    this._url = null;
  }

  /** Connect to the router's WebSocket face. */
  connect(url = 'ws://localhost:9696') {
    this._url = url;
    this._doConnect();
  }

  _doConnect() {
    if (this.ws) {
      try { this.ws.close(); } catch (_) {}
    }

    this.ws = new WebSocket(this._url);
    this.ws.binaryType = 'arraybuffer';

    this.ws.onopen = () => {
      this.connected = true;
      if (this.onStatusChange) this.onStatusChange(true);
    };

    this.ws.onclose = () => {
      this.connected = false;
      if (this.onStatusChange) this.onStatusChange(false);
      // Reject all pending requests
      for (const [nonce, entry] of this.pending) {
        clearTimeout(entry.timer);
        entry.reject(new Error('WebSocket closed'));
      }
      this.pending.clear();
      // Auto-reconnect after delay
      this._reconnectTimer = setTimeout(() => this._doConnect(), 3000);
    };

    this.ws.onerror = () => {
      // onclose will fire after onerror
    };

    this.ws.onmessage = (event) => {
      this._handleMessage(new Uint8Array(event.data));
    };
  }

  disconnect() {
    clearTimeout(this._reconnectTimer);
    if (this.ws) this.ws.close();
    this.ws = null;
    this.connected = false;
  }

  /** Send a management command and wait for the response. */
  async command(module, verb, params = {}) {
    const nonce = crypto.getRandomValues(new Uint8Array(4));
    const nonceValue = new DataView(nonce.buffer).getUint32(0);
    const nameStr = `/localhost/nfd/${module}/${verb}`;
    const interest = this._encodeInterest(nameStr, params, nonce);

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(nonceValue);
        reject(new Error(`Timeout: ${module}/${verb}`));
      }, 5000);

      this.pending.set(nonceValue, { resolve, reject, timer, nameStr });
      this.ws.send(interest);
    });
  }

  /** Shortcut for common commands. */
  async listFaces() { return this.command('faces', 'list'); }
  async listFib() { return this.command('fib', 'list'); }
  async listRib() { return this.command('rib', 'list'); }
  async listStrategy() { return this.command('strategy-choice', 'list'); }
  async csInfo() { return this.command('cs', 'info'); }
  async statusGeneral() { return this.command('status', 'general'); }
  async listNeighbors() { return this.command('neighbors', 'list'); }
  async listServices() { return this.command('service', 'list'); }
  async browseServices() { return this.command('service', 'browse'); }

  async addRoute(prefix, faceId, cost = 0) {
    return this.command('rib', 'register', { name: prefix, face_id: faceId, cost });
  }

  async removeRoute(prefix, faceId) {
    return this.command('rib', 'unregister', { name: prefix, face_id: faceId });
  }

  async createFace(uri) {
    return this.command('faces', 'create', { uri });
  }

  async destroyFace(faceId) {
    return this.command('faces', 'destroy', { face_id: faceId });
  }

  async setStrategy(prefix, strategy) {
    return this.command('strategy-choice', 'set', { name: prefix, strategy });
  }

  // ── Internal ────────────────────────────────────────────────────────────────

  _encodeInterest(nameStr, params, nonce) {
    const enc = new TlvEncoder();
    enc.writeNested(Type.INTEREST, (w) => {
      // Name: /localhost/nfd/<module>/<verb>[/<params-component>]
      const parts = nameStr.split('/').filter(Boolean);
      w.writeNested(Type.NAME, (n) => {
        for (const part of parts) {
          n.writeTlv(Type.NAME_COMPONENT, part);
        }
        // Encode control parameters as a name component (value only)
        const paramBytes = this._encodeParams(params);
        if (paramBytes.length > 0) {
          n.writeTlv(Type.NAME_COMPONENT, paramBytes);
        }
      });
      // CanBePrefix (so response name can differ)
      w.writeTlv(Type.CAN_BE_PREFIX, new Uint8Array(0));
      // MustBeFresh
      w.writeTlv(Type.MUST_BE_FRESH, new Uint8Array(0));
      // Nonce
      w.writeTlv(Type.NONCE, nonce);
      // InterestLifetime (5 seconds)
      w.writeTlvInt(Type.INTEREST_LIFETIME, 5000);
    });
    return enc.toBytes();
  }

  _encodeParams(params) {
    if (!params || Object.keys(params).length === 0) return new Uint8Array(0);
    const enc = new TlvEncoder();
    if (params.name) {
      // Encode name as inner TLV
      const nameBytes = encodeName(params.name);
      enc.writeBytes(nameBytes);
    }
    if (params.face_id !== undefined) enc.writeTlvInt(Type.FACE_ID, params.face_id);
    if (params.uri) enc.writeTlv(Type.URI, params.uri);
    if (params.local_uri) enc.writeTlv(Type.LOCAL_URI, params.local_uri);
    if (params.origin !== undefined) enc.writeTlvInt(0x6f, params.origin);
    if (params.cost !== undefined) enc.writeTlvInt(Type.COST, params.cost);
    if (params.flags !== undefined) enc.writeTlvInt(Type.FLAGS, params.flags);
    if (params.capacity !== undefined) enc.writeTlvInt(Type.CAPACITY, params.capacity);
    if (params.strategy) {
      const stratBytes = encodeName(params.strategy);
      enc.writeTlv(Type.STRATEGY, stratBytes);
    }
    return enc.toBytes();
  }

  _handleMessage(data) {
    try {
      const dec = new TlvDecoder(data);
      let pkt = dec.readTlv();

      // Unwrap NDNLPv2 LpPacket (0x64) to get the inner Data
      if (pkt.type === Type.LP_PACKET) {
        const lpDec = new TlvDecoder(pkt.value);
        while (!lpDec.eof) {
          const field = lpDec.readTlv();
          if (field.type === Type.LP_FRAGMENT) {
            // Fragment contains the actual packet
            const innerDec = new TlvDecoder(field.value);
            pkt = innerDec.readTlv();
            break;
          }
        }
      }

      if (pkt.type !== Type.DATA) return; // Only process Data packets

      const response = this._decodeData(pkt.value);
      if (!response) return;

      // Match against pending requests by name prefix
      // Since we can't match by nonce in Data, match by the oldest pending request
      // (management is request-response, so this works for sequential commands)
      if (this.pending.size > 0) {
        const [nonce, entry] = this.pending.entries().next().value;
        this.pending.delete(nonce);
        clearTimeout(entry.timer);
        entry.resolve(response);
      }
    } catch (e) {
      console.warn('NDN decode error:', e);
    }
  }

  _decodeData(dataValue) {
    const dec = new TlvDecoder(dataValue);
    let name = null;
    let content = null;

    while (!dec.eof) {
      const tlv = dec.readTlv();
      switch (tlv.type) {
        case Type.NAME:
          name = decodeNameComponents(tlv.value);
          break;
        case Type.CONTENT:
          content = tlv.value;
          break;
      }
    }

    if (!content || content.length === 0) {
      return { name, statusCode: 200, statusText: '', body: null, raw: '' };
    }

    // Try to parse as ControlResponse
    try {
      return this._decodeControlResponse(content, name);
    } catch (_) {
      // Not a ControlResponse — return raw text
      return { name, statusCode: 200, statusText: new TextDecoder().decode(content), body: null, raw: new TextDecoder().decode(content) };
    }
  }

  _decodeControlResponse(bytes, name) {
    const dec = new TlvDecoder(bytes);
    const outer = dec.readTlv();
    if (outer.type !== Type.CONTROL_RESPONSE) {
      // Might be raw text response
      return {
        name,
        statusCode: 200,
        statusText: new TextDecoder().decode(bytes),
        body: null,
        raw: new TextDecoder().decode(bytes),
      };
    }

    const inner = new TlvDecoder(outer.value);
    let statusCode = 0;
    let statusText = '';
    let body = null;

    while (!inner.eof) {
      const tlv = inner.readTlv();
      switch (tlv.type) {
        case Type.STATUS_CODE:
          statusCode = new TlvDecoder(tlv.value).readNonNegInt(tlv.value.length);
          break;
        case Type.STATUS_TEXT:
          statusText = new TextDecoder().decode(tlv.value);
          break;
        case Type.CONTROL_PARAMETERS:
          body = this._decodeControlParams(tlv.value);
          break;
      }
    }

    return { name, statusCode, statusText, body, raw: statusText };
  }

  _decodeControlParams(bytes) {
    const dec = new TlvDecoder(bytes);
    const params = {};

    while (!dec.eof) {
      const tlv = dec.readTlv();
      switch (tlv.type) {
        case Type.NAME:
          params.name = decodeNameComponents(tlv.value);
          break;
        case Type.FACE_ID:
          params.face_id = new TlvDecoder(tlv.value).readNonNegInt(tlv.value.length);
          break;
        case Type.COST:
          params.cost = new TlvDecoder(tlv.value).readNonNegInt(tlv.value.length);
          break;
        case Type.URI:
          params.uri = new TextDecoder().decode(tlv.value);
          break;
        case Type.LOCAL_URI:
          params.local_uri = new TextDecoder().decode(tlv.value);
          break;
        case Type.ORIGIN:
          params.origin = new TlvDecoder(tlv.value).readNonNegInt(tlv.value.length);
          break;
        case Type.FLAGS:
          params.flags = new TlvDecoder(tlv.value).readNonNegInt(tlv.value.length);
          break;
        case Type.CAPACITY:
          params.capacity = new TlvDecoder(tlv.value).readNonNegInt(tlv.value.length);
          break;
        case Type.COUNT:
          params.count = new TlvDecoder(tlv.value).readNonNegInt(tlv.value.length);
          break;
        case Type.FACE_PERSISTENCY:
          params.face_persistency = new TlvDecoder(tlv.value).readNonNegInt(tlv.value.length);
          break;
        case Type.STRATEGY:
          params.strategy = decodeNameComponents(tlv.value);
          break;
      }
    }

    return params;
  }
}
