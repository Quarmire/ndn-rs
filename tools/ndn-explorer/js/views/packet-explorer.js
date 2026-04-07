// @ts-check
import { wasmMod, adaptWasmTlvTree } from '../wasm-types.js';

/**
 * Packet Explorer view — TLV encoder and inspector for NDN packets.
 *
 * Encoder tab: build Interest / Data packets from form fields and see the
 *              NDN wire format (TLV hex) with byte count.
 * Inspector tab: paste any hex byte string, parse it into an interactive
 *               Wireshark-style TLV tree with mutual hover highlighting
 *               between the hex dump and the field tree.
 */

// ── TLV type metadata ─────────────────────────────────────────────────────────

/** @type {Record<number, string>} */
const TYPE_NAMES = {
  0x05: 'Interest',          0x06: 'Data',
  0x07: 'Name',              0x08: 'GenericNameComponent',
  0x01: 'ImplicitSha256DigestComponent',
  0x02: 'ParametersSha256DigestComponent',
  0x21: 'CanBePrefix',       0x12: 'MustBeFresh',
  0x1e: 'ForwardingHint',    0x0a: 'Nonce',
  0x0c: 'InterestLifetime',  0x22: 'HopLimit',
  0x24: 'ApplicationParameters',
  0x14: 'MetaInfo',          0x15: 'Content',
  0x16: 'SignatureInfo',     0x17: 'SignatureValue',
  0x18: 'ContentType',       0x19: 'FreshnessPeriod',
  0x1a: 'FinalBlockId',      0x1b: 'SignatureType',
  0x1c: 'KeyLocator',        0x1d: 'KeyDigest',
  0x26: 'SignatureNonce',    0x28: 'SignatureTime',
  0x2a: 'SignatureSeqNum',
  0x2c: 'InterestSignatureInfo',
  0x2e: 'InterestSignatureValue',
  0x0320: 'Nack',            0x0321: 'NackReason',
  0x64: 'LpPacket',          0x50: 'LpFragment',
  0x62: 'LpPitToken',
};

/**
 * Short category name for color coding.
 * @type {Record<number, string>}
 */
const TYPE_CAT = {
  0x05: 'interest', 0x06: 'data',
  0x07: 'name',  0x08: 'name', 0x01: 'name', 0x02: 'name',
  0x14: 'meta',  0x18: 'meta', 0x19: 'meta', 0x1a: 'meta',
  0x15: 'content',
  0x16: 'sig',   0x17: 'sig',  0x1b: 'sig',  0x1c: 'sig',
  0x1d: 'sig',   0x26: 'sig',  0x28: 'sig',  0x2a: 'sig',
  0x2c: 'sig',   0x2e: 'sig',
  0x0a: 'nonce', 0x0c: 'lifetime',
  0x12: 'flag',  0x21: 'flag',
  0x64: 'lp',    0x50: 'lp',   0x62: 'lp',
};

/** TLV types that contain nested TLV fields. */
const CONTAINER_TYPES = new Set([0x05, 0x06, 0x07, 0x14, 0x16, 0x1e, 0x2c, 0x0320, 0x64]);

// ── TLV codec (pure JS) ───────────────────────────────────────────────────────

/**
 * @typedef {Object} TlvNode
 * @property {number}   typ
 * @property {string}   typeName
 * @property {number}   length    - value length in bytes
 * @property {number}   startByte - offset of T field in parent buffer
 * @property {number}   endByte   - offset just past last V byte
 * @property {string}   valueHex  - space-separated lowercase hex of V bytes
 * @property {string|null} valueText - UTF-8 text if all bytes are printable ASCII
 * @property {TlvNode[]} children
 */

/** @param {number} v @returns {Uint8Array} */
function encVli(v) {
  if (v < 0xFD) return new Uint8Array([v]);
  if (v < 0x10000) return new Uint8Array([0xFD, v >> 8, v & 0xFF]);
  if (v < 0x100000000) {
    return new Uint8Array([0xFE, (v >>> 24) & 0xFF, (v >>> 16) & 0xFF, (v >>> 8) & 0xFF, v & 0xFF]);
  }
  throw new RangeError('VLI value exceeds 32 bits');
}

/** @param {...Uint8Array} arrays @returns {Uint8Array} */
function cat(...arrays) {
  const len = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

/** @param {number} type @param {Uint8Array} value @returns {Uint8Array} */
function encTlv(type, value) {
  return cat(encVli(type), encVli(value.length), value);
}

/** @param {number} v @returns {Uint8Array} */
function encNNI(v) {
  if (v <= 0xFF) return new Uint8Array([v]);
  if (v <= 0xFFFF) return new Uint8Array([v >> 8, v & 0xFF]);
  if (v <= 0xFFFFFFFF) {
    return new Uint8Array([(v >>> 24) & 0xFF, (v >>> 16) & 0xFF, (v >>> 8) & 0xFF, v & 0xFF]);
  }
  throw new RangeError('NNI value too large');
}

/** @param {string} name @returns {Uint8Array} */
function encName(name) {
  const enc = new TextEncoder();
  const comps = name.split('/').filter(Boolean);
  return encTlv(0x07, cat(...comps.map(c => encTlv(0x08, enc.encode(c)))));
}

/**
 * @param {{name:string, canBePrefix?:boolean, mustBeFresh?:boolean, lifetimeMs?:number}} opts
 * @returns {Uint8Array}
 */
function encodeInterest(opts) {
  const nonce = new Uint8Array(4);
  crypto.getRandomValues(nonce);
  const parts = [encName(opts.name)];
  if (opts.canBePrefix) parts.push(encTlv(0x21, new Uint8Array(0)));
  if (opts.mustBeFresh) parts.push(encTlv(0x12, new Uint8Array(0)));
  parts.push(encTlv(0x0a, nonce));
  const lt = opts.lifetimeMs ?? 4000;
  if (lt !== 4000) parts.push(encTlv(0x0c, encNNI(lt)));
  return encTlv(0x05, cat(...parts));
}

/**
 * @param {{name:string, content?:string, freshnessMs?:number}} opts
 * @returns {Uint8Array}
 */
function encodeData(opts) {
  const nameField  = encName(opts.name);
  const metaBody   = (opts.freshnessMs ?? 0) > 0
    ? encTlv(0x19, encNNI(opts.freshnessMs ?? 0)) : new Uint8Array(0);
  const metaInfo   = encTlv(0x14, metaBody);
  const content    = encTlv(0x15, opts.content
    ? new TextEncoder().encode(opts.content) : new Uint8Array(0));
  const sigInfo    = encTlv(0x16, encTlv(0x1b, encNNI(0))); // DigestSha256
  const sigVal     = encTlv(0x17, new Uint8Array(32).fill(0xAA));
  return encTlv(0x06, cat(nameField, metaInfo, content, sigInfo, sigVal));
}

/**
 * Decode a VLI from buf at pos.
 * @param {Uint8Array} buf @param {number} pos
 * @returns {{value:number, size:number}|null}
 */
function decVli(buf, pos) {
  if (pos >= buf.length) return null;
  const f = buf[pos];
  if (f === 0xFD) {
    if (pos + 3 > buf.length) return null;
    return { value: (buf[pos + 1] << 8) | buf[pos + 2], size: 3 };
  }
  if (f === 0xFE) {
    if (pos + 5 > buf.length) return null;
    return {
      value: buf[pos+1] * 0x1000000 + ((buf[pos+2] << 16) | (buf[pos+3] << 8) | buf[pos+4]),
      size: 5,
    };
  }
  if (f === 0xFF) return null; // >4 GB not supported
  return { value: f, size: 1 };
}

/**
 * @param {Uint8Array} buf @param {number} start @param {number} end
 * @returns {TlvNode[]}
 */
function decRange(buf, start, end) {
  /** @type {TlvNode[]} */
  const nodes = [];
  let pos = start;
  while (pos < end) {
    const tv = decVli(buf, pos); if (!tv) break;
    const typeStart = pos; pos += tv.size;
    const lv = decVli(buf, pos); if (!lv) break;
    pos += lv.size;
    const valStart = pos;
    const valEnd   = pos + lv.value;
    if (valEnd > buf.length) break;

    const vb       = buf.subarray(valStart, valEnd);
    const valueHex = Array.from(vb).map(b => b.toString(16).padStart(2, '0')).join(' ');
    const valueText = (vb.length > 0 && vb.every(b => b >= 32 && b < 127))
      ? new TextDecoder().decode(vb) : null;

    nodes.push({
      typ: tv.value,
      typeName: TYPE_NAMES[tv.value] ?? 'Unknown',
      length: lv.value,
      startByte: typeStart,
      endByte: valEnd,
      valueHex,
      valueText,
      children: CONTAINER_TYPES.has(tv.value) ? decRange(buf, valStart, valEnd) : [],
    });
    pos = valEnd;
  }
  return nodes;
}

/** @param {Uint8Array} buf @returns {TlvNode[]} */
const decodeTlv = buf => decRange(buf, 0, buf.length);

/**
 * DFS pre-order flatten — parents precede their children.
 * Iterating in reverse gives deepest (most specific) nodes first.
 * @param {TlvNode[]} nodes @param {TlvNode[]} [out] @returns {TlvNode[]}
 */
function flatten(nodes, out = []) {
  for (const n of nodes) { out.push(n); flatten(n.children, out); }
  return out;
}

/**
 * Find the deepest node containing byte offset `off`.
 * @param {TlvNode[]} flat @param {number} off @returns {TlvNode|null}
 */
function deepestAt(flat, off) {
  let found = null;
  for (const n of flat) {
    if (n.startByte <= off && off < n.endByte) found = n; // last match = deepest
  }
  return found;
}

/**
 * Parse a hex string (spaces, colons, or continuous) into bytes.
 * @param {string} hex @returns {Uint8Array|null}
 */
function parseHex(hex) {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  if (clean.length % 2 !== 0) return null;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** @param {Uint8Array} buf @returns {string} uppercase space-separated hex */
const toHex = buf => Array.from(buf).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');

// ── Pre-built example packets ─────────────────────────────────────────────────

function makeExamples() {
  return {
    interest: encodeInterest({ name: '/ndn/edu/demo/video', lifetimeMs: 4000 }),
    data:     encodeData({ name: '/ndn/edu/demo/video', content: 'Hello NDN!', freshnessMs: 10000 }),
    lp: (() => {
      // Minimal LpPacket wrapping an Interest fragment
      const inner = encodeInterest({ name: '/ndn/test' });
      return encTlv(0x64, cat(encTlv(0x50, inner)));
    })(),
  };
}

// ── PacketExplorer view ───────────────────────────────────────────────────────

export class PacketExplorer {
  /**
   * @param {HTMLElement} container
   * @param {object} app
   */
  constructor(container, app) {
    this.container = container;
    this.app = app;

    /** @type {'encoder'|'inspector'} */
    this.activeTab = 'encoder';

    // Encoder state
    /** @type {'interest'|'data'} */
    this.encType = 'interest';
    this.encOpts = {
      name: '/ndn/edu/demo/video',
      canBePrefix: false, mustBeFresh: false, lifetimeMs: 4000,
      content: '', freshnessMs: 0,
    };
    /** @type {Uint8Array|null} */
    this.encBytes = null;

    // Inspector state
    /** @type {Uint8Array|null} */
    this.inspBytes = null;
    /** @type {TlvNode[]} */
    this.inspFlat = [];
  }

  /** Lazy-render on first navigation to this tab. */
  onShow() {
    if (!this.container.firstChild) this.render();
  }

  render() {
    this.container.innerHTML = `
      <h1 style="margin-bottom:0.4rem">Packet Explorer</h1>
      <p style="color:var(--text2);font-size:0.85rem;margin-bottom:1.1rem">
        <strong>Encoder</strong>: build NDN packets and inspect their wire format.
        <strong>Inspector</strong>: paste any hex byte string and explore the TLV field tree.
        Hover over hex bytes or tree nodes to highlight the corresponding field.
      </p>
      <div class="pex-tabs">
        <button class="pex-tab-btn ${this.activeTab === 'encoder' ? 'active' : ''}"
                data-tab="encoder">Encoder</button>
        <button class="pex-tab-btn ${this.activeTab === 'inspector' ? 'active' : ''}"
                data-tab="inspector">Inspector</button>
      </div>
      <div id="pex-encoder"   class="pex-tab-pane" ${this.activeTab !== 'encoder'   ? 'style="display:none"' : ''}>
        ${this._renderEncoder()}
      </div>
      <div id="pex-inspector" class="pex-tab-pane" ${this.activeTab !== 'inspector' ? 'style="display:none"' : ''}>
        ${this._renderInspector()}
      </div>`;

    this._wireTabButtons();
    this._wireEncoderEvents();
    this._wireInspectorEvents();
  }

  // ── Tab switching ────────────────────────────────────────────────────────

  /** @param {'encoder'|'inspector'} tab */
  _switchTab(tab) {
    this.activeTab = tab;
    this.container.querySelectorAll('.pex-tab-btn').forEach(btn => {
      btn.classList.toggle('active', /** @type {HTMLElement} */ (btn).dataset.tab === tab);
    });
    this.container.querySelectorAll('.pex-tab-pane').forEach(pane => {
      /** @type {HTMLElement} */ (pane).style.display =
        pane.id === `pex-${tab}` ? '' : 'none';
    });
  }

  _wireTabButtons() {
    this.container.querySelectorAll('.pex-tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        this._switchTab(/** @type {'encoder'|'inspector'} */ (
          /** @type {HTMLElement} */ (btn).dataset.tab ?? 'encoder'));
      });
    });
  }

  // ── Encoder ──────────────────────────────────────────────────────────────

  _renderEncoder() {
    return `
      <div class="pex-enc-layout">
        <div class="pipeline-panel">
          <div class="panel-title">Packet Type</div>
          <div class="composer-type-row" style="margin-bottom:0.75rem">
            <label class="radio-label">
              <input type="radio" name="enc-type" value="interest"
                ${this.encType === 'interest' ? 'checked' : ''}> Interest
            </label>
            <label class="radio-label">
              <input type="radio" name="enc-type" value="data"
                ${this.encType === 'data' ? 'checked' : ''}> Data
            </label>
          </div>
          <div id="enc-form">${this._renderEncForm()}</div>
          <button id="enc-build" class="pipe-run-btn" style="margin-top:0.5rem">
            &#9654; Build Packet
          </button>
        </div>
        <div class="pipeline-panel">
          <div class="panel-title" style="margin-bottom:0.5rem">
            Wire Format
            <span id="enc-byte-count" class="pex-byte-count"></span>
          </div>
          <div id="enc-output" class="pex-enc-output">
            <p style="color:var(--text2);font-size:0.82rem">
              Click <strong>Build Packet</strong> to generate the NDN wire format.
            </p>
          </div>
        </div>
      </div>`;
  }

  _renderEncForm() {
    const o = this.encOpts;
    if (this.encType === 'interest') {
      return `
        <div class="composer-field">
          <label class="field-label" for="enc-name">Name</label>
          <input type="text" id="enc-name" class="pipe-input"
            value="${esc(o.name)}" placeholder="/ndn/...">
        </div>
        <div class="composer-field">
          <label class="field-label">Lifetime</label>
          <div class="slider-row">
            <input type="range" id="enc-lifetime" min="100" max="60000"
              step="100" value="${o.lifetimeMs}">
            <span class="slider-val" id="enc-lifetime-val">${o.lifetimeMs} ms</span>
          </div>
        </div>
        <div class="composer-check-row">
          <label class="check-label">
            <input type="checkbox" id="enc-cbp" ${o.canBePrefix ? 'checked' : ''}> CanBePrefix
          </label>
          <label class="check-label">
            <input type="checkbox" id="enc-mbf" ${o.mustBeFresh ? 'checked' : ''}> MustBeFresh
          </label>
        </div>`;
    }
    return `
      <div class="composer-field">
        <label class="field-label" for="enc-name">Name</label>
        <input type="text" id="enc-name" class="pipe-input"
          value="${esc(o.name)}" placeholder="/ndn/...">
      </div>
      <div class="composer-field">
        <label class="field-label" for="enc-content">Content</label>
        <textarea id="enc-content" class="pipe-textarea" rows="2"
          placeholder="packet payload…">${esc(o.content ?? '')}</textarea>
      </div>
      <div class="composer-field">
        <label class="field-label">Freshness Period</label>
        <div class="slider-row">
          <input type="range" id="enc-freshness" min="0" max="86400000"
            step="1000" value="${o.freshnessMs ?? 0}">
          <span class="slider-val" id="enc-freshness-val">${fmtMs(o.freshnessMs ?? 0)}</span>
        </div>
      </div>`;
  }

  _wireEncoderEvents() {
    const q = (/** @type {string} */ s) => this.container.querySelector(s);

    // Packet type radio
    this.container.querySelectorAll('input[name="enc-type"]').forEach(r => {
      r.addEventListener('change', () => {
        const radio = /** @type {HTMLInputElement} */ (r);
        if (radio.checked) {
          this.encType = /** @type {'interest'|'data'} */ (radio.value);
          const form = q('#enc-form');
          if (form) {
            form.innerHTML = this._renderEncForm();
            this._wireEncFormFields();
          }
        }
      });
    });

    this._wireEncFormFields();
    q('#enc-build')?.addEventListener('click', () => this._buildPacket());
  }

  _wireEncFormFields() {
    const q = (/** @type {string} */ s) => this.container.querySelector(s);

    q('#enc-name')?.addEventListener('input', e => {
      this.encOpts.name = /** @type {HTMLInputElement} */ (e.target).value;
    });

    if (this.encType === 'interest') {
      wireSlider(this.container, 'enc-lifetime', 'enc-lifetime-val',
        v => { this.encOpts.lifetimeMs = v; }, v => `${v} ms`);
      q('#enc-cbp')?.addEventListener('change', e => {
        this.encOpts.canBePrefix = /** @type {HTMLInputElement} */ (e.target).checked;
      });
      q('#enc-mbf')?.addEventListener('change', e => {
        this.encOpts.mustBeFresh = /** @type {HTMLInputElement} */ (e.target).checked;
      });
    } else {
      q('#enc-content')?.addEventListener('input', e => {
        this.encOpts.content = /** @type {HTMLTextAreaElement} */ (e.target).value;
      });
      wireSlider(this.container, 'enc-freshness', 'enc-freshness-val',
        v => { this.encOpts.freshnessMs = v; }, fmtMs);
    }
  }

  _buildPacket() {
    try {
      let bytes;
      if (wasmMod) {
        // Use the Rust encoder — byte-for-byte identical to what ndn-cxx produces.
        const hexStr = this.encType === 'interest'
          ? wasmMod.tlv_encode_interest(
              this.encOpts.name,
              this.encOpts.canBePrefix  ?? false,
              this.encOpts.mustBeFresh  ?? false,
              0,                              // 0 → auto nonce in Rust
              this.encOpts.lifetimeMs   ?? 4000,
            )
          : wasmMod.tlv_encode_data(
              this.encOpts.name,
              this.encOpts.content      ?? '',
              this.encOpts.freshnessMs  ?? 0,
            );
        bytes = parseHex(hexStr) ?? new Uint8Array(0);
      } else {
        bytes = this.encType === 'interest'
          ? encodeInterest(this.encOpts)
          : encodeData(this.encOpts);
      }
      this.encBytes = bytes;
      this._showEncOutput(bytes);
    } catch (e) {
      const out = this.container.querySelector('#enc-output');
      if (out) out.innerHTML =
        `<p style="color:var(--red);font-size:0.82rem">Error: ${esc(String(e))}</p>`;
    }
  }

  /** @param {Uint8Array} bytes */
  _showEncOutput(bytes) {
    const hexStr = toHex(bytes);
    const out = this.container.querySelector('#enc-output');
    const cnt = this.container.querySelector('#enc-byte-count');
    if (cnt) cnt.textContent = `${bytes.length} bytes`;
    if (!out) return;

    // Render colorized hex with TLV structure hints
    const tree = decodeTlv(bytes);
    const flat = flatten(tree);

    out.innerHTML = `
      <div class="pex-hex-block" id="enc-hex-block">${renderHexBlock(bytes, flat)}</div>
      <div class="pex-enc-actions">
        <button id="enc-copy" class="pipe-ctrl-btn">Copy hex</button>
        <button id="enc-inspect" class="pipe-ctrl-btn">Inspect &rarr;</button>
        <button id="enc-pipeline" class="pipe-run-btn">&#9654; Run in Pipeline</button>
      </div>`;

    out.querySelector('#enc-copy')?.addEventListener('click', () => {
      navigator.clipboard?.writeText(hexStr).catch(() => {});
    });
    out.querySelector('#enc-inspect')?.addEventListener('click', () => {
      this._sendToInspector(bytes);
    });
    out.querySelector('#enc-pipeline')?.addEventListener('click', () => {
      this._sendToPipeline();
    });
  }

  // ── Inspector ─────────────────────────────────────────────────────────────

  _renderInspector() {
    return `
      <div class="pex-ins-toolbar">
        <label class="toolbar-label" for="ins-example">Load example</label>
        <select id="ins-example" class="pipe-select">
          <option value="">— paste hex below —</option>
          <option value="interest">Simple Interest</option>
          <option value="data">Data packet</option>
          <option value="lp">LpPacket (NDNLPv2 wrapper)</option>
        </select>
        <button id="ins-parse" class="pipe-run-btn">Parse</button>
        <button id="ins-clear" class="pipe-ctrl-btn">Clear</button>
      </div>
      <textarea id="ins-hex-input" class="pex-hex-input"
        placeholder="Paste hex bytes here, e.g.:  05 2c 07 1c 08 03 6e 64 6e …"></textarea>
      <div id="ins-panes" class="pex-panes-wrap">
        <p class="pex-empty-state">
          Paste hex bytes above and click <strong>Parse</strong>, or load an example.
        </p>
      </div>`;
  }

  _wireInspectorEvents() {
    const q = (/** @type {string} */ s) => this.container.querySelector(s);

    // Example loader
    /** @type {HTMLSelectElement|null} */ (q('#ins-example'))
      ?.addEventListener('change', e => {
        const key = /** @type {HTMLSelectElement} */ (e.target).value;
        if (!key) return;
        const examples = makeExamples();
        const bytes = examples[/** @type {keyof typeof examples} */ (key)];
        if (!bytes) return;
        const input = /** @type {HTMLTextAreaElement|null} */ (q('#ins-hex-input'));
        if (input) input.value = toHex(bytes);
        this._parseAndRender(bytes);
        /** @type {HTMLSelectElement} */ (e.target).value = '';
      });

    q('#ins-parse')?.addEventListener('click', () => {
      const hex = /** @type {HTMLTextAreaElement|null} */ (q('#ins-hex-input'))?.value ?? '';
      const bytes = parseHex(hex);
      if (!bytes || bytes.length === 0) {
        this._showInspError('Invalid hex input — check for odd number of digits or non-hex characters.');
        return;
      }
      this._parseAndRender(bytes);
    });

    q('#ins-clear')?.addEventListener('click', () => {
      const input = /** @type {HTMLTextAreaElement|null} */ (q('#ins-hex-input'));
      if (input) input.value = '';
      const panes = q('#ins-panes');
      if (panes) panes.innerHTML =
        '<p class="pex-empty-state">Paste hex bytes above and click <strong>Parse</strong>, or load an example.</p>';
    });
  }

  /** Navigate to the Pipeline view pre-loaded with the current encoder packet. */
  _sendToPipeline() {
    const o = this.encOpts;
    /** @type {import('./pipeline-trace.js').PacketSpec} */
    const packet = this.encType === 'interest'
      ? {
          type: 'interest',
          name: o.name,
          canBePrefix: o.canBePrefix,
          mustBeFresh: o.mustBeFresh,
          lifetimeMs:  o.lifetimeMs,
        }
      : {
          type: 'data',
          name:        o.name,
          content:     o.content ?? '',
          freshnessMs: o.freshnessMs ?? 0,
        };
    this.app.navigate('pipeline-trace', { packet });
  }

  /** @param {Uint8Array} bytes */
  _sendToInspector(bytes) {
    this._switchTab('inspector');
    const input = /** @type {HTMLTextAreaElement|null} */ (
      this.container.querySelector('#ins-hex-input'));
    if (input) input.value = toHex(bytes);
    this._parseAndRender(bytes);
  }

  /** @param {Uint8Array} bytes */
  _parseAndRender(bytes) {
    this.inspBytes = bytes;

    let tree;
    if (wasmMod) {
      // Use Rust decoder — authoritative field names from ndn-packet type constants.
      const wasmResult = wasmMod.tlv_parse_hex(toHex(bytes).toLowerCase());
      tree = Array.isArray(wasmResult) ? adaptWasmTlvTree(wasmResult) : decodeTlv(bytes);
    } else {
      tree = decodeTlv(bytes);
    }
    this.inspFlat = flatten(tree);

    const panesWrap = this.container.querySelector('#ins-panes');
    if (!panesWrap) return;

    if (tree.length === 0) {
      panesWrap.innerHTML = '<p class="pex-empty-state" style="color:var(--red)">Could not parse any TLV fields from these bytes.</p>';
      return;
    }

    panesWrap.innerHTML = `
      <div class="pex-panes">
        <div class="pex-pane">
          <div class="pex-pane-title">
            Hex Dump
            <span class="pex-byte-count">${bytes.length} bytes</span>
          </div>
          <div class="hx-dump" id="ins-hex-dump">${this._renderHexDump(bytes)}</div>
        </div>
        <div class="pex-pane">
          <div class="pex-pane-title">TLV Tree</div>
          <div class="tlv-tree" id="ins-tlv-tree">${this._renderTree(tree, 0)}</div>
        </div>
      </div>`;

    this._wireHoverHighlight();
    this._wireTreeToggle();
  }

  /** @param {string} msg */
  _showInspError(msg) {
    const panes = this.container.querySelector('#ins-panes');
    if (panes) panes.innerHTML =
      `<p class="pex-empty-state" style="color:var(--red)">${esc(msg)}</p>`;
  }

  // ── Hex dump renderer ─────────────────────────────────────────────────────

  /** @param {Uint8Array} buf @returns {string} */
  _renderHexDump(buf) {
    const MAX = 2048;
    const display = buf.length > MAX ? buf.subarray(0, MAX) : buf;
    let html = '';
    for (let row = 0; row < display.length; row += 16) {
      html += '<div class="hx-row">';
      html += `<span class="hx-off">${row.toString(16).padStart(4, '0')}</span>`;
      for (let col = 0; col < 16; col++) {
        if (col === 8) html += '<span class="hx-sep">&nbsp;</span>';
        const off = row + col;
        if (off < display.length) {
          const b = display[off].toString(16).padStart(2, '0');
          html += `<span class="hx-byte" data-off="${off}">${b}</span>`;
        } else {
          html += '<span class="hx-pad">  </span>';
        }
      }
      html += '</div>';
    }
    if (buf.length > MAX) {
      html += `<div class="hx-truncated">… ${buf.length - MAX} more bytes (truncated)</div>`;
    }
    return html;
  }

  // ── TLV tree renderer ─────────────────────────────────────────────────────

  /**
   * @param {TlvNode[]} nodes
   * @param {number} depth
   * @returns {string}
   */
  _renderTree(nodes, depth) {
    return nodes.map(n => this._renderTreeNode(n, depth)).join('');
  }

  /**
   * @param {TlvNode} node
   * @param {number} depth
   * @returns {string}
   */
  _renderTreeNode(node, depth) {
    const hasChildren = node.children.length > 0;
    const catCls = `tlv-cat-${TYPE_CAT[node.typ] ?? 'unknown'}`;
    const indent = depth * 14;

    const toggle = hasChildren
      ? `<span class="tlv-toggle">&#9660;</span>`   // ▼ expanded by default
      : `<span class="tlv-toggle tlv-toggle-leaf"></span>`;

    let valDisplay = '';
    if (!hasChildren) {
      if (node.valueText) {
        valDisplay = `<span class="tlv-val-text">"${esc(node.valueText)}"</span>`;
      } else if (node.valueHex) {
        const h = node.valueHex;
        valDisplay = `<span class="tlv-val-hex">${h.length > 47 ? h.slice(0, 47) + '…' : h}</span>`;
      }
    }

    const childrenHtml = hasChildren
      ? `<div class="tlv-children">${this._renderTree(node.children, depth + 1)}</div>`
      : '';

    return `
      <div class="tlv-node ${catCls}"
           data-start="${node.startByte}" data-end="${node.endByte}">
        <div class="tlv-header" style="padding-left:${indent}px">
          ${toggle}
          <span class="tlv-type-hex">0x${node.typ.toString(16).padStart(2, '0')}</span>
          <span class="tlv-type-name">${esc(node.typeName)}</span>
          ${valDisplay}
          <span class="tlv-len">${node.length}B</span>
        </div>
        ${childrenHtml}
      </div>`;
  }

  // ── Hover highlight wiring ────────────────────────────────────────────────

  _wireHoverHighlight() {
    const flat = this.inspFlat;

    // Hex bytes → highlight matching tree node
    this.container.querySelectorAll('.hx-byte').forEach(span => {
      span.addEventListener('mouseenter', () => {
        const off = parseInt(/** @type {HTMLElement} */ (span).dataset.off ?? '0');
        const node = deepestAt(flat, off);
        if (node) {
          this._hlRange(node.startByte, node.endByte);
          this._hlTreeNode(node.startByte, node.endByte);
        }
      });
      span.addEventListener('mouseleave', () => this._clearHl());
    });

    // Tree node headers → highlight hex range
    this.container.querySelectorAll('.tlv-node').forEach(el => {
      const header = el.querySelector('.tlv-header');
      if (!header) return;
      header.addEventListener('mouseenter', e => {
        e.stopPropagation();
        const s = parseInt(/** @type {HTMLElement} */ (el).dataset.start ?? '0');
        const e2 = parseInt(/** @type {HTMLElement} */ (el).dataset.end ?? '0');
        this._hlRange(s, e2);
        this._hlTreeNode(s, e2);
      });
      header.addEventListener('mouseleave', e => {
        e.stopPropagation();
        this._clearHl();
      });
    });
  }

  _wireTreeToggle() {
    this.container.querySelectorAll('.tlv-node').forEach(el => {
      const header = el.querySelector('.tlv-header');
      const children = el.querySelector('.tlv-children');
      const toggle = header?.querySelector('.tlv-toggle');
      if (!header || !children || !toggle) return;
      header.addEventListener('click', () => {
        const hidden = /** @type {HTMLElement} */ (children).style.display === 'none';
        /** @type {HTMLElement} */ (children).style.display = hidden ? '' : 'none';
        toggle.innerHTML = hidden ? '&#9660;' : '&#9654;'; // ▼ / ▶
      });
    });
  }

  /**
   * @param {number} start @param {number} end
   */
  _hlRange(start, end) {
    this.container.querySelectorAll('.hx-byte').forEach(span => {
      const off = parseInt(/** @type {HTMLElement} */ (span).dataset.off ?? '0');
      span.classList.toggle('hl', off >= start && off < end);
    });
  }

  /**
   * @param {number} start @param {number} end
   */
  _hlTreeNode(start, end) {
    this.container.querySelectorAll('.tlv-node').forEach(el => {
      const s = parseInt(/** @type {HTMLElement} */ (el).dataset.start ?? '-1');
      const e2 = parseInt(/** @type {HTMLElement} */ (el).dataset.end ?? '-1');
      el.classList.toggle('hl', s === start && e2 === end);
    });
  }

  _clearHl() {
    this.container.querySelectorAll('.hx-byte').forEach(s => s.classList.remove('hl'));
    this.container.querySelectorAll('.tlv-node').forEach(n => n.classList.remove('hl'));
  }
}

// ── Helpers (module-level) ────────────────────────────────────────────────────

/**
 * Render a colorized hex block for the encoder output (no interactivity needed).
 * @param {Uint8Array} buf @param {TlvNode[]} flat @returns {string}
 */
function renderHexBlock(buf, flat) {
  return Array.from(buf).map((byte, off) => {
    const node = deepestAt(flat, off);
    const cat = node ? (TYPE_CAT[node.typ] ?? 'unknown') : 'unknown';
    const b = byte.toString(16).padStart(2, '0').toUpperCase();
    return `<span class="hxb-cat-${cat}">${b}</span>`;
  }).join(' ');
}

/**
 * Wire a range input to its value display and an onChange callback.
 * @param {HTMLElement} container
 * @param {string} inputId
 * @param {string} valId
 * @param {(v: number) => void} onChange
 * @param {(v: number) => string} [fmt]
 */
function wireSlider(container, inputId, valId, onChange, fmt) {
  const input = /** @type {HTMLInputElement|null} */ (container.querySelector(`#${inputId}`));
  const valEl = container.querySelector(`#${valId}`);
  if (!input || !valEl) return;
  input.addEventListener('input', () => {
    const v = parseInt(input.value);
    onChange(v);
    valEl.textContent = fmt ? fmt(v) : String(v);
  });
}

/** @param {string} s @returns {string} */
function esc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/** @param {number} ms @returns {string} */
function fmtMs(ms) {
  if (ms === 0) return '0 ms';
  if (ms < 1000) return `${ms} ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)} s`;
  if (ms < 3600000) return `${(ms / 60000).toFixed(1)} min`;
  return `${(ms / 3600000).toFixed(1)} hr`;
}
