// @ts-check
/**
 * Security / Signing Animations view.
 *
 * Shows the full NDN packet signing and verification lifecycle as
 * step-by-step animated diagrams:
 *
 *   Sign mode:
 *     1. Packet assembly  — TLV blocks drop into position one by one
 *     2. Hash             — content bytes flow into SHA-256 box, digest emerges
 *     3. Sign             — digest enters key block, signature bytes emerge
 *     4. Append           — signature bytes fill the SignatureValue field (?? → hex)
 *     5. Complete         — final wire-format packet with byte count
 *
 *   Verify mode (reverse path):
 *     1. Extract sig      — SignatureValue highlighted / lifted out
 *     2. Signed region    — Name + MetaInfo + Content + SignatureInfo highlighted
 *     3. Hash             — signed bytes → SHA-256 → digest
 *     4. Verify           — (digest + public key) → verify block → PASS / FAIL
 *
 *   Cert Chain tab:
 *     Stacked mini-packet diagrams: leaf cert → KSK → trust anchor
 *     with "signed by" arrows between levels.
 */

// ── Step definitions ──────────────────────────────────────────────────────────

/** @typedef {{ id: string, label: string, desc: string }} Step */

/** @type {Step[]} */
const SIGN_STEPS = [
  {
    id: 'assemble',
    label: 'Assemble packet',
    desc: 'The NDN Data packet is built field-by-field as TLV (Type-Length-Value) blocks. ' +
          'Each field is encoded in canonical order: Name, MetaInfo, Content, SignatureInfo. ' +
          'The SignatureValue field is reserved but left empty (shown as ??) until signing completes.',
  },
  {
    id: 'hash',
    label: 'Hash the signed region',
    desc: 'The signed region covers all fields except SignatureValue: ' +
          'Name + MetaInfo + Content + SignatureInfo. ' +
          'These bytes are fed into SHA-256, producing a 32-byte digest. ' +
          'For DigestSha256, this digest is the signature.',
  },
  {
    id: 'sign',
    label: 'Sign with key',
    desc: 'The 32-byte digest is passed to the signing algorithm along with the private key. ' +
          'DigestSha256: the digest itself is the "signature" — no key required. ' +
          'ECDSA-P256: the key signs the digest, producing a 64-byte DER signature. ' +
          'HMAC-SHA256: the key is mixed with the digest via HMAC, producing 32 bytes.',
  },
  {
    id: 'append',
    label: 'Append SignatureValue',
    desc: 'The signature bytes replace the ?? placeholder in the SignatureValue field. ' +
          'The Length prefix of the TLV is updated to match the actual byte count. ' +
          'The packet is now complete and ready to be sent.',
  },
  {
    id: 'complete',
    label: 'Packet complete',
    desc: 'The signed Data packet is fully assembled. The SignatureValue field now contains ' +
          'the real signature bytes. Any NDN node or consumer that receives this packet can ' +
          'verify its integrity and authenticity using the same process in reverse.',
  },
];

/** @type {Step[]} */
const VERIFY_STEPS = [
  {
    id: 'extract-sig',
    label: 'Extract SignatureValue',
    desc: 'The verifier reads the SignatureValue TLV from the end of the packet. ' +
          'These bytes are the signature that was produced during signing and will be checked.',
  },
  {
    id: 'signed-region',
    label: 'Identify signed region',
    desc: 'The signed region is everything except the SignatureValue field: ' +
          'Name + MetaInfo + Content + SignatureInfo. ' +
          'This is the exact byte range that was hashed during signing.',
  },
  {
    id: 'hash',
    label: 'Re-hash the signed region',
    desc: 'The verifier feeds the same signed region through SHA-256, ' +
          'producing a fresh 32-byte digest. ' +
          'If the packet has not been tampered with, this digest will match the one computed at signing time.',
  },
  {
    id: 'verify',
    label: 'Verify signature',
    desc: 'The fresh digest is combined with the public key (or shared HMAC key) ' +
          'and the extracted signature in a cryptographic verification step. ' +
          'PASS: the signature was produced by the correct key over unmodified bytes. ' +
          'FAIL: the packet was tampered with, the wrong key was used, or the signature is invalid.',
  },
];

// ── Signature type definitions ────────────────────────────────────────────────

/** @type {Record<string, {label: string, keyLabel: string, sigLen: number, color: string}>} */
const SIG_TYPES = {
  DigestSha256: { label: 'DigestSha256 (type 0)',   keyLabel: '— (no key)',          sigLen: 32, color: '#79c0ff' },
  'ECDSA-P256':  { label: 'ECDSA-P256   (type 3)',   keyLabel: 'ECDSA private key',   sigLen: 64, color: '#3fb950' },
  'HMAC-256':    { label: 'HMAC-SHA256  (type 4)',   keyLabel: 'Shared HMAC key',     sigLen: 32, color: '#d2a8ff' },
};

// ── Utility: fake bytes ───────────────────────────────────────────────────────

function fakeHex(len) {
  const bytes = [];
  for (let i = 0; i < len; i++) bytes.push(((i * 37 + 91) & 0xFF).toString(16).padStart(2, '0'));
  return bytes.join(' ');
}

function shortHex(len) {
  return fakeHex(Math.min(len, 8)) + (len > 8 ? ' …' : '');
}

// ── SecurityAnim view ─────────────────────────────────────────────────────────

export class SecurityAnim {
  /** @param {HTMLElement} container @param {any} app */
  constructor(container, app) {
    this.container = container;
    this.app = app;
    this._rendered = false;

    this._mode = /** @type {'sign'|'verify'|'certchain'} */ ('sign');
    this._sigType = 'DigestSha256';
    this._packetName = '/ndn/example/data';
    this._content = 'Hello, NDN!';
    this._tampered = false;

    this._step = 0;
    this._steps = SIGN_STEPS;
    this._animating = false;
    this._autoTimer = /** @type {number|null} */ (null);

    /** @type {HTMLElement|null} */ this._canvas = null;
    /** @type {HTMLElement|null} */ this._descBox = null;
    /** @type {HTMLElement|null} */ this._stepIndicator = null;
  }

  onShow() {
    if (!this._rendered) {
      this._rendered = true;
      this._buildDOM();
      this._showStep(0);
    }
  }

  // ── DOM construction ─────────────────────────────────────────────────────────

  _buildDOM() {
    this.container.innerHTML = '';
    this.container.className = 'view sec-root';

    // ── Top bar ──────────────────────────────────────────────────────────────
    const topbar = document.createElement('div');
    topbar.className = 'sec-topbar';
    topbar.innerHTML = `
      <div class="sec-mode-tabs">
        <button class="sec-tab sec-tab-active" data-mode="sign">Sign</button>
        <button class="sec-tab" data-mode="verify">Verify</button>
        <button class="sec-tab" data-mode="certchain">Cert Chain</button>
      </div>
      <div class="sec-form" id="sec-form">
        <label class="sec-label">Name
          <input class="sec-input" id="sec-name" value="/ndn/example/data">
        </label>
        <label class="sec-label">Content
          <input class="sec-input sec-input-content" id="sec-content" value="Hello, NDN!">
        </label>
        <label class="sec-label">Signature type
          <select class="sec-input" id="sec-sigtype">
            ${Object.entries(SIG_TYPES).map(([k, v]) =>
              `<option value="${k}">${v.label}</option>`
            ).join('')}
          </select>
        </label>
        <label class="sec-label sec-tamper-label" id="sec-tamper-wrap" style="display:none">
          <input type="checkbox" id="sec-tampered"> Tamper content (verify will FAIL)
        </label>
      </div>
    `;
    this.container.appendChild(topbar);

    // ── Main area ─────────────────────────────────────────────────────────────
    const main = document.createElement('div');
    main.className = 'sec-main';

    // Animation canvas
    const canvasWrap = document.createElement('div');
    canvasWrap.className = 'sec-canvas-wrap';
    const canvas = document.createElement('div');
    canvas.className = 'sec-canvas';
    this._canvas = canvas;
    canvasWrap.appendChild(canvas);
    main.appendChild(canvasWrap);

    // Step description
    const descBox = document.createElement('div');
    descBox.className = 'sec-desc-box';
    this._descBox = descBox;
    main.appendChild(descBox);

    this.container.appendChild(main);

    // ── Controls bar ─────────────────────────────────────────────────────────
    const controls = document.createElement('div');
    controls.className = 'sec-controls';
    controls.innerHTML = `
      <div class="sec-step-indicator" id="sec-step-indicator"></div>
      <div class="sec-btn-row">
        <button class="sec-btn" id="sec-prev">← Prev</button>
        <button class="sec-btn sec-btn-primary" id="sec-next">Next →</button>
        <button class="sec-btn" id="sec-auto">Auto Play</button>
        <button class="sec-btn" id="sec-restart">Restart</button>
      </div>
    `;
    this._stepIndicator = controls.querySelector('#sec-step-indicator');
    this.container.appendChild(controls);

    // ── Event wiring ─────────────────────────────────────────────────────────
    topbar.querySelectorAll('.sec-tab').forEach(btn => {
      btn.addEventListener('click', () => {
        this._stopAuto();
        this._mode = /** @type {any} */ (/** @type {HTMLElement} */(btn).dataset.mode);
        topbar.querySelectorAll('.sec-tab').forEach(b => b.classList.remove('sec-tab-active'));
        btn.classList.add('sec-tab-active');
        const form = topbar.querySelector('#sec-form');
        const tamperWrap = topbar.querySelector('#sec-tamper-wrap');
        if (form) /** @type {HTMLElement} */(form).style.display =
          this._mode === 'certchain' ? 'none' : '';
        if (tamperWrap) /** @type {HTMLElement} */(tamperWrap).style.display =
          this._mode === 'verify' ? '' : 'none';
        this._steps = this._mode === 'verify' ? VERIFY_STEPS : SIGN_STEPS;
        this._showStep(0);
      });
    });

    topbar.querySelector('#sec-name')?.addEventListener('input', (e) => {
      this._packetName = /** @type {HTMLInputElement} */(e.target).value || '/ndn/example';
      this._showStep(this._step);
    });
    topbar.querySelector('#sec-content')?.addEventListener('input', (e) => {
      this._content = /** @type {HTMLInputElement} */(e.target).value;
      this._showStep(this._step);
    });
    topbar.querySelector('#sec-sigtype')?.addEventListener('change', (e) => {
      this._sigType = /** @type {HTMLSelectElement} */(e.target).value;
      this._showStep(this._step);
    });
    topbar.querySelector('#sec-tampered')?.addEventListener('change', (e) => {
      this._tampered = /** @type {HTMLInputElement} */(e.target).checked;
      if (this._step >= 2) this._showStep(this._step);
    });

    controls.querySelector('#sec-prev')?.addEventListener('click', () => {
      this._stopAuto();
      this._showStep(Math.max(0, this._step - 1));
    });
    controls.querySelector('#sec-next')?.addEventListener('click', () => {
      this._stopAuto();
      this._showStep(Math.min(this._steps.length - 1, this._step + 1));
    });
    controls.querySelector('#sec-auto')?.addEventListener('click', () => {
      if (this._autoTimer !== null) { this._stopAuto(); return; }
      this._showStep(0);
      this._startAuto();
    });
    controls.querySelector('#sec-restart')?.addEventListener('click', () => {
      this._stopAuto();
      this._showStep(0);
    });
  }

  // ── Auto-play ─────────────────────────────────────────────────────────────

  _startAuto() {
    const autoBtn = this.container.querySelector('#sec-auto');
    if (autoBtn) autoBtn.textContent = '⏸ Pause';
    const advance = () => {
      if (this._step < this._steps.length - 1) {
        this._showStep(this._step + 1);
        this._autoTimer = window.setTimeout(advance, 2800);
      } else {
        this._stopAuto();
      }
    };
    this._autoTimer = window.setTimeout(advance, 2000);
  }

  _stopAuto() {
    if (this._autoTimer !== null) { clearTimeout(this._autoTimer); this._autoTimer = null; }
    const autoBtn = this.container.querySelector('#sec-auto');
    if (autoBtn) autoBtn.textContent = 'Auto Play';
  }

  // ── Step rendering ────────────────────────────────────────────────────────

  /** @param {number} i */
  _showStep(i) {
    this._step = i;
    this._steps = this._mode === 'verify' ? VERIFY_STEPS : SIGN_STEPS;
    i = Math.max(0, Math.min(i, this._steps.length - 1));
    this._step = i;

    if (this._descBox) {
      const step = this._steps[i];
      this._descBox.innerHTML = `<strong>${step.label}</strong><br>${step.desc}`;
    }

    if (this._stepIndicator) {
      this._stepIndicator.innerHTML = this._steps.map((s, idx) =>
        `<span class="sec-step-dot ${idx === i ? 'active' : idx < i ? 'done' : ''}"
               title="${s.label}"></span>`
      ).join('');
    }

    // Update nav buttons
    const prev = this.container.querySelector('#sec-prev');
    const next = this.container.querySelector('#sec-next');
    if (prev) /** @type {HTMLButtonElement} */(prev).disabled = i === 0;
    if (next) /** @type {HTMLButtonElement} */(next).disabled = i === this._steps.length - 1;

    if (this._mode === 'certchain') {
      this._renderCertChain();
    } else if (this._mode === 'verify') {
      this._renderVerifyStep(i);
    } else {
      this._renderSignStep(i);
    }
  }

  // ── Packet field helper ───────────────────────────────────────────────────

  /**
   * Build the array of packet field descriptors for the current settings.
   * @param {boolean} sigFilled whether SignatureValue shows real bytes (true) or ??
   * @returns {Array<{id:string, type:string, label:string, value:string, indent:number, highlight:string}>}
   */
  _packetFields(sigFilled = false) {
    const st = SIG_TYPES[this._sigType];
    const sigHex = sigFilled ? shortHex(st.sigLen) : '??  '.repeat(8).trim();
    const sigTypeCode = this._sigType === 'DigestSha256' ? '0' : this._sigType === 'ECDSA-P256' ? '3' : '4';
    const name = this._packetName || '/ndn/example';
    const components = name.replace(/^\//, '').split('/').filter(Boolean);
    const nameHex = components.map(c => `0x08 ${c.length} "${c}"`).join('  ');
    const contentBytes = this._content || '(empty)';
    return [
      { id: 'data',    type: '0x06', label: 'Data',              value: '',                indent: 0, highlight: '' },
      { id: 'name',    type: '0x07', label: 'Name',              value: name,              indent: 1, highlight: 'signed' },
      ...components.map((c, i) => ({
        id: `nc${i}`, type: '0x08', label: 'NameComponent',       value: `"${c}"`,          indent: 2, highlight: 'signed',
      })),
      { id: 'meta',    type: '0x14', label: 'MetaInfo',           value: '',                indent: 1, highlight: 'signed' },
      { id: 'fresh',   type: '0x19', label: 'FreshnessPeriod',    value: '10000 ms',        indent: 2, highlight: 'signed' },
      { id: 'content', type: '0x15', label: 'Content',            value: `"${contentBytes}"`, indent: 1, highlight: 'signed' },
      { id: 'siginfo', type: '0x16', label: 'SignatureInfo',      value: '',                indent: 1, highlight: 'signed' },
      { id: 'sigtype', type: '0x1b', label: 'SignatureType',      value: sigTypeCode,       indent: 2, highlight: 'signed' },
      { id: 'sigval',  type: '0x17', label: 'SignatureValue',     value: sigHex,            indent: 1, highlight: 'sigval' },
    ];
  }

  // ── Sign animation steps ──────────────────────────────────────────────────

  /** @param {number} i */
  _renderSignStep(i) {
    if (!this._canvas) return;
    this._canvas.innerHTML = '';
    switch (i) {
      case 0: return this._renderSignAssemble();
      case 1: return this._renderSignHash();
      case 2: return this._renderSignKey();
      case 3: return this._renderSignAppend();
      case 4: return this._renderSignComplete();
    }
  }

  _renderSignAssemble() {
    if (!this._canvas) return;
    const fields = this._packetFields(false);
    const wrap = document.createElement('div');
    wrap.className = 'sec-packet-tree';
    fields.forEach((f, idx) => {
      const row = document.createElement('div');
      row.className = `sec-field sec-field-${f.highlight || 'neutral'} sec-field-appear`;
      row.style.animationDelay = `${idx * 80}ms`;
      row.style.paddingLeft = `${f.indent * 1.4 + 0.5}rem`;
      row.innerHTML =
        `<span class="sec-field-type">${f.type}</span>` +
        `<span class="sec-field-label">${f.label}</span>` +
        (f.value ? `<span class="sec-field-value">${f.value}</span>` : '');
      if (f.id === 'sigval') row.classList.add('sec-field-sigval-empty');
      wrap.appendChild(row);
    });
    this._canvas.appendChild(wrap);
  }

  _renderSignHash() {
    if (!this._canvas) return;
    const st = SIG_TYPES[this._sigType];
    this._canvas.innerHTML = `
      <div class="sec-flow-diagram">
        <div class="sec-flow-col sec-flow-col-packet">
          <div class="sec-flow-title">Signed region</div>
          ${['Name', 'MetaInfo', 'Content', 'SignatureInfo'].map(f =>
            `<div class="sec-flow-field">${f}</div>`
          ).join('')}
          <div class="sec-flow-arrow-down">↓ bytes</div>
        </div>
        <div class="sec-flow-arrow sec-flow-arrow-right">→</div>
        <div class="sec-flow-box sec-flow-hash">
          <div class="sec-flow-box-icon">⬡</div>
          <div class="sec-flow-box-label">SHA-256</div>
          <div class="sec-flow-box-sub">32 bytes out</div>
        </div>
        <div class="sec-flow-arrow sec-flow-arrow-right">→</div>
        <div class="sec-flow-col sec-flow-col-digest">
          <div class="sec-flow-title">Digest</div>
          <div class="sec-flow-bytes">${fakeHex(16)}<br>${fakeHex(16)}</div>
          ${this._sigType === 'DigestSha256'
            ? `<div class="sec-flow-note">DigestSha256: digest = signature</div>` : ''}
        </div>
      </div>
    `;
  }

  _renderSignKey() {
    if (!this._canvas) return;
    const st = SIG_TYPES[this._sigType];
    const isDirect = this._sigType === 'DigestSha256';
    this._canvas.innerHTML = `
      <div class="sec-flow-diagram">
        <div class="sec-flow-col sec-flow-col-digest">
          <div class="sec-flow-title">Digest (32 B)</div>
          <div class="sec-flow-bytes">${fakeHex(8)}…</div>
        </div>
        <div class="sec-flow-arrow sec-flow-arrow-right">→</div>
        <div class="sec-flow-box ${isDirect ? 'sec-flow-hash' : 'sec-flow-key'}">
          <div class="sec-flow-box-icon">${isDirect ? '⬡' : '🔑'}</div>
          <div class="sec-flow-box-label">${isDirect ? 'DigestSha256' : this._sigType}</div>
          <div class="sec-flow-box-sub">${st.keyLabel}</div>
        </div>
        <div class="sec-flow-arrow sec-flow-arrow-right">→</div>
        <div class="sec-flow-col">
          <div class="sec-flow-title">Signature (${st.sigLen} B)</div>
          <div class="sec-flow-bytes sec-flow-bytes-sig">${fakeHex(Math.min(st.sigLen, 16))}${st.sigLen > 16 ? '<br>…' : ''}</div>
        </div>
      </div>
    `;
  }

  _renderSignAppend() {
    if (!this._canvas) return;
    const fields = this._packetFields(false);
    const st = SIG_TYPES[this._sigType];
    const wrap = document.createElement('div');
    wrap.className = 'sec-packet-tree';
    fields.forEach(f => {
      const row = document.createElement('div');
      row.className = `sec-field sec-field-${f.highlight || 'neutral'}`;
      row.style.paddingLeft = `${f.indent * 1.4 + 0.5}rem`;
      if (f.id === 'sigval') {
        row.classList.add('sec-field-sigval-filling');
        row.innerHTML =
          `<span class="sec-field-type">${f.type}</span>` +
          `<span class="sec-field-label">${f.label}</span>` +
          `<span class="sec-field-value sec-field-value-filling">${shortHex(st.sigLen)}</span>`;
      } else {
        row.innerHTML =
          `<span class="sec-field-type">${f.type}</span>` +
          `<span class="sec-field-label">${f.label}</span>` +
          (f.value ? `<span class="sec-field-value">${f.value}</span>` : '');
      }
      wrap.appendChild(row);
    });
    this._canvas.appendChild(wrap);
  }

  _renderSignComplete() {
    if (!this._canvas) return;
    const fields = this._packetFields(true);
    const st = SIG_TYPES[this._sigType];
    const byteCount = 80 + this._packetName.length + this._content.length + st.sigLen;
    const wrap = document.createElement('div');
    wrap.className = 'sec-packet-tree';
    fields.forEach(f => {
      const row = document.createElement('div');
      row.className = `sec-field sec-field-${f.highlight || 'neutral'}`;
      row.style.paddingLeft = `${f.indent * 1.4 + 0.5}rem`;
      row.innerHTML =
        `<span class="sec-field-type">${f.type}</span>` +
        `<span class="sec-field-label">${f.label}</span>` +
        (f.value ? `<span class="sec-field-value">${f.value}</span>` : '');
      wrap.appendChild(row);
    });
    const byteBar = document.createElement('div');
    byteBar.className = 'sec-byte-count';
    byteBar.innerHTML = `Total wire size: <strong>~${byteCount} bytes</strong> · Signature: ${st.sigLen} bytes (${this._sigType})`;
    wrap.appendChild(byteBar);
    this._canvas.appendChild(wrap);
  }

  // ── Verify animation steps ────────────────────────────────────────────────

  /** @param {number} i */
  _renderVerifyStep(i) {
    if (!this._canvas) return;
    this._canvas.innerHTML = '';
    switch (i) {
      case 0: return this._renderVerifyExtractSig();
      case 1: return this._renderVerifySignedRegion();
      case 2: return this._renderVerifyHash();
      case 3: return this._renderVerifyResult();
    }
  }

  _renderVerifyExtractSig() {
    if (!this._canvas) return;
    const st = SIG_TYPES[this._sigType];
    const fields = this._packetFields(true);
    const wrap = document.createElement('div');
    wrap.className = 'sec-packet-tree';
    fields.forEach(f => {
      const row = document.createElement('div');
      const isExtracted = f.id === 'sigval';
      row.className = `sec-field ${isExtracted ? 'sec-field-extracted' : 'sec-field-neutral'}`;
      row.style.paddingLeft = `${f.indent * 1.4 + 0.5}rem`;
      row.innerHTML =
        `<span class="sec-field-type">${f.type}</span>` +
        `<span class="sec-field-label">${f.label}</span>` +
        (f.value ? `<span class="sec-field-value">${f.value}</span>` : '');
      if (isExtracted) {
        row.title = `${st.sigLen}-byte ${this._sigType} signature extracted for verification`;
      }
      wrap.appendChild(row);
    });
    const note = document.createElement('div');
    note.className = 'sec-verify-note';
    note.textContent = `↑ SignatureValue (${st.sigLen} bytes) extracted`;
    wrap.appendChild(note);
    this._canvas.appendChild(wrap);
  }

  _renderVerifySignedRegion() {
    if (!this._canvas) return;
    const fields = this._packetFields(true);
    const wrap = document.createElement('div');
    wrap.className = 'sec-packet-tree';
    fields.forEach(f => {
      const row = document.createElement('div');
      row.className = `sec-field ${f.highlight === 'signed' ? 'sec-field-signed-hi' : 'sec-field-dim'}`;
      row.style.paddingLeft = `${f.indent * 1.4 + 0.5}rem`;
      row.innerHTML =
        `<span class="sec-field-type">${f.type}</span>` +
        `<span class="sec-field-label">${f.label}</span>` +
        (f.value ? `<span class="sec-field-value">${f.value}</span>` : '');
      wrap.appendChild(row);
    });
    const note = document.createElement('div');
    note.className = 'sec-verify-note';
    note.textContent = '↑ Highlighted region is fed to SHA-256';
    wrap.appendChild(note);
    this._canvas.appendChild(wrap);
  }

  _renderVerifyHash() {
    if (!this._canvas) return;
    this._canvas.innerHTML = `
      <div class="sec-flow-diagram">
        <div class="sec-flow-col">
          <div class="sec-flow-title">Signed region</div>
          ${['Name', 'MetaInfo', 'Content', 'SignatureInfo'].map(f =>
            `<div class="sec-flow-field">${f}</div>`
          ).join('')}
        </div>
        <div class="sec-flow-arrow sec-flow-arrow-right">→</div>
        <div class="sec-flow-box sec-flow-hash">
          <div class="sec-flow-box-icon">⬡</div>
          <div class="sec-flow-box-label">SHA-256</div>
        </div>
        <div class="sec-flow-arrow sec-flow-arrow-right">→</div>
        <div class="sec-flow-col">
          <div class="sec-flow-title">Fresh digest</div>
          <div class="sec-flow-bytes">${fakeHex(16)}<br>${fakeHex(16)}</div>
        </div>
      </div>
      <div class="sec-verify-compare">
        <div class="sec-compare-row">
          <span class="sec-compare-label">Fresh digest</span>
          <code>${fakeHex(16)}…</code>
        </div>
        <div class="sec-compare-row">
          <span class="sec-compare-label">Expected (from sig)</span>
          <code>${fakeHex(16)}…</code>
        </div>
      </div>
    `;
  }

  _renderVerifyResult() {
    if (!this._canvas) return;
    const pass = !this._tampered;
    const st = SIG_TYPES[this._sigType];
    const isDirect = this._sigType === 'DigestSha256';
    this._canvas.innerHTML = `
      <div class="sec-flow-diagram">
        <div class="sec-flow-col">
          <div class="sec-flow-title">Fresh digest</div>
          <div class="sec-flow-bytes">${fakeHex(8)}…</div>
        </div>
        <div class="sec-flow-arrow sec-flow-arrow-right">+</div>
        <div class="sec-flow-col">
          <div class="sec-flow-title">Extracted sig</div>
          <div class="sec-flow-bytes">${fakeHex(8)}…</div>
        </div>
        ${!isDirect ? `
          <div class="sec-flow-arrow sec-flow-arrow-right">+</div>
          <div class="sec-flow-col">
            <div class="sec-flow-title">Public key</div>
            <div class="sec-flow-box-sub">${st.keyLabel.replace('private', 'public')}</div>
          </div>
        ` : ''}
        <div class="sec-flow-arrow sec-flow-arrow-right">→</div>
        <div class="sec-flow-box ${pass ? 'sec-flow-verify-pass' : 'sec-flow-verify-fail'}">
          <div class="sec-flow-box-icon">${pass ? '✓' : '✗'}</div>
          <div class="sec-flow-box-label">${pass ? 'PASS' : 'FAIL'}</div>
        </div>
      </div>
      <div class="sec-verify-result ${pass ? 'sec-result-pass' : 'sec-result-fail'}">
        ${pass
          ? `Signature is valid. The packet was signed by the correct key and has not been modified.`
          : `Signature verification failed. The content was tampered with — the digest does not match.`
        }
      </div>
    `;
  }

  // ── Cert chain ────────────────────────────────────────────────────────────

  _renderCertChain() {
    if (!this._canvas) return;
    const name = this._packetName || '/ndn/example/data';
    const parts = name.replace(/^\//, '').split('/').filter(Boolean);
    const appName = '/' + parts.join('/');
    const sitePrefix = '/' + (parts[0] || 'ndn');
    const trustAnchor = sitePrefix + '/KEY/%00%01';
    const ksk = sitePrefix + '/operator/KEY/%00%02';
    const dsk = appName + '/KEY/%00%03';

    this._canvas.innerHTML = `
      <div class="sec-cert-chain">
        <div class="sec-cert-level">
          <div class="sec-cert-card">
            <div class="sec-cert-card-header">Trust Anchor</div>
            <div class="sec-cert-field"><span class="sec-ct">Name</span>${trustAnchor}</div>
            <div class="sec-cert-field"><span class="sec-ct">KeyType</span>EC-P256</div>
            <div class="sec-cert-field"><span class="sec-ct">Self-signed</span>yes</div>
            <div class="sec-cert-badge sec-cert-anchor">⚓ Trust anchor — must be pre-installed</div>
          </div>
        </div>
        <div class="sec-cert-arrow">↓ signs ↓</div>
        <div class="sec-cert-level">
          <div class="sec-cert-card">
            <div class="sec-cert-card-header">Key-Signing Key (KSK)</div>
            <div class="sec-cert-field"><span class="sec-ct">Name</span>${ksk}</div>
            <div class="sec-cert-field"><span class="sec-ct">KeyType</span>EC-P256</div>
            <div class="sec-cert-field"><span class="sec-ct">SignedBy</span>${trustAnchor}</div>
            <div class="sec-cert-badge sec-cert-ksk">🔑 Operator key — signs DSK certs</div>
          </div>
        </div>
        <div class="sec-cert-arrow">↓ signs ↓</div>
        <div class="sec-cert-level">
          <div class="sec-cert-card">
            <div class="sec-cert-card-header">Data-Signing Key (DSK)</div>
            <div class="sec-cert-field"><span class="sec-ct">Name</span>${dsk}</div>
            <div class="sec-cert-field"><span class="sec-ct">KeyType</span>EC-P256</div>
            <div class="sec-cert-field"><span class="sec-ct">SignedBy</span>${ksk}</div>
            <div class="sec-cert-badge sec-cert-dsk">📝 Application key — signs data packets</div>
          </div>
        </div>
        <div class="sec-cert-arrow">↓ signs ↓</div>
        <div class="sec-cert-level">
          <div class="sec-cert-card sec-cert-card-data">
            <div class="sec-cert-card-header">Data Packet</div>
            <div class="sec-cert-field"><span class="sec-ct">Name</span>${appName}</div>
            <div class="sec-cert-field"><span class="sec-ct">Content</span>"${this._content || 'Hello, NDN!'}"</div>
            <div class="sec-cert-field"><span class="sec-ct">SignedBy</span>${dsk}</div>
          </div>
        </div>
        <div class="sec-cert-note">
          Verification follows the chain upward: Data → DSK → KSK → Trust Anchor.
          Each step checks that the signing key name matches the KeyLocator in the packet's SignatureInfo.
        </div>
      </div>
    `;
  }
}
