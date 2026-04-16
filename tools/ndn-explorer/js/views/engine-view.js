/**
 * Engine View — ndn-fwd pipeline visualization.
 *
 * Renders the forwarding pipeline as an interactive SVG with:
 * - Left-to-right stage flow for Interest/Data/Nack paths
 * - Living data structure panels (PIT table, FIB trie, CS grid)
 * - PacketContext strip showing ownership transfer between stages
 * - Bytes lifecycle with ref-count tracking
 * - Rust feature animations (SmallVec, DashMap, hand-over-hand locking)
 * - Step-by-step animation with configurable speed and scenarios
 * - Inline security chain walk in the Validation stage
 *
 * Everything is HTML/SVG — no Three.js.  Text scales with zoom.
 * Every element is interactive (hover for design notes, click for details).
 */

import { LAYER_COLORS } from '../app.js';

// ═════════════════════════════════════════════════════════════════════════════
//  ANIMATION ENGINE — step-based controller that all components subscribe to
// ═════════════════════════════════════════════════════════════════════════════

class AnimationEngine {
  constructor() {
    this.steps = [];
    this.currentStep = -1;
    this.speed = 1.0;           // multiplier
    this.state = 'stopped';     // 'stopped' | 'playing' | 'paused'
    this.subscribers = [];
    this._timer = null;
  }

  loadScenario(steps) {
    this.reset();
    this.steps = steps;
  }

  subscribe(fn) { this.subscribers.push(fn); }

  _notify(direction) {
    const step = this.steps[this.currentStep];
    for (const fn of this.subscribers) fn(this.currentStep, step, direction);
  }

  play() {
    if (this.steps.length === 0) return;
    this.state = 'playing';
    this._scheduleNext();
  }

  pause() {
    this.state = 'paused';
    clearTimeout(this._timer);
  }

  step() {
    if (this.currentStep < this.steps.length - 1) {
      this.currentStep++;
      this._notify('forward');
    }
  }

  stepBack() {
    if (this.currentStep > 0) {
      this.currentStep--;
      this._notify('backward');
    }
  }

  reset() {
    this.state = 'stopped';
    this.currentStep = -1;
    clearTimeout(this._timer);
    this._notify('reset');
  }

  setSpeed(s) { this.speed = s; }

  _scheduleNext() {
    if (this.state !== 'playing') return;
    if (this.currentStep >= this.steps.length - 1) {
      this.state = 'stopped';
      return;
    }
    const nextStep = this.steps[this.currentStep + 1];
    // Duration proportional to real latency: 1µs ≈ 800ms at 1x speed
    const baseMs = (nextStep.durationNs || 1000) / 1000 * 800;
    const ms = Math.max(200, baseMs / this.speed);
    this._timer = setTimeout(() => {
      this.currentStep++;
      this._notify('forward');
      this._scheduleNext();
    }, ms);
  }
}

// ═════════════════════════════════════════════════════════════════════════════
//  SCENARIO BUILDER — generates animation steps from engine.json + config
// ═════════════════════════════════════════════════════════════════════════════

const PRESETS = {
  'interest-cs-miss': {
    label: 'Interest → CS miss → forward',
    type: 'interest',
    name: '/ndn/edu/ucla/cs/class',
    csHit: false,
    pitExists: false,
    fibMatch: '/ndn/edu/ucla',
    fibFaceId: 3,
    fibCost: 10,
  },
  'interest-cs-hit': {
    label: 'Interest → CS hit (fastest path)',
    type: 'interest',
    name: '/ndn/edu/ucla/cs/class',
    csHit: true,
    pitExists: false,
  },
  'interest-aggregation': {
    label: 'Interest aggregation (PIT exists)',
    type: 'interest',
    name: '/ndn/edu/ucla/cs/class',
    csHit: false,
    pitExists: true,
  },
  'interest-loop': {
    label: 'Loop detection (duplicate nonce)',
    type: 'interest',
    name: '/ndn/edu/ucla/cs/class',
    csHit: false,
    pitExists: true,
    duplicateNonce: true,
  },
  'data-full': {
    label: 'Data → validate → PIT match → CS insert',
    type: 'data',
    name: '/ndn/edu/ucla/cs/class',
    securityProfile: 'default',
    pitExists: true,
  },
  'data-unsolicited': {
    label: 'Data → unsolicited (no PIT entry)',
    type: 'data',
    name: '/ndn/edu/ucla/cs/class',
    securityProfile: 'disabled',
    pitExists: false,
  },
  'data-security-chain': {
    label: 'Data → full Ed25519 chain walk',
    type: 'data',
    name: '/sensor/node1/temp/1712400000',
    securityProfile: 'default',
    pitExists: true,
    certCached: true,
    schemaRule: '/sensor/<node>/<type> => /sensor/<node>/KEY/<id>',
  },
  'nack-retry': {
    label: 'Nack → strategy retries alternate nexthop',
    type: 'nack',
    name: '/ndn/edu/ucla/cs/class',
    nackReason: 'NoRoute',
    pitExists: true,
    altFaceId: 5,
    altCost: 20,
  },
  'nack-propagate': {
    label: 'Nack → propagated to consumers',
    type: 'nack',
    name: '/ndn/edu/ucla/cs/class',
    nackReason: 'Congestion',
    pitExists: true,
    noAlternate: true,
  },
  'discovery-consumed': {
    label: 'Discovery hello consumed (never enters pipeline)',
    type: 'interest',
    name: '/localhop/_discovery/hello',
    discoveryConsumed: true,
  },
  'concurrent-2pkt': {
    label: 'Two concurrent Interests (DashMap sharding)',
    type: 'concurrent',
    packets: [
      { name: '/ndn/edu/ucla/paper', csHit: false, pitExists: false, fibMatch: '/ndn/edu/ucla', fibFaceId: 3 },
      { name: '/ndn/com/google/search', csHit: false, pitExists: false, fibMatch: '/ndn/com/google', fibFaceId: 2 },
    ],
  },
};

function buildSteps(scenario, engineData) {
  const steps = [];
  const stages = engineData.pipeline?.stages || {};
  const timescales = {};
  for (const [id, s] of Object.entries(stages)) {
    timescales[id] = parseNs(s.timescale ? Object.values(s.timescale)[0] : '500 ns');
  }

  // Helper to add a step
  const add = (opts) => steps.push({
    stage: opts.stage,
    durationNs: timescales[opts.stage] || 500,
    fieldsSet: opts.fieldsSet || [],
    fieldValues: opts.fieldValues || {},
    tableOp: opts.tableOp || null,
    bytesOp: opts.bytesOp || null,
    rustFeature: opts.rustFeature || null,
    securityStep: opts.securityStep || null,
    action: opts.action || 'Continue',
    detail: opts.detail || '',
    terminal: opts.terminal || false,
  });

  if (scenario.type === 'interest') {
    // Inbound
    add({
      stage: 'inbound',
      fieldsSet: ['raw_bytes', 'face_id', 'arrival'],
      fieldValues: { raw_bytes: `Bytes(${scenario.name})`, face_id: 'face:1', arrival: 'now()' },
      bytesOp: { label: 'BytesMut::freeze()', rc: 1, note: 'Kernel recv → Bytes' },
      detail: `Interest for ${scenario.name} arrives on face 1`,
    });

    // Decode
    add({
      stage: 'decode',
      durationNs: 681,
      fieldsSet: ['name', 'packet', 'name_hashes'],
      fieldValues: { name: `Arc<Name>(${scenario.name})`, packet: 'Interest', name_hashes: 'NameHashes(...)' },
      bytesOp: { label: 'raw_bytes.clone()', rc: 2, note: 'Interest::decode() — ref-count +1, same allocation' },
      rustFeature: 'zero_copy',
      detail: 'TLV parse: Name decoded eagerly, Nonce/Lifetime behind OnceLock<T>',
    });

    // CS Lookup
    if (scenario.csHit) {
      add({
        stage: 'cs_lookup',
        durationNs: 856,
        fieldsSet: ['cs_hit'],
        fieldValues: { cs_hit: 'true' },
        tableOp: { table: 'cs', op: 'hit', name: scenario.name },
        bytesOp: { label: 'CsEntry.data.clone()', rc: 3, note: 'Cache hit returns wire-format Bytes — zero re-encoding' },
        rustFeature: 'zero_copy',
        action: 'Satisfy',
        detail: `CS hit! Cached Data sent directly to consumer. Fastest path: ~1.24µs total.`,
        terminal: true,
      });
    } else {
      add({
        stage: 'cs_lookup',
        durationNs: 622,
        fieldsSet: ['cs_hit'],
        fieldValues: { cs_hit: 'false' },
        tableOp: { table: 'cs', op: 'miss', name: scenario.name },
        detail: 'CS miss — no cached entry. Continue to PIT.',
      });

      // PIT Check
      if (scenario.duplicateNonce) {
        add({
          stage: 'pit_check',
          durationNs: 2580,
          tableOp: { table: 'pit', op: 'loop_detected', name: scenario.name },
          rustFeature: 'dashmap',
          action: 'Drop(LoopDetected)',
          detail: 'Same nonce seen from different face — forwarding loop detected.',
          terminal: true,
        });
      } else if (scenario.pitExists) {
        add({
          stage: 'pit_check',
          durationNs: 2580,
          tableOp: { table: 'pit', op: 'aggregate', name: scenario.name, face: 1 },
          rustFeature: 'smallvec',
          action: 'Drop(Aggregated)',
          detail: 'PIT entry exists — Interest aggregated (in-record added), not forwarded again.',
          terminal: true,
        });
      } else {
        add({
          stage: 'pit_check',
          durationNs: 1400,
          fieldsSet: ['pit_token'],
          fieldValues: { pit_token: `PitToken(0x${Math.random().toString(16).slice(2,10)})` },
          tableOp: { table: 'pit', op: 'insert', name: scenario.name, face: 1, nonce: Math.floor(Math.random() * 0xFFFFFFFF) },
          rustFeature: 'dashmap',
          detail: 'New PIT entry created. DashMap insert — sharded, lock-free on unrelated names.',
        });

        // Strategy
        add({
          stage: 'strategy',
          durationNs: 94,
          fieldsSet: ['out_faces'],
          fieldValues: { out_faces: `SmallVec[face:${scenario.fibFaceId || 3}]` },
          tableOp: { table: 'fib', op: 'lpm', name: scenario.name, match: scenario.fibMatch || '/ndn' },
          rustFeature: 'decide_sync',
          action: 'Send',
          detail: `FIB LPM → ${scenario.fibMatch || '/ndn'} (face ${scenario.fibFaceId || 3}, cost ${scenario.fibCost || 10}). BestRoute::decide_sync() — no Box::pin.`,
          terminal: true,
        });
      }
    }
  } else if (scenario.type === 'data') {
    // Inbound
    add({
      stage: 'inbound',
      fieldsSet: ['raw_bytes', 'face_id', 'arrival'],
      fieldValues: { raw_bytes: `Bytes(${scenario.name})`, face_id: 'face:3', arrival: 'now()' },
      bytesOp: { label: 'BytesMut::freeze()', rc: 1, note: 'Kernel recv → Bytes' },
      detail: `Data for ${scenario.name} arrives on face 3`,
    });

    // Decode
    add({
      stage: 'decode',
      durationNs: 595,
      fieldsSet: ['name', 'packet', 'name_hashes'],
      fieldValues: { name: `Arc<Name>(${scenario.name})`, packet: 'Data', name_hashes: 'NameHashes(...)' },
      bytesOp: { label: 'raw_bytes.clone()', rc: 2, note: 'Data::decode() — ref-count +1' },
      rustFeature: 'zero_copy',
      detail: 'TLV parse identifies packet as Data (type 0x06).',
    });

    // Validation — expanded into sub-steps for security chain walk
    if (scenario.securityProfile === 'disabled') {
      add({
        stage: 'validation',
        durationNs: 724,
        securityStep: 'disabled',
        detail: 'Security profile: Disabled — passthrough (724ns overhead). Matches NFD default behavior.',
      });
    } else {
      // Step 1: Enter validation stage
      add({
        stage: 'validation',
        durationNs: 100,
        securityStep: 'enter',
        detail: 'Entering ValidationStage. SecurityProfile: Default — full chain validation enabled.',
      });

      // Step 2: Extract KeyLocator
      add({
        stage: 'validation',
        durationNs: 50,
        securityStep: 'extract_keylocator',
        detail: `KeyLocator extracted: /sensor/node1/KEY/k1 (from SignatureInfo field).`,
      });

      // Step 3: Trust schema check
      add({
        stage: 'validation',
        durationNs: 158,
        securityStep: 'schema_check',
        rustFeature: 'rwlock_read',
        detail: scenario.schemaRule
          ? `Schema check: ${scenario.schemaRule} — captures match. schema.read() acquires shared RwLock (~1µs).`
          : 'Trust schema check: data name and key name satisfy a rule. schema.read() shared lock.',
      });

      // Step 4: CertCache lookup
      add({
        stage: 'validation',
        durationNs: 80,
        securityStep: scenario.certCached ? 'cert_cache_hit' : 'cert_cache_miss',
        rustFeature: 'dashmap',
        detail: scenario.certCached
          ? 'CertCache hit — certificate found via DashMap<Arc<Name>, Certificate>. O(1) lookup.'
          : 'CertCache miss — spawning CertFetcher Interest to fetch certificate over the network.',
      });

      // Step 5: Verify signature
      add({
        stage: 'validation',
        durationNs: 44370,
        securityStep: 'verify_signature',
        rustFeature: 'sign_sync',
        detail: 'Ed25519 verification: 44.37µs (100B payload). Verifier::verify_sync() — CPU-only, no Box::pin.',
      });

      // Step 6: Chain walk — check if trust anchor
      add({
        stage: 'validation',
        durationNs: 500,
        securityStep: 'trust_anchor_check',
        detail: 'Issuer /sensor/KEY/root is a trust anchor — final signature verification.',
      });

      // Step 7: SafeData construction
      add({
        stage: 'validation',
        durationNs: 50,
        fieldsSet: ['verified'],
        fieldValues: { verified: 'true → SafeData ✓' },
        securityStep: 'safe_data',
        detail: 'Data promoted to SafeData { inner: Data, trust_path: CertChain([...]), verified_at }. pub(crate) fields — compiler-enforced proof of verification.',
      });
    }

    // PIT Match
    if (scenario.pitExists) {
      add({
        stage: 'pit_match',
        durationNs: 1910,
        fieldsSet: ['out_faces'],
        fieldValues: { out_faces: 'SmallVec[face:1]' },
        tableOp: { table: 'pit', op: 'satisfy', name: scenario.name },
        rustFeature: 'dashmap',
        action: 'Satisfy',
        detail: 'PIT match — collected in-record faces, entry removed atomically (DashMap entry API).',
      });
    } else {
      add({
        stage: 'pit_match',
        durationNs: 1310,
        tableOp: { table: 'pit', op: 'miss', name: scenario.name },
        action: 'Drop(Unsolicited)',
        detail: 'No PIT entry — unsolicited Data dropped. Security feature: prevents cache pollution.',
        terminal: true,
      });
    }

    // CS Insert (only if PIT matched)
    if (scenario.pitExists) {
      add({
        stage: 'cs_insert',
        durationNs: 7620,
        tableOp: { table: 'cs', op: 'insert', name: scenario.name },
        bytesOp: { label: 'cs.insert(raw_bytes.clone())', rc: 3, note: 'CS stores same Bytes allocation — wire-format preserved' },
        rustFeature: 'zero_copy',
        action: 'Satisfy',
        detail: 'Data cached for future CS hits, then fanned out to all in-record faces.',
        terminal: true,
      });
    }
  } else if (scenario.type === 'nack') {
    // ── Nack pipeline ─────────────────────────────────────────────────
    add({
      stage: 'inbound',
      fieldsSet: ['raw_bytes', 'face_id', 'arrival'],
      fieldValues: { raw_bytes: `Bytes(Nack:${scenario.name})`, face_id: 'face:3', arrival: 'now()' },
      bytesOp: { label: 'BytesMut::freeze()', rc: 1, note: 'Nack arrives from upstream' },
      detail: `Nack for ${scenario.name} arrives (reason: ${scenario.nackReason}).`,
    });

    add({
      stage: 'decode',
      durationNs: 500,
      fieldsSet: ['name', 'packet'],
      fieldValues: { name: `Arc<Name>(${scenario.name})`, packet: `Nack(${scenario.nackReason})` },
      detail: 'TLV parse identifies Nack with embedded Interest and reason code.',
    });

    // PIT lookup — the pending entry is still there
    add({
      stage: 'nack_pit_lookup',
      durationNs: 800,
      fieldsSet: ['pit_token'],
      fieldValues: { pit_token: 'PitToken(existing)' },
      tableOp: { table: 'pit', op: 'highlight', name: scenario.name },
      detail: 'PIT entry found — Interest is still pending. Strategy gets full context.',
    });

    // Strategy decision on Nack
    if (scenario.noAlternate) {
      add({
        stage: 'nack_strategy',
        durationNs: 200,
        action: 'Nack(propagate)',
        detail: `No alternate nexthops — Nack propagated to all ${scenario.pitExists ? 'in-record consumers' : 'requesters'}. Strategy gives up.`,
        terminal: true,
      });
    } else {
      add({
        stage: 'nack_strategy',
        durationNs: 200,
        fieldsSet: ['out_faces'],
        fieldValues: { out_faces: `SmallVec[face:${scenario.altFaceId || 5}]` },
        rustFeature: 'decide_sync',
        action: 'Forward(retry)',
        detail: `BestRoute retries on alternate nexthop: face ${scenario.altFaceId || 5} (cost ${scenario.altCost || 20}). Automatic failover — no application retry logic needed.`,
        terminal: true,
      });
    }
  }

  // ── Discovery consumed (special Interest case) ──────────────────────
  if (scenario.type === 'interest' && scenario.discoveryConsumed) {
    // Override: only inbound + decode + discovery consumed
    steps.length = 0;
    add({
      stage: 'inbound',
      fieldsSet: ['raw_bytes', 'face_id', 'arrival'],
      fieldValues: { raw_bytes: `Bytes(${scenario.name})`, face_id: 'face:1', arrival: 'now()' },
      detail: `Interest for ${scenario.name} arrives on face 1.`,
    });
    add({
      stage: 'decode',
      durationNs: 681,
      fieldsSet: ['name', 'packet'],
      fieldValues: { name: `Arc<Name>(${scenario.name})`, packet: 'Interest' },
      detail: 'TLV parse identifies as Interest.',
    });
    add({
      stage: 'discovery',
      durationNs: 100,
      action: 'Consumed',
      detail: `Discovery hook: on_inbound() returns true — packet consumed by discovery subsystem. Never enters forwarding pipeline.`,
      terminal: true,
    });
  }

  // ── Concurrent packets (multi-step interleaved) ─────────────────────
  if (scenario.type === 'concurrent' && scenario.packets) {
    steps.length = 0;
    // Build steps for each packet, tag with packet index
    for (let pi = 0; pi < scenario.packets.length; pi++) {
      const pkt = scenario.packets[pi];
      const pktSteps = buildSteps({ type: 'interest', ...pkt }, engineData);
      for (const s of pktSteps) {
        s.packetIndex = pi;
        s.detail = `[Pkt ${pi + 1}] ${s.detail}`;
        steps.push(s);
      }
    }
    // Interleave: sort by stage order, keeping packet index as tiebreaker
    const stageOrder = ['inbound', 'decode', 'discovery', 'cs_lookup', 'pit_check', 'strategy'];
    steps.sort((a, b) => {
      const oa = stageOrder.indexOf(a.stage), ob = stageOrder.indexOf(b.stage);
      if (oa !== ob) return oa - ob;
      return (a.packetIndex || 0) - (b.packetIndex || 0);
    });
  }

  return steps;
}

function parseNs(str) {
  if (!str || typeof str !== 'string') return 500;
  const m = str.match(/([\d.]+)\s*(ns|µs|us|ms)/);
  if (!m) return 500;
  const v = parseFloat(m[1]);
  switch (m[2]) {
    case 'ns': return v;
    case 'µs': case 'us': return v * 1000;
    case 'ms': return v * 1e6;
    default: return 500;
  }
}

function formatNs(ns) {
  if (ns < 1000) return `${Math.round(ns)} ns`;
  if (ns < 1e6) return `${(ns/1000).toFixed(1)} µs`;
  return `${(ns/1e6).toFixed(2)} ms`;
}

// ═════════════════════════════════════════════════════════════════════════════
//  ENGINE VIEW — main class
// ═════════════════════════════════════════════════════════════════════════════

export class EngineView {
  constructor(container, app) {
    this.container = container;
    this.app = app;
    this.engine = new AnimationEngine();
    this.ed = null;          // engine data
    this._built = false;

    // State for data structures
    this.pitEntries = [];
    this.csEntries = [];
    this.fibRoutes = [
      { prefix: '/ndn/edu/ucla', nexthops: [{ face: 3, cost: 10 }] },
      { prefix: '/ndn/edu/mit', nexthops: [{ face: 5, cost: 20 }] },
      { prefix: '/ndn/com/google', nexthops: [{ face: 2, cost: 5 }] },
    ];

    // Scenario
    this.currentPreset = 'interest-cs-miss';
    this.scenario = { ...PRESETS['interest-cs-miss'] };

    // Config panel
    this.configOpen = false;

    // Tooltip
    this.tooltipEl = null;
  }

  onShow() {
    if (!this._built) {
      try {
        this._build();
        this._built = true;
      } catch (e) {
        console.error('EngineView build error:', e);
        this.container.innerHTML = `<div style="padding:2rem;color:#ff7b72;">
          <h3>Engine View Error</h3>
          <pre style="font-size:0.75rem;color:#e6edf3;background:#161b22;padding:1rem;border-radius:6px;overflow:auto;">${e.stack || e.message || e}</pre>
        </div>`;
      }
    }
  }

  _build() {
    this.ed = this.app.engineData;
    this.container.innerHTML = '';
    this.container.classList.add('ev-root');

    // Tooltip
    this.tooltipEl = document.createElement('div');
    this.tooltipEl.className = 'ev-tooltip';
    document.body.appendChild(this.tooltipEl);

    // Control bar
    this._buildControls();

    // Pipeline SVG
    this._buildPipelineSvg();

    // PacketContext strip
    this._buildContextStrip();

    // Security chain walk panel (inline, between context strip and data structures)
    this._buildSecurityPanel();

    // Data structure panels
    this._buildDataStructures();

    // Bytes lifecycle
    this._buildBytesLifecycle();

    // Scenario config panel
    this._buildConfigPanel();

    // Subscribe animation engine
    this.engine.subscribe((idx, step, dir) => this._onStep(idx, step, dir));

    // Load default scenario
    this._loadScenario();
  }

  // ── Control Bar ─────────────────────────────────────────────────────────

  _buildControls() {
    const bar = document.createElement('div');
    bar.className = 'ev-controls';
    bar.innerHTML = `
      <button class="ev-btn" data-act="play" title="Play animation">&#9654; Play</button>
      <button class="ev-btn" data-act="pause" title="Pause">&#9646;&#9646;</button>
      <button class="ev-btn" data-act="step" title="Step forward">&#9654;|</button>
      <button class="ev-btn" data-act="back" title="Step backward">|&#9664;</button>
      <button class="ev-btn" data-act="reset" title="Reset">&#8634;</button>
      <div class="ev-sep"></div>
      <div class="ev-speed">
        <span>Speed:</span>
        <input type="range" min="1" max="8" step="1" value="2" title="Animation speed">
        <span class="ev-speed-label">1x</span>
      </div>
      <div class="ev-sep"></div>
      <select class="ev-scenario-select" title="Choose scenario">
        ${Object.entries(PRESETS).map(([k, v]) =>
          `<option value="${k}" ${k === this.currentPreset ? 'selected' : ''}>${v.label}</option>`
        ).join('')}
      </select>
      <button class="ev-btn" data-act="config" title="Edit scenario">Edit...</button>
      <span class="ev-step-info" id="ev-step-info">Ready</span>
    `;
    this.container.appendChild(bar);

    // Wire buttons
    bar.querySelectorAll('.ev-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const act = btn.dataset.act;
        if (act === 'play') this.engine.play();
        else if (act === 'pause') this.engine.pause();
        else if (act === 'step') this.engine.step();
        else if (act === 'back') this.engine.stepBack();
        else if (act === 'reset') { this.engine.reset(); this._resetVisualization(); }
        else if (act === 'config') this._toggleConfig();
      });
    });

    // Speed slider
    const speedRange = bar.querySelector('input[type="range"]');
    const speedLabel = bar.querySelector('.ev-speed-label');
    const speeds = [0.25, 0.5, 1, 2, 4, 8, 12, 16];
    speedRange.addEventListener('input', () => {
      const s = speeds[parseInt(speedRange.value) - 1] || 1;
      this.engine.setSpeed(s);
      speedLabel.textContent = `${s}x`;
    });

    // Scenario select
    bar.querySelector('.ev-scenario-select').addEventListener('change', (e) => {
      this.currentPreset = e.target.value;
      this.scenario = { ...PRESETS[this.currentPreset] };
      this._loadScenario();
    });
  }

  // ── Pipeline SVG ────────────────────────────────────────────────────────

  _buildPipelineSvg() {
    const wrap = document.createElement('div');
    wrap.className = 'ev-pipeline-wrap';

    // SVG viewBox designed for a clear left-to-right flow
    const W = 1100, H = 520;
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
    svg.classList.add('ev-pipeline-svg');
    this.svg = svg;

    // Defs: create all elements with createElementNS for maximum reliability.
    const NS = 'http://www.w3.org/2000/svg';
    const defs = document.createElementNS(NS, 'defs');

    // Arrow markers
    for (const [id, color] of [['ev-arrow','#58a6ff'],['ev-arrow-red','#ff7b72'],['ev-arrow-green','#3fb950']]) {
      const m = document.createElementNS(NS, 'marker');
      m.id = id;
      for (const [k,v] of [['markerWidth','8'],['markerHeight','6'],['refX','7'],['refY','3'],['orient','auto']]) m.setAttribute(k,v);
      const p = document.createElementNS(NS, 'path');
      p.setAttribute('d', 'M0,0 L8,3 L0,6');
      p.setAttribute('fill', color);
      m.appendChild(p);
      defs.appendChild(m);
    }

    // Glow filter
    const flt = document.createElementNS(NS, 'filter');
    flt.id = 'ev-glow';
    const blur = document.createElementNS(NS, 'feGaussianBlur');
    blur.setAttribute('stdDeviation', '3');
    blur.setAttribute('result', 'blur');
    flt.appendChild(blur);
    const merge = document.createElementNS(NS, 'feMerge');
    const mn1 = document.createElementNS(NS, 'feMergeNode');
    mn1.setAttribute('in', 'blur');
    merge.appendChild(mn1);
    const mn2 = document.createElementNS(NS, 'feMergeNode');
    mn2.setAttribute('in', 'SourceGraphic');
    merge.appendChild(mn2);
    flt.appendChild(merge);
    defs.appendChild(flt);

    svg.appendChild(defs);

    // ── Stage layout ────────────────────────────────────────────────────
    // Interest path: top lane
    // Data path: bottom lane
    // Shared: inbound faces (left), outbound faces (right)

    const stageW = 130, stageH = 60;
    const laneY_interest = 60;
    const laneY_data = 230;
    const laneGap = 170;

    // Interest path stages
    const interestStages = [
      { id: 'decode', x: 200, y: laneY_interest, label: 'TLV Decode', time: '681 ns', share: 0.30 },
      { id: 'cs_lookup', x: 370, y: laneY_interest, label: 'CS Lookup', time: '622-856 ns', share: 0.10 },
      { id: 'pit_check', x: 540, y: laneY_interest, label: 'PIT Check', time: '1.40 µs', share: 0.15 },
      { id: 'strategy', x: 710, y: laneY_interest, label: 'Strategy', time: '94 ns', share: 0.20 },
    ];

    // Data path stages
    const dataStages = [
      { id: 'decode', x: 200, y: laneY_data, label: 'TLV Decode', time: '595 ns', share: 0.30 },
      { id: 'validation', x: 370, y: laneY_data, label: 'Validation', time: '724ns - 46µs', share: 0.0, w: 160 },
      { id: 'pit_match', x: 580, y: laneY_data, label: 'PIT Match', time: '1.91 µs', share: 0.15 },
      { id: 'cs_insert', x: 750, y: laneY_data, label: 'CS Insert', time: '1.10 µs', share: 0.10 },
    ];

    // ── Lane labels ─────────────────────────────────────────────────────
    this._svgText(svg, 20, laneY_interest + stageH/2, 'INTEREST PATH', 13, '#58a6ff', 'bold');
    this._svgText(svg, 20, laneY_data + stageH/2, 'DATA PATH', 13, '#3fb950', 'bold');

    // ── Inbound section ─────────────────────────────────────────────────
    // Faces → mpsc channel → batch drain → decode
    this._svgRect(svg, 30, 135, 80, 50, 4, '#1a2d50', '#30363d');
    this._svgText(svg, 70, 155, 'Faces In', 11, '#58a6ff');
    this._svgText(svg, 70, 168, '(recv loop)', 9, '#8b949e');

    // mpsc channel
    this._svgRect(svg, 130, 140, 50, 40, 4, '#332211', '#c87533');
    this._svgText(svg, 155, 157, 'mpsc', 9, '#c87533');
    this._svgText(svg, 155, 168, '4096', 8, '#8b949e');

    // Arrow: faces → mpsc
    this._svgArrow(svg, 110, 160, 130, 160, '#58a6ff');
    // Arrow: mpsc → decode (interest)
    this._svgArrow(svg, 180, 155, 200, laneY_interest + stageH/2, '#58a6ff');
    // Arrow: mpsc → decode (data)
    this._svgArrow(svg, 180, 165, 200, laneY_data + stageH/2, '#3fb950');

    // ── Outbound section ────────────────────────────────────────────────
    this._svgRect(svg, 910, 135, 80, 50, 4, '#1a3322', '#30363d');
    this._svgText(svg, 950, 155, 'Faces Out', 11, '#3fb950');
    this._svgText(svg, 950, 168, '(send queue)', 9, '#8b949e');

    // ── Render Interest stages ──────────────────────────────────────────
    this.stageEls = {};
    for (const s of interestStages) {
      this._renderStage(svg, s, stageW, stageH, '#1a2d50', '#58a6ff');
    }

    // Interest path arrows
    for (let i = 0; i < interestStages.length - 1; i++) {
      const from = interestStages[i], to = interestStages[i + 1];
      const fW = from.w || stageW;
      this._svgArrow(svg, from.x + fW, from.y + stageH/2, to.x, to.y + stageH/2, '#58a6ff');
    }
    // Strategy → faces out
    const lastI = interestStages[interestStages.length - 1];
    this._svgArrow(svg, lastI.x + stageW, lastI.y + stageH/2, 910, 155, '#58a6ff');

    // CS hit short-circuit: cs_lookup → Satisfy (down and left to faces out)
    const csStage = interestStages[1];
    this._svgPath(svg, `M${csStage.x + stageW/2},${csStage.y + stageH} L${csStage.x + stageW/2},${csStage.y + stageH + 25} L${910},${csStage.y + stageH + 25}`,
      '#3fb950', true, 'CS hit → Satisfy');

    // PIT aggregation/loop short-circuit: pit_check → Drop (down)
    const pitStage = interestStages[2];
    this._svgPath(svg, `M${pitStage.x + stageW/2},${pitStage.y + stageH} L${pitStage.x + stageW/2},${pitStage.y + stageH + 30}`,
      '#ff7b72', true, 'Aggregate / Loop → Drop');

    // ── Render Data stages ──────────────────────────────────────────────
    for (const s of dataStages) {
      this._renderStage(svg, s, s.w || stageW, stageH, '#1a3322', '#3fb950');
    }

    // Data path arrows
    for (let i = 0; i < dataStages.length - 1; i++) {
      const from = dataStages[i], to = dataStages[i + 1];
      const fW = from.w || stageW;
      this._svgArrow(svg, from.x + fW, from.y + stageH/2, to.x, to.y + stageH/2, '#3fb950');
    }
    // CS insert → faces out (Satisfy fan-out)
    const lastD = dataStages[dataStages.length - 1];
    this._svgArrow(svg, lastD.x + stageW, lastD.y + stageH/2, 910, 165, '#3fb950');

    // Unsolicited drop: pit_match → Drop
    const pmStage = dataStages[2];
    this._svgPath(svg, `M${pmStage.x + stageW/2},${pmStage.y + stageH} L${pmStage.x + stageW/2},${pmStage.y + stageH + 30}`,
      '#ff7b72', true, 'Unsolicited → Drop');

    // ── Nack path (third lane) ──────────────────────────────────────────
    const laneY_nack = 390;
    this._svgText(svg, 20, laneY_nack + stageH/2, 'NACK PATH', 13, '#ff7b72', 'bold');

    const nackStages = [
      { id: 'decode', x: 200, y: laneY_nack, label: 'TLV Decode', time: '~500 ns', share: 0.20 },
      { id: 'nack_pit_lookup', x: 400, y: laneY_nack, label: 'PIT Lookup', time: '~800 ns', share: 0.10 },
      { id: 'nack_strategy', x: 600, y: laneY_nack, label: 'Strategy', time: '~200 ns', share: 0.05 },
    ];
    for (const s of nackStages) {
      this._renderStage(svg, s, stageW, stageH, '#2d1a1a', '#ff7b72');
    }
    for (let i = 0; i < nackStages.length - 1; i++) {
      const from = nackStages[i], to = nackStages[i + 1];
      this._svgArrow(svg, from.x + stageW, from.y + stageH/2, to.x, to.y + stageH/2, '#ff7b72');
    }
    // Nack strategy → faces out (retry) or → faces in (propagate)
    const nackLast = nackStages[nackStages.length - 1];
    this._svgPath(svg, `M${nackLast.x + stageW},${nackLast.y + stageH/2} L${910},${nackLast.y + stageH/2 - 15}`,
      '#58a6ff', true, 'Retry → alternate face');
    this._svgPath(svg, `M${nackLast.x + stageW},${nackLast.y + stageH/2} L${910},${nackLast.y + stageH/2 + 15}`,
      '#ff7b72', true, 'Propagate → consumers');

    // mpsc → nack decode
    this._svgArrow(svg, 180, 170, 200, laneY_nack + stageH/2, '#ff7b72');

    // ── Batch drain visualization ───────────────────────────────────────
    // Small batch buffer indicator on the mpsc box
    this._svgRect(svg, 132, 122, 46, 14, 2, '#1a1a1a', '#c87533');
    this._svgText(svg, 155, 130, 'batch ≤64', 7, '#c87533');
    // Individual packet dots in the batch buffer (decorative)
    for (let i = 0; i < 6; i++) {
      const bx = 135 + i * 6;
      const bdot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      bdot.setAttribute('cx', bx); bdot.setAttribute('cy', 129);
      bdot.setAttribute('r', '2');
      bdot.setAttribute('fill', i < 4 ? '#58a6ff' : '#30363d');
      bdot.setAttribute('opacity', i < 4 ? '0.8' : '0.3');
      bdot.id = `ev-batch-dot-${i}`;
      svg.appendChild(bdot);
    }

    // ── Discovery hook (between mpsc and decode) ────────────────────────
    // Small diamond between the channel and decode stages
    const discX = 190, discY_i = laneY_interest + stageH/2, discY_d = laneY_data + stageH/2;
    const discSize = 8;
    const discDiamond = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
    discDiamond.setAttribute('points', `${discX},${discY_i - discSize} ${discX + discSize},${discY_i} ${discX},${discY_i + discSize} ${discX - discSize},${discY_i}`);
    discDiamond.setAttribute('fill', '#d29922');
    discDiamond.setAttribute('opacity', '0.5');
    discDiamond.id = 'ev-discovery-hook';
    discDiamond.style.cursor = 'pointer';
    discDiamond.addEventListener('mouseenter', (e) => {
      this.tooltipEl.innerHTML = `<strong>Discovery Hook</strong><div>on_inbound() checks for /localhop/_discovery/ packets.</div><div>Hello/probe/SWIM packets are consumed here and never enter the forwarding pipeline.</div><div class="ev-tt-src">dispatcher/pipeline.rs</div>`;
      this._showTooltip(e);
    });
    discDiamond.addEventListener('mouseleave', () => this._hideTooltip());
    discDiamond.addEventListener('mousemove', (e) => this._moveTooltip(e));
    svg.appendChild(discDiamond);
    this._svgText(svg, discX, discY_i + discSize + 8, 'disc', 7, '#d29922');

    // (nack + discovery positions stored below with all other stagePositions)

    // ── Packet dots (animated — supports multiple for concurrent scenarios)
    const PACKET_COLORS = ['#58a6ff', '#d2a8ff', '#ffa657'];
    this.packetDots = [];
    for (let i = 0; i < 3; i++) {
      const dot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      dot.setAttribute('r', i === 0 ? '8' : '6');
      dot.setAttribute('fill', PACKET_COLORS[i]);
      dot.setAttribute('cx', '-20');
      dot.setAttribute('cy', '-20');
      dot.classList.add('ev-packet-dot');
      dot.setAttribute('filter', 'url(#ev-glow)');
      dot.style.display = i === 0 ? 'block' : 'none';
      svg.appendChild(dot);
      this.packetDots.push(dot);
    }
    this.packetDot = this.packetDots[0]; // backwards compat

    // Store stage positions for animation
    this.stagePositions = {};
    for (const s of [...interestStages, ...dataStages]) {
      this.stagePositions[s.id + '_' + (s.y < 200 ? 'interest' : 'data')] = {
        cx: s.x + (s.w || stageW) / 2,
        cy: s.y + stageH / 2,
      };
    }
    // Also store inbound/outbound
    this.stagePositions['inbound_interest'] = { cx: 155, cy: 155 };
    this.stagePositions['inbound_data'] = { cx: 155, cy: 165 };
    // Nack stage positions
    for (const s of nackStages) {
      this.stagePositions[s.id + '_nack'] = { cx: s.x + stageW/2, cy: s.y + stageH/2 };
    }
    // Discovery hook position
    this.stagePositions['discovery_interest'] = { cx: discX, cy: discY_i };

    wrap.appendChild(svg);
    this.container.appendChild(wrap);
  }

  _renderStage(svg, s, w, h, fill, stroke) {
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.classList.add('ev-stage-box');
    g.dataset.stage = s.id;

    // Background rect
    const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    rect.setAttribute('x', s.x); rect.setAttribute('y', s.y);
    rect.setAttribute('width', w); rect.setAttribute('height', h);
    rect.setAttribute('rx', '6');
    rect.setAttribute('fill', fill); rect.setAttribute('stroke', stroke);
    rect.setAttribute('stroke-width', '1.5');
    rect.classList.add('ev-stage-rect');
    g.appendChild(rect);

    // Label
    this._svgText(g, s.x + w/2, s.y + 20, s.label, 12, '#e6edf3', 'bold');

    // Timing
    if (s.time) {
      this._svgText(g, s.x + w/2, s.y + 36, s.time, 10, '#d29922');
    }

    // Timing bar (proportional width)
    if (s.share > 0) {
      const barW = Math.max(8, w * Math.min(s.share * 3, 1));
      const barColor = s.share < 0.12 ? '#3fb950' : s.share < 0.2 ? '#d29922' : '#ff7b72';
      const bar = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      bar.setAttribute('x', s.x + 4); bar.setAttribute('y', s.y + h - 8);
      bar.setAttribute('width', barW); bar.setAttribute('height', 4);
      bar.setAttribute('rx', '2'); bar.setAttribute('fill', barColor);
      bar.setAttribute('opacity', '0.7');
      g.appendChild(bar);
    }

    // Hover: show tooltip
    g.addEventListener('mouseenter', (e) => {
      const stageData = this.ed?.pipeline?.stages?.[s.id];
      if (!stageData) return;
      const reads = (stageData.reads || []).join(', ');
      const writes = (stageData.writes || []).join(', ');
      const shorts = (stageData.short_circuits || []).map(sc => `${sc.action}: ${sc.description}`).join('<br>');
      this.tooltipEl.innerHTML = `
        <strong>${stageData.chip_label}</strong>
        <div style="margin:0.2rem 0"><code>${stageData.signature || ''}</code></div>
        <div><strong>Reads:</strong> ${reads || 'none'} &nbsp; <strong>Writes:</strong> ${writes || 'none'}</div>
        ${shorts ? `<div style="margin-top:0.2rem"><strong>Short-circuits:</strong><br>${shorts}</div>` : ''}
        <div style="margin-top:0.3rem">${stageData.design_note || ''}</div>
        <div class="ev-tt-src">${stageData.source || ''}</div>
        <div class="ev-tt-time">Timing: ${JSON.stringify(stageData.timescale || {})}</div>
      `;
      this._showTooltip(e);
    });
    g.addEventListener('mouseleave', () => this._hideTooltip());
    g.addEventListener('mousemove', (e) => this._moveTooltip(e));

    // Click: open wiki link in new tab
    g.addEventListener('click', () => {
      const stageData = this.ed?.pipeline?.stages?.[s.id];
      if (stageData?.wiki_link) {
        window.open(`../wiki/${stageData.wiki_link}`, '_blank', 'noopener');
      }
    });

    svg.appendChild(g);
    const lane = s.y < 200 ? 'interest' : s.y < 350 ? 'data' : 'nack';
    this.stageEls[s.id + '_' + lane] = g;
  }

  // ── PacketContext Strip ──────────────────────────────────────────────────

  _buildContextStrip() {
    const strip = document.createElement('div');
    strip.className = 'ev-ctx-strip';
    strip.innerHTML = `
      <div class="ev-ctx-header">
        <span class="ev-ctx-title">PacketContext</span>
        <span class="ev-ctx-ownership">owned by: <span class="ev-ctx-owner-name" id="ev-ctx-owner">—</span> <span class="ev-rust-badge">move semantics</span></span>
      </div>
      <div class="ev-ctx-fields" id="ev-ctx-fields"></div>
      <div class="ev-ctx-note" id="ev-ctx-note"></div>
    `;
    this.container.appendChild(strip);

    const fieldsDiv = strip.querySelector('#ev-ctx-fields');
    const fields = this.ed?.context_fields || [];
    for (const f of fields) {
      const card = document.createElement('div');
      card.className = 'ev-ctx-field';
      card.id = `ev-cf-${f.name}`;
      card.innerHTML = `
        <span class="ev-ctx-fname">${f.name}</span>
        <span class="ev-ctx-ftype">${f.type}</span>
        <span class="ev-ctx-fval" id="ev-cfv-${f.name}"></span>
      `;
      card.title = `${f.description}\nSet by: ${f.set_by}`;
      fieldsDiv.appendChild(card);
    }
  }

  // ── Security Chain Walk Panel ──────────────────────────────────────────

  _buildSecurityPanel() {
    const sec = this.ed?.security;
    const chainSteps = sec?.validator?.chain_walk || [];
    const profiles = sec?.profiles || [];

    const panel = document.createElement('div');
    panel.className = 'ev-security-expand';
    panel.id = 'ev-security-panel';

    // Build the step-by-step chain walk visualization
    const stepsHtml = [
      { id: 'enter', icon: '🔒', label: 'Enter Validation', sub: 'SecurityProfile determines behavior' },
      { id: 'extract_keylocator', icon: '🔑', label: 'Extract KeyLocator', sub: 'Identify signing key from SignatureInfo' },
      { id: 'schema_check', icon: '📋', label: 'Trust Schema Check', sub: 'schema.read() — shared RwLock, ~1µs' },
      { id: 'cert_cache_hit', icon: '✅', label: 'CertCache Hit', sub: 'DashMap<Arc<Name>, Certificate> — O(1)' },
      { id: 'cert_cache_miss', icon: '❌', label: 'CertCache Miss', sub: 'Spawn CertFetcher Interest → Pending' },
      { id: 'verify_signature', icon: '🔐', label: 'Verify Signature', sub: 'Ed25519: 44.37µs — sign_sync() avoids Box::pin' },
      { id: 'trust_anchor_check', icon: '⚓', label: 'Trust Anchor Check', sub: 'Chain terminates at pre-configured root' },
      { id: 'safe_data', icon: '✓', label: 'SafeData Constructed', sub: 'pub(crate) fields — compiler enforces verification proof' },
      { id: 'disabled', icon: '⏭', label: 'Passthrough (Disabled)', sub: '724ns — no validation, matches NFD default' },
    ];

    panel.innerHTML = `
      <div style="padding:0.5rem 0.75rem;">
        <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.4rem;">
          <strong style="color:#d29922;font-size:0.82rem;">Security Chain Walk</strong>
          <span class="ev-rust-badge">Arc&lt;RwLock&lt;TrustSchema&gt;&gt;</span>
          <span style="margin-left:auto;font-size:0.68rem;color:var(--text2);">
            Profile: <span id="ev-sec-profile" style="color:#d29922;">—</span>
          </span>
        </div>

        <div style="display:flex;gap:0.3rem;margin-bottom:0.5rem;" id="ev-sec-profiles">
          ${profiles.map(p => `
            <span class="ev-sec-profile-badge" data-profile="${p.name.toLowerCase()}"
                  style="padding:0.1rem 0.4rem;border-radius:3px;font-size:0.64rem;border:1px solid var(--border);opacity:0.4;transition:all 0.3s;"
                  title="${p.use_case}">
              ${p.name} ${p.sig_verify ? '✓sig' : ''} ${p.chain_fetch === true ? '✓chain' : ''}
            </span>
          `).join('')}
        </div>

        <div id="ev-sec-steps">
          ${stepsHtml.map(s => `
            <div class="ev-sec-step" id="ev-sec-step-${s.id}">
              <span class="ev-sec-icon">${s.icon}</span>
              <div>
                <div style="font-weight:600;">${s.label}</div>
                <div style="font-size:0.62rem;color:var(--text2);">${s.sub}</div>
              </div>
            </div>
          `).join('')}
        </div>

        <div id="ev-sec-schema-rule" style="display:none;margin-top:0.4rem;padding:0.3rem 0.5rem;border:1px solid rgba(210,153,34,0.2);border-radius:4px;font-family:monospace;font-size:0.7rem;color:#d29922;">
        </div>

        <div id="ev-sec-safedata" style="display:none;margin-top:0.4rem;">
          <span class="ev-safedata-badge">🔒 SafeData ✓</span>
          <span style="font-size:0.66rem;color:var(--text2);margin-left:0.5rem;">
            trust_path: <code>CertChain</code> | verified_at: <code>now()</code> | fields: <code>pub(crate)</code>
          </span>
        </div>
      </div>
    `;
    this.container.appendChild(panel);
  }

  _animateSecurityStep(stepId) {
    const panel = document.getElementById('ev-security-panel');
    if (!panel) return;

    // Open the panel
    panel.classList.add('open');

    // Highlight the active profile
    if (stepId === 'disabled') {
      panel.querySelector('[data-profile="disabled"]')?.style.setProperty('opacity', '1');
      panel.querySelector('[data-profile="disabled"]')?.style.setProperty('border-color', '#d29922');
      const profEl = document.getElementById('ev-sec-profile');
      if (profEl) profEl.textContent = 'Disabled';
    } else if (stepId === 'enter') {
      panel.querySelector('[data-profile="default"]')?.style.setProperty('opacity', '1');
      panel.querySelector('[data-profile="default"]')?.style.setProperty('border-color', '#d29922');
      const profEl = document.getElementById('ev-sec-profile');
      if (profEl) profEl.textContent = 'Default';
    }

    // Activate the step
    const stepEl = document.getElementById(`ev-sec-step-${stepId}`);
    if (stepEl) {
      stepEl.classList.add('active');
      // Mark previous steps as passed
      let prev = stepEl.previousElementSibling;
      while (prev) {
        if (prev.classList.contains('ev-sec-step')) prev.classList.add('passed');
        prev = prev.previousElementSibling;
      }
    }

    // Show schema rule for schema_check step
    if (stepId === 'schema_check' && this.scenario.schemaRule) {
      const ruleEl = document.getElementById('ev-sec-schema-rule');
      if (ruleEl) {
        ruleEl.style.display = 'block';
        // Highlight captures in the rule
        const rule = this.scenario.schemaRule;
        const highlighted = rule.replace(/<(\w+)>/g, '<span style="color:#58a6ff;font-weight:700;">&lt;$1&gt;</span>');
        ruleEl.innerHTML = `Rule: ${highlighted}`;
      }
    }

    // Show SafeData badge for safe_data step
    if (stepId === 'safe_data') {
      const sdEl = document.getElementById('ev-sec-safedata');
      if (sdEl) sdEl.style.display = 'block';
    }
  }

  _resetSecurityPanel() {
    const panel = document.getElementById('ev-security-panel');
    if (!panel) return;
    panel.classList.remove('open');
    panel.querySelectorAll('.ev-sec-step').forEach(el => {
      el.classList.remove('active', 'passed');
    });
    panel.querySelectorAll('.ev-sec-profile-badge').forEach(el => {
      el.style.opacity = '0.4';
      el.style.borderColor = 'var(--border)';
    });
    const ruleEl = document.getElementById('ev-sec-schema-rule');
    if (ruleEl) ruleEl.style.display = 'none';
    const sdEl = document.getElementById('ev-sec-safedata');
    if (sdEl) sdEl.style.display = 'none';
  }

  // ── Data Structure Panels ───────────────────────────────────────────────

  _buildDataStructures() {
    const tables = document.createElement('div');
    tables.className = 'ev-tables';

    // PIT
    const pitPanel = document.createElement('div');
    pitPanel.className = 'ev-table-panel';
    pitPanel.innerHTML = `
      <div class="ev-table-title">Pending Interest Table <code>DashMap&lt;PitToken, PitEntry&gt;</code></div>
      <table class="ev-pit-table">
        <thead><tr><th>Name</th><th>In-Records</th><th>Nonces <span class="ev-rust-badge">SmallVec[4]</span></th><th>Expires</th></tr></thead>
        <tbody id="ev-pit-body"></tbody>
      </table>
    `;
    tables.appendChild(pitPanel);

    // FIB
    const fibPanel = document.createElement('div');
    fibPanel.className = 'ev-table-panel';
    fibPanel.innerHTML = `
      <div class="ev-table-title">Forwarding Information Base <code>NameTrie&lt;Arc&lt;FibEntry&gt;&gt;</code></div>
      <div class="ev-fib-trie" id="ev-fib-trie"></div>
    `;
    tables.appendChild(fibPanel);
    this._renderFibTrie(fibPanel.querySelector('#ev-fib-trie'));

    // CS
    const csPanel = document.createElement('div');
    csPanel.className = 'ev-table-panel';
    csPanel.innerHTML = `
      <div class="ev-table-title">Content Store <code>dyn ContentStore (LruCs)</code></div>
      <div class="ev-cs-grid" id="ev-cs-grid"></div>
      <div class="ev-cs-stats" id="ev-cs-stats">hits: 0 &nbsp; misses: 0 &nbsp; entries: 0</div>
    `;
    tables.appendChild(csPanel);
    this._renderCsGrid(csPanel.querySelector('#ev-cs-grid'));

    this.container.appendChild(tables);
  }

  _renderFibTrie(container) {
    // Build a visual trie from fibRoutes
    const trie = {};
    for (const route of this.fibRoutes) {
      const parts = route.prefix.split('/').filter(Boolean);
      let node = trie;
      for (const p of parts) {
        if (!node[p]) node[p] = { _children: {}, _nexthops: null };
        node = node[p]._children;
      }
      // Attach nexthops to the last node... hacky but works for display
    }

    container.innerHTML = '';
    const renderNode = (name, depth, prefix) => {
      const div = document.createElement('div');
      div.className = 'ev-fib-node';
      div.dataset.prefix = prefix;
      div.style.paddingLeft = (depth * 16) + 'px';

      const route = this.fibRoutes.find(r => r.prefix === prefix);
      let nhHtml = '';
      if (route) {
        nhHtml = route.nexthops.map(nh =>
          `<span class="ev-fib-nexthop">face:${nh.face} cost:${nh.cost}</span>`
        ).join(' ');
      }

      div.innerHTML = `
        <span class="ev-fib-lock" id="ev-fib-lock-${prefix.replace(/\//g, '_')}">&#128274;</span>
        <span>/${name}</span>
        ${nhHtml}
      `;
      container.appendChild(div);
    };

    // Hardcoded trie for display
    renderNode('(root)', 0, '/');
    renderNode('ndn', 1, '/ndn');
    renderNode('edu', 2, '/ndn/edu');
    renderNode('ucla', 3, '/ndn/edu/ucla');
    renderNode('mit', 3, '/ndn/edu/mit');
    renderNode('com', 2, '/ndn/com');
    renderNode('google', 3, '/ndn/com/google');
  }

  _renderCsGrid(container) {
    container.innerHTML = '';
    // Render 8 cells (some empty)
    for (let i = 0; i < 8; i++) {
      const cell = document.createElement('div');
      cell.className = 'ev-cs-cell empty';
      cell.id = `ev-cs-cell-${i}`;
      cell.innerHTML = '<span class="ev-cs-name">—</span><div class="ev-cs-freshness" style="width:0"></div>';
      container.appendChild(cell);
    }
    // Pre-populate some entries
    this._csInsert(0, '/app/video/frame3', 90);
    this._csInsert(1, '/app/data/item7', 60);
  }

  _csInsert(cellIdx, name, freshness) {
    const cell = document.getElementById(`ev-cs-cell-${cellIdx}`);
    if (!cell) return;
    cell.classList.remove('empty');
    cell.classList.add('inserting');
    cell.querySelector('.ev-cs-name').textContent = name.split('/').slice(-2).join('/');
    cell.querySelector('.ev-cs-freshness').style.width = freshness + '%';
    cell.title = `${name}\nFreshness: ${freshness}%\nStored as wire-format Bytes (zero-copy)`;
    setTimeout(() => cell.classList.remove('inserting'), 400);
  }

  // ── Bytes Lifecycle ─────────────────────────────────────────────────────

  _buildBytesLifecycle() {
    const section = document.createElement('div');
    section.className = 'ev-bytes';
    const lifecycle = this.ed?.bytes_lifecycle?.stages || [];

    section.innerHTML = `
      <div class="ev-bytes-title">
        bytes::Bytes Lifecycle
        <span class="ev-rust-badge">zero-copy end-to-end</span>
      </div>
      <div class="ev-bytes-chain" id="ev-bytes-chain">
        ${lifecycle.map((s, i) => `
          <div class="ev-bytes-node" id="ev-bn-${i}" style="border-color:${s.color}">
            <span class="ev-bytes-label">${s.label}</span>
            <span class="ev-bytes-rc" id="ev-brc-${i}">rc=${s.refcount}</span>
            <span class="ev-bytes-op-note" id="ev-bop-${i}"></span>
          </div>
          ${i < lifecycle.length - 1 ? '<div class="ev-bytes-arrow"></div>' : ''}
        `).join('')}
      </div>
    `;
    this.container.appendChild(section);
  }

  // ── Config Panel ────────────────────────────────────────────────────────

  _buildConfigPanel() {
    const panel = document.createElement('div');
    panel.className = 'ev-config-panel';
    panel.id = 'ev-config-panel';
    panel.innerHTML = `
      <div class="ev-config-title">
        Scenario Configuration
        <button class="ev-btn" onclick="document.getElementById('ev-config-panel').classList.remove('open')">Close</button>
      </div>
      <div class="ev-config-section">
        <h4>Packet</h4>
        <div class="ev-config-row">
          <label>Type</label>
          <select id="ev-cfg-type">
            <option value="interest">Interest</option>
            <option value="data">Data</option>
          </select>
        </div>
        <div class="ev-config-row">
          <label>Name</label>
          <input id="ev-cfg-name" value="${this.scenario.name}" placeholder="/ndn/...">
        </div>
      </div>
      <div class="ev-config-section">
        <h4>Initial State</h4>
        <div class="ev-config-row">
          <label>CS has entry</label>
          <select id="ev-cfg-cs"><option value="0">No (miss)</option><option value="1">Yes (hit)</option></select>
        </div>
        <div class="ev-config-row">
          <label>PIT has entry</label>
          <select id="ev-cfg-pit"><option value="0">No (new)</option><option value="1">Yes (aggregate)</option></select>
        </div>
        <div class="ev-config-row">
          <label>Security</label>
          <select id="ev-cfg-sec">
            <option value="disabled">Disabled</option>
            <option value="accept-signed">AcceptSigned</option>
            <option value="default">Default (full chain)</option>
          </select>
        </div>
      </div>
      <button class="ev-btn" id="ev-config-apply" style="width:100%;margin-top:0.5rem;">
        Apply & Close
      </button>
    `;
    document.body.appendChild(panel);

    // Apply button reads inputs and rebuilds scenario
    panel.querySelector('#ev-config-apply').addEventListener('click', () => {
      const type = panel.querySelector('#ev-cfg-type').value;
      const name = panel.querySelector('#ev-cfg-name').value || '/ndn/test';
      const csHit = panel.querySelector('#ev-cfg-cs').value === '1';
      const pitExists = panel.querySelector('#ev-cfg-pit').value === '1';
      const secProfile = panel.querySelector('#ev-cfg-sec').value;

      this.scenario = {
        type,
        name,
        csHit,
        pitExists,
        securityProfile: secProfile,
        fibMatch: '/ndn',
        fibFaceId: 3,
        fibCost: 10,
      };
      this.currentPreset = '(custom)';
      this._loadScenario();
      panel.classList.remove('open');
    });
  }

  _toggleConfig() {
    document.getElementById('ev-config-panel')?.classList.toggle('open');
  }

  // ── Animation Handler ───────────────────────────────────────────────────

  _loadScenario() {
    this._resetVisualization();
    const steps = buildSteps(this.scenario, this.ed || {});
    this.engine.loadScenario(steps);
    document.getElementById('ev-step-info').textContent =
      `${steps.length} steps | ${this.scenario.type} for ${this.scenario.name}`;
  }

  _resetVisualization() {
    // Reset context fields
    this.container.querySelectorAll('.ev-ctx-field').forEach(el => {
      el.classList.remove('set', 'just-set', 'dropped');
      const val = el.querySelector('.ev-ctx-fval');
      if (val) val.textContent = '';
    });
    document.getElementById('ev-ctx-owner').textContent = '—';
    document.getElementById('ev-ctx-note').textContent = '';

    // Reset PIT
    document.getElementById('ev-pit-body').innerHTML = '';
    this.pitEntries = [];

    // Reset packet dots
    for (const dot of this.packetDots) {
      dot.setAttribute('cx', '-20');
      dot.setAttribute('cy', '-20');
      dot.style.display = dot === this.packetDots[0] ? 'block' : 'none';
    }

    // Reset stage highlights
    Object.values(this.stageEls).forEach(g => g.classList.remove('ev-stage-active'));

    // Reset bytes lifecycle
    this.container.querySelectorAll('.ev-bytes-node').forEach(el => el.classList.remove('active'));

    // Reset FIB highlights
    this.container.querySelectorAll('.ev-fib-node').forEach(el => el.classList.remove('matched'));
    this.container.querySelectorAll('.ev-fib-lock').forEach(el => el.classList.remove('visible'));

    // Reset security panel
    this._resetSecurityPanel();
  }

  _onStep(idx, step, direction) {
    if (!step) return;
    if (direction === 'reset') { this._resetVisualization(); return; }

    const info = document.getElementById('ev-step-info');
    if (info) info.textContent = `Step ${idx + 1}/${this.engine.steps.length} | ${step.stage} | ${step.action} | ${formatNs(step.durationNs)}`;

    // ── Move packet dot ──────────────────────────────────────────────
    const path = this.scenario.type === 'nack' ? 'nack'
               : this.scenario.type === 'data' ? 'data' : 'interest';
    const pktIdx = step.packetIndex || 0;
    const dot = this.packetDots[pktIdx] || this.packetDots[0];
    dot.style.display = 'block';

    const posKey = step.stage + '_' + path;
    const pos = this.stagePositions[posKey]
             || this.stagePositions[step.stage + '_interest']
             || this.stagePositions[step.stage + '_data'];
    if (pos) {
      dot.setAttribute('cx', pos.cx);
      dot.setAttribute('cy', pos.cy);
      const fillColor = path === 'nack' ? '#ff7b72' : path === 'data' ? '#3fb950' : '#58a6ff';
      dot.setAttribute('fill', pktIdx > 0 ? ['#58a6ff', '#d2a8ff', '#ffa657'][pktIdx] : fillColor);
    }

    // For concurrent: show additional dots
    if (this.scenario.type === 'concurrent') {
      const totalPkts = this.scenario.packets?.length || 1;
      for (let i = 0; i < totalPkts && i < this.packetDots.length; i++) {
        this.packetDots[i].style.display = 'block';
      }
    }

    // Discovery consumed: flash the discovery diamond
    if (step.stage === 'discovery') {
      const disc = document.getElementById('ev-discovery-hook');
      if (disc) {
        disc.setAttribute('opacity', '1');
        disc.setAttribute('fill', '#ffa657');
        setTimeout(() => { disc.setAttribute('opacity', '0.5'); disc.setAttribute('fill', '#d29922'); }, 800);
      }
    }

    // ── Highlight active stage ───────────────────────────────────────
    Object.values(this.stageEls).forEach(g => g.classList.remove('ev-stage-active'));
    const activeEl = this.stageEls[posKey] || this.stageEls[step.stage + '_interest'];
    if (activeEl) activeEl.classList.add('ev-stage-active');

    // ── Update context fields ────────────────────────────────────────
    for (const field of (step.fieldsSet || [])) {
      const el = document.getElementById(`ev-cf-${field}`);
      if (el) {
        el.classList.add('set', 'just-set');
        setTimeout(() => el.classList.remove('just-set'), 600);
      }
      const valEl = document.getElementById(`ev-cfv-${field}`);
      if (valEl && step.fieldValues?.[field]) {
        valEl.textContent = step.fieldValues[field];
      }
    }

    // Update ownership label
    const ownerEl = document.getElementById('ev-ctx-owner');
    if (ownerEl && step.stage !== 'inbound') ownerEl.textContent = step.stage;

    // Update note
    const noteEl = document.getElementById('ev-ctx-note');
    if (noteEl) noteEl.innerHTML = step.detail +
      (step.rustFeature ? ` <span class="ev-rust-badge">${step.rustFeature}</span>` : '');

    // ── Terminal action: Drop animation ──────────────────────────────
    if (step.terminal && step.action.startsWith('Drop')) {
      this.container.querySelectorAll('.ev-ctx-field.set').forEach(el => {
        el.classList.add('dropped');
      });
    }

    // ── Table operations ─────────────────────────────────────────────
    if (step.tableOp) this._handleTableOp(step.tableOp);

    // ── Bytes lifecycle ──────────────────────────────────────────────
    if (step.bytesOp) this._handleBytesOp(step.bytesOp, idx);

    // ── FIB LPM animation ────────────────────────────────────────────
    if (step.tableOp?.table === 'fib' && step.tableOp.op === 'lpm') {
      this._animateFibLpm(step.tableOp.match);
    }

    // ── Security chain walk ──────────────────────────────────────────
    if (step.securityStep) {
      this._animateSecurityStep(step.securityStep);
    }
  }

  _handleTableOp(op) {
    if (op.table === 'pit') {
      const tbody = document.getElementById('ev-pit-body');
      if (!tbody) return;

      if (op.op === 'insert') {
        const tr = document.createElement('tr');
        tr.className = 'ev-pit-row-enter';
        tr.id = `ev-pit-${op.name.replace(/\//g, '_')}`;
        const nonce = op.nonce || Math.floor(Math.random() * 0xFFFFFFFF);
        tr.innerHTML = `
          <td>${op.name}</td>
          <td>face:${op.face || 1}</td>
          <td>${this._renderSmallVec([nonce], 4)}</td>
          <td>4s</td>
        `;
        tbody.appendChild(tr);
        this.pitEntries.push(op.name);
      } else if (op.op === 'aggregate') {
        const existing = document.getElementById(`ev-pit-${op.name.replace(/\//g, '_')}`);
        if (existing) {
          // Add in-record
          const inCell = existing.cells[1];
          if (inCell) inCell.textContent += `, face:${op.face || 2}`;
        }
      } else if (op.op === 'satisfy') {
        const row = document.getElementById(`ev-pit-${op.name.replace(/\//g, '_')}`);
        if (row) row.classList.add('ev-pit-row-satisfied');
      } else if (op.op === 'loop_detected' || op.op === 'miss') {
        // Drop visual on existing row if any
        const row = document.getElementById(`ev-pit-${op.name.replace(/\//g, '_')}`);
        if (row && op.op !== 'miss') row.classList.add('ev-pit-row-dropped');
      }
    } else if (op.table === 'cs') {
      if (op.op === 'hit') {
        // Flash the matching cell
        const cells = document.querySelectorAll('.ev-cs-cell:not(.empty)');
        cells.forEach(c => {
          if (c.querySelector('.ev-cs-name')?.textContent?.includes(op.name.split('/').pop())) {
            c.classList.add('hit');
            setTimeout(() => c.classList.remove('hit'), 500);
          }
        });
        // Update stats
        this._updateCsStats(1, 0);
      } else if (op.op === 'miss') {
        this._updateCsStats(0, 1);
      } else if (op.op === 'insert') {
        // Find first empty cell
        for (let i = 0; i < 8; i++) {
          const cell = document.getElementById(`ev-cs-cell-${i}`);
          if (cell?.classList.contains('empty')) {
            this._csInsert(i, op.name, 100);
            break;
          }
        }
      }
    }
  }

  _updateCsStats(hits, misses) {
    const el = document.getElementById('ev-cs-stats');
    if (!el) return;
    const cur = el.textContent.match(/hits:\s*(\d+)\s+misses:\s*(\d+)/);
    const h = parseInt(cur?.[1] || 0) + hits;
    const m = parseInt(cur?.[2] || 0) + misses;
    const entries = document.querySelectorAll('.ev-cs-cell:not(.empty)').length;
    el.textContent = `hits: ${h}   misses: ${m}   entries: ${entries}`;
  }

  _handleBytesOp(op, stepIdx) {
    // Light up the corresponding bytes lifecycle node
    const nodeEl = document.getElementById(`ev-bn-${Math.min(stepIdx, 6)}`);
    if (nodeEl) {
      nodeEl.classList.add('active');
      const rcEl = nodeEl.querySelector('.ev-bytes-rc');
      if (rcEl) {
        rcEl.textContent = `rc=${op.rc}`;
        rcEl.classList.add('bumped');
        setTimeout(() => rcEl.classList.remove('bumped'), 400);
      }
      const noteEl = nodeEl.querySelector('.ev-bytes-op-note');
      if (noteEl) noteEl.textContent = op.note || '';
    }
  }

  _animateFibLpm(matchPrefix) {
    // Highlight matching nodes in the FIB trie with hand-over-hand locking
    const parts = matchPrefix.split('/').filter(Boolean);
    let prefix = '';
    let delay = 0;
    for (const part of parts) {
      prefix += '/' + part;
      const nodeEl = this.container.querySelector(`.ev-fib-node[data-prefix="${prefix}"]`);
      if (nodeEl) {
        setTimeout(() => {
          nodeEl.classList.add('matched');
          // Show lock briefly
          const lockEl = nodeEl.querySelector('.ev-fib-lock');
          if (lockEl) {
            lockEl.classList.add('visible');
            // Hand-over-hand: release after 300ms (before next node locks)
            setTimeout(() => lockEl.classList.remove('visible'), 300);
          }
        }, delay);
        delay += 250;
      }
    }
  }

  _renderSmallVec(values, capacity) {
    let html = '<span class="ev-smallvec">';
    for (let i = 0; i < capacity; i++) {
      html += `<span class="ev-sv-slot ${i < values.length ? 'filled' : 'empty'}"></span>`;
    }
    html += `<span class="ev-sv-label">stack[${capacity}]</span>`;
    if (values.length > capacity) {
      html += `<span class="ev-sv-spill">+${values.length - capacity} heap</span>`;
    }
    html += '</span>';
    return html;
  }

  // ── SVG Helpers ─────────────────────────────────────────────────────────

  _svgText(parent, x, y, text, size, fill, weight) {
    const el = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    el.setAttribute('x', x); el.setAttribute('y', y);
    el.setAttribute('font-size', size); el.setAttribute('fill', fill);
    el.setAttribute('text-anchor', 'middle'); el.setAttribute('dominant-baseline', 'central');
    if (weight) el.setAttribute('font-weight', weight);
    el.setAttribute('font-family', '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif');
    el.textContent = text;
    parent.appendChild(el);
    return el;
  }

  _svgRect(parent, x, y, w, h, r, fill, stroke) {
    const el = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    el.setAttribute('x', x); el.setAttribute('y', y);
    el.setAttribute('width', w); el.setAttribute('height', h);
    el.setAttribute('rx', r || 0);
    el.setAttribute('fill', fill); el.setAttribute('stroke', stroke || 'none');
    el.setAttribute('stroke-width', '1');
    parent.appendChild(el);
    return el;
  }

  _svgArrow(parent, x1, y1, x2, y2, color) {
    const el = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    el.setAttribute('x1', x1); el.setAttribute('y1', y1);
    el.setAttribute('x2', x2); el.setAttribute('y2', y2);
    el.setAttribute('stroke', color); el.setAttribute('stroke-width', '1.5');
    el.setAttribute('marker-end', `url(#ev-arrow)`);
    el.classList.add('ev-trace');
    parent.appendChild(el);
    return el;
  }

  _svgPath(parent, d, color, dashed, label) {
    const el = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    el.setAttribute('d', d);
    el.setAttribute('stroke', color); el.setAttribute('stroke-width', '1.5');
    el.setAttribute('fill', 'none');
    if (dashed) el.setAttribute('stroke-dasharray', '5,3');
    el.classList.add('ev-trace');
    parent.appendChild(el);

    if (label) {
      // Parse midpoint from path
      const pts = d.match(/([\d.]+)/g);
      if (pts && pts.length >= 4) {
        const mx = (parseFloat(pts[0]) + parseFloat(pts[pts.length - 2])) / 2;
        const my = (parseFloat(pts[1]) + parseFloat(pts[pts.length - 1])) / 2;
        this._svgText(parent, mx + 30, my, label, 9, color);
      }
    }
    return el;
  }

  // ── Tooltip ─────────────────────────────────────────────────────────────

  _showTooltip(e) {
    this.tooltipEl.style.display = 'block';
    this._moveTooltip(e);
  }
  _moveTooltip(e) {
    this.tooltipEl.style.left = (e.clientX + 15) + 'px';
    this.tooltipEl.style.top = (e.clientY - 10) + 'px';
  }
  _hideTooltip() {
    this.tooltipEl.style.display = 'none';
  }
}
