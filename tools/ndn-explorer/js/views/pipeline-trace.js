// @ts-check
/**
 * Pipeline Trace view — animated interactive NDN forwarding pipeline.
 *
 * Compose a packet, configure a scenario with knobs, then run it through
 * the Interest or Data forwarding pipeline stage-by-stage.  A JS-based
 * simulation drives the animation; real WASM processing can be substituted
 * when ndn-wasm is available via wasm-types.js.
 */

// ── Type definitions ──────────────────────────────────────────────────────────

/**
 * @typedef {'Continue'|'Satisfy'|'Drop'|'Send'|'Nack'|'Aggregated'} PipelineAction
 * @typedef {'interest'|'data'} PacketType
 * @typedef {'BestRoute'|'Multicast'|'Suppress'} StrategyName
 */

/**
 * @typedef {Object} StageEvent
 * @property {number} index - stage index (0-based)
 * @property {string} name  - stage name
 * @property {PipelineAction} action
 * @property {string} detail - human-readable explanation
 * @property {Record<string, string>} state - key/value pairs for the state panel
 * @property {boolean} [terminal] - true when the pipeline stops at this stage
 */

/**
 * @typedef {Object} SimSettings
 * @property {boolean} csHit           - CS already contains this name
 * @property {number}  csSize          - CS capacity in entries
 * @property {boolean} pitPending      - PIT has a pending entry for this name
 * @property {boolean} pitNonceCollide - nonce already seen → loop detection
 * @property {StrategyName} strategy
 * @property {number}  faceCount       - number of outgoing faces (0 = no route)
 * @property {boolean} sigValid        - signature passes validation
 * @property {number}  rttMs           - simulated measured RTT in ms
 */

/**
 * @typedef {Object} PacketSpec
 * @property {PacketType} type
 * @property {string}  name
 * @property {boolean} [canBePrefix]
 * @property {boolean} [mustBeFresh]
 * @property {number}  [lifetimeMs]
 * @property {string}  [content]
 * @property {number}  [freshnessMs]
 */

/**
 * @typedef {Object} Scenario
 * @property {string} label
 * @property {PacketSpec} packet
 * @property {Partial<SimSettings>} settings
 */

// ── Stage definitions ─────────────────────────────────────────────────────────

/** @type {Record<PacketType, Array<{name:string, crate:string, desc:string, actions:PipelineAction[]}>>} */
const STAGE_DEFS = {
  interest: [
    {
      name: 'TlvDecode',
      crate: 'ndn-engine',
      desc: 'Decode raw bytes into an Interest packet. Unwrap NDNLPv2 link-protocol headers (fragmentation reassembly, Nack detection). Enforce /localhost scope — drop if the Interest arrived on a non-local face but targets a local prefix.',
      actions: ['Continue', 'Drop'],
    },
    {
      name: 'CsLookup',
      crate: 'ndn-engine',
      desc: 'Search the Content Store for cached Data matching this Interest (name + CanBePrefix + MustBeFresh). On a cache hit, short-circuit: return the cached Data immediately to the downstream face without touching PIT or FIB.',
      actions: ['Satisfy', 'Continue'],
    },
    {
      name: 'PitCheck',
      crate: 'ndn-engine',
      desc: 'Check the Pending Interest Table. If an existing PIT entry matches and the nonce was seen before, drop (loop). If nonce differs, aggregate by adding the incoming face to the in-record list. If no match, create a new PIT entry.',
      actions: ['Continue', 'Drop', 'Aggregated'],
    },
    {
      name: 'Strategy',
      crate: 'ndn-engine',
      desc: 'Consult the forwarding strategy assigned to this name prefix. The strategy performs FIB longest-prefix-match, selects outgoing face(s) based on EWMA RTT measurements, and returns a forwarding decision.',
      actions: ['Send', 'Nack'],
    },
  ],
  data: [
    {
      name: 'TlvDecode',
      crate: 'ndn-engine',
      desc: 'Decode raw bytes into a Data packet. Unwrap NDNLPv2 link-protocol headers. Enforce /localhost scope — drop if the Data targets a local prefix but arrived from a non-local face.',
      actions: ['Continue', 'Drop'],
    },
    {
      name: 'PitMatch',
      crate: 'ndn-engine',
      desc: 'Match this Data against PIT entries by name (and selectors). Collect all downstream faces from matching in-records — these are the consumers waiting for this Data. If no PIT entry matches, this is unsolicited Data and gets dropped.',
      actions: ['Continue', 'Drop'],
    },
    {
      name: 'Validation',
      crate: 'ndn-engine',
      desc: 'Verify the Data packet\'s cryptographic signature. Walk the certificate chain if needed, fetching missing certificates via the CertFetcher. Packets awaiting certificates are queued. If validation fails, the Data is dropped.',
      actions: ['Continue', 'Drop'],
    },
    {
      name: 'CsInsert',
      crate: 'ndn-engine',
      desc: 'Insert the validated Data into the Content Store. The admission policy decides whether to cache (e.g., skip if CachePolicyType::NoCache is set). Then dispatch: send the Data to all downstream faces collected from PIT in-records.',
      actions: ['Send'],
    },
  ],
};

// ── Scenarios ─────────────────────────────────────────────────────────────────

/** @type {Record<string, Scenario>} */
const SCENARIOS = {
  simple: {
    label: 'Simple Interest → Data',
    packet: { type: 'interest', name: '/ndn/edu/demo/video', lifetimeMs: 4000, canBePrefix: false, mustBeFresh: false },
    settings: { csHit: false, csSize: 250, pitPending: false, pitNonceCollide: false, strategy: 'BestRoute', faceCount: 2, sigValid: true, rttMs: 50 },
  },
  'cache-hit': {
    label: 'Interest → Cache Hit',
    packet: { type: 'interest', name: '/ndn/edu/demo/cached', lifetimeMs: 4000, mustBeFresh: false },
    settings: { csHit: true, csSize: 500, pitPending: false, pitNonceCollide: false, strategy: 'BestRoute', faceCount: 2 },
  },
  'nack-noroute': {
    label: 'Interest → Nack (NoRoute)',
    packet: { type: 'interest', name: '/ndn/unknown/resource', lifetimeMs: 4000 },
    settings: { csHit: false, csSize: 0, pitPending: false, pitNonceCollide: false, strategy: 'BestRoute', faceCount: 0 },
  },
  'loop-detect': {
    label: 'Interest Loop Detection',
    packet: { type: 'interest', name: '/ndn/edu/demo/video', lifetimeMs: 4000 },
    settings: { csHit: false, csSize: 250, pitPending: true, pitNonceCollide: true, strategy: 'BestRoute', faceCount: 2 },
  },
  aggregation: {
    label: 'Interest Aggregation (3 consumers)',
    packet: { type: 'interest', name: '/ndn/edu/demo/video', lifetimeMs: 4000 },
    settings: { csHit: false, csSize: 250, pitPending: true, pitNonceCollide: false, strategy: 'BestRoute', faceCount: 2 },
  },
  'invalid-sig': {
    label: 'Data: Invalid Signature',
    packet: { type: 'data', name: '/ndn/edu/demo/video', content: 'Hello NDN!', freshnessMs: 10000 },
    settings: { csHit: false, csSize: 250, pitPending: true, pitNonceCollide: false, strategy: 'BestRoute', faceCount: 2, sigValid: false, rttMs: 50 },
  },
  multipath: {
    label: 'Multipath Forwarding',
    packet: { type: 'interest', name: '/ndn/edu/video/stream', lifetimeMs: 4000 },
    settings: { csHit: false, csSize: 250, pitPending: false, pitNonceCollide: false, strategy: 'Multicast', faceCount: 3, sigValid: true, rttMs: 15 },
  },
};

// ── Swimlane colors (up to 5 rows) ───────────────────────────────────────────

const SWIM_COLORS = ['#58a6ff', '#3fb950', '#d2a8ff', '#f0883e', '#ff7b72'];

// ── Multi-packet timeline scenarios ──────────────────────────────────────────

/**
 * @typedef {Object} SwimPacket
 * @property {PacketSpec} packet
 * @property {Partial<SimSettings>} settings
 */
/**
 * @typedef {Object} SwimlaneScenario
 * @property {string} label
 * @property {SwimPacket[]} packets
 */

/** @type {Record<string, SwimlaneScenario>} */
const SWIMLANE_SCENARIOS = {
  aggregation: {
    label: 'Interest Aggregation (3 consumers)',
    packets: [
      {
        packet: { type: 'interest', name: '/ndn/edu/demo/video', lifetimeMs: 4000, canBePrefix: false, mustBeFresh: false },
        settings: { csHit: false, csSize: 250, pitPending: false, pitNonceCollide: false, strategy: 'BestRoute', faceCount: 2, sigValid: true, rttMs: 50 },
      },
      {
        packet: { type: 'interest', name: '/ndn/edu/demo/video', lifetimeMs: 4000, canBePrefix: false, mustBeFresh: false },
        settings: { csHit: false, csSize: 250, pitPending: true, pitNonceCollide: false, strategy: 'BestRoute', faceCount: 2, sigValid: true, rttMs: 50 },
      },
      {
        packet: { type: 'interest', name: '/ndn/edu/demo/video', lifetimeMs: 4000, canBePrefix: false, mustBeFresh: false },
        settings: { csHit: false, csSize: 250, pitPending: true, pitNonceCollide: false, strategy: 'BestRoute', faceCount: 2, sigValid: true, rttMs: 50 },
      },
    ],
  },
  pipelining: {
    label: 'Pipelining: Interest then Data',
    packets: [
      {
        packet: { type: 'interest', name: '/ndn/edu/demo/file', lifetimeMs: 4000, canBePrefix: false, mustBeFresh: false },
        settings: { csHit: false, csSize: 250, pitPending: false, pitNonceCollide: false, strategy: 'BestRoute', faceCount: 1, sigValid: true, rttMs: 30 },
      },
      {
        packet: { type: 'data', name: '/ndn/edu/demo/file', content: 'Hello NDN!', freshnessMs: 10000 },
        settings: { csHit: false, csSize: 250, pitPending: true, pitNonceCollide: false, strategy: 'BestRoute', faceCount: 1, sigValid: true, rttMs: 30 },
      },
    ],
  },
  'cache-compare': {
    label: 'Cache Miss then Cache Hit',
    packets: [
      {
        packet: { type: 'interest', name: '/ndn/edu/cached/video', lifetimeMs: 4000 },
        settings: { csHit: false, csSize: 0, pitPending: false, pitNonceCollide: false, strategy: 'BestRoute', faceCount: 2, sigValid: true, rttMs: 40 },
      },
      {
        packet: { type: 'interest', name: '/ndn/edu/cached/video', lifetimeMs: 4000 },
        settings: { csHit: true, csSize: 1, pitPending: false, pitNonceCollide: false, strategy: 'BestRoute', faceCount: 2, sigValid: true, rttMs: 40 },
      },
    ],
  },
  multipath: {
    label: 'Multipath: BestRoute vs Multicast',
    packets: [
      {
        packet: { type: 'interest', name: '/ndn/stream/v1', lifetimeMs: 4000 },
        settings: { csHit: false, csSize: 250, pitPending: false, pitNonceCollide: false, strategy: 'BestRoute', faceCount: 3, sigValid: true, rttMs: 20 },
      },
      {
        packet: { type: 'interest', name: '/ndn/stream/v1', lifetimeMs: 4000 },
        settings: { csHit: false, csSize: 250, pitPending: false, pitNonceCollide: false, strategy: 'Multicast', faceCount: 3, sigValid: true, rttMs: 20 },
      },
    ],
  },
  'drop-vs-forward': {
    label: 'Invalid Sig Drop vs Valid Forward',
    packets: [
      {
        packet: { type: 'data', name: '/ndn/edu/demo/doc', content: 'Legit data', freshnessMs: 5000 },
        settings: { csHit: false, csSize: 250, pitPending: true, pitNonceCollide: false, strategy: 'BestRoute', faceCount: 1, sigValid: true, rttMs: 50 },
      },
      {
        packet: { type: 'data', name: '/ndn/edu/demo/doc', content: 'Tampered data', freshnessMs: 5000 },
        settings: { csHit: false, csSize: 250, pitPending: true, pitNonceCollide: false, strategy: 'BestRoute', faceCount: 1, sigValid: false, rttMs: 50 },
      },
    ],
  },
};

// ── Action CSS classes ────────────────────────────────────────────────────────

/** @type {Record<string, string>} */
const ACTION_CLASSES = {
  Continue:   'action-continue',
  Send:       'action-send',
  Satisfy:    'action-satisfy',
  Drop:       'action-drop',
  Nack:       'action-nack',
  Aggregated: 'action-aggregated',
};

// ── JS simulation engine ──────────────────────────────────────────────────────

/**
 * Simulate the NDN forwarding pipeline in pure JS.
 * @param {PacketSpec} packet
 * @param {SimSettings} settings
 * @returns {StageEvent[]}
 */
function simulate(packet, settings) {
  /** @type {StageEvent[]} */
  const events = [];
  const name = packet.name || '/';
  const comps = name.split('/').filter(Boolean).length;

  if (packet.type === 'interest') {
    // ── Stage 0: TlvDecode ───────────────────────────────────────────────────
    if (comps === 0) {
      events.push({ index: 0, name: 'TlvDecode', action: 'Drop',
        detail: 'Name is empty — packet dropped at TlvDecode.',
        state: { Error: 'Empty name' }, terminal: true });
      return events;
    }
    events.push({ index: 0, name: 'TlvDecode', action: 'Continue',
      detail: `Decoded Interest with ${comps} name component${comps !== 1 ? 's' : ''}.`,
      state: {
        Name: name,
        Components: String(comps),
        CanBePrefix: packet.canBePrefix ? 'Yes' : 'No',
        MustBeFresh: packet.mustBeFresh ? 'Yes' : 'No',
        Lifetime: `${packet.lifetimeMs ?? 4000} ms`,
      },
    });

    // ── Stage 1: CsLookup ────────────────────────────────────────────────────
    if (settings.csHit) {
      events.push({ index: 1, name: 'CsLookup', action: 'Satisfy',
        detail: `Cache hit — found matching Data for ${name}. Returning cached copy to downstream face; PIT and Strategy are bypassed.`,
        state: { Result: 'HIT', 'CS Entries': String(settings.csSize), Freshness: 'Valid' },
        terminal: true });
      return events;
    }
    events.push({ index: 1, name: 'CsLookup', action: 'Continue',
      detail: `Cache miss for ${name}. Forwarding to PIT check.`,
      state: { Result: 'MISS', 'CS Entries': String(settings.csSize) },
    });

    // ── Stage 2: PitCheck ────────────────────────────────────────────────────
    if (settings.pitPending) {
      if (settings.pitNonceCollide) {
        events.push({ index: 2, name: 'PitCheck', action: 'Drop',
          detail: `Nonce already present in PIT entry for ${name} — forwarding loop detected. Interest dropped.`,
          state: { Entry: 'Existing', Nonce: 'Duplicate (loop)', Result: 'Drop' },
          terminal: true });
        return events;
      }
      events.push({ index: 2, name: 'PitCheck', action: 'Aggregated',
        detail: `Existing PIT entry for ${name}. New nonce, same name — Interest aggregated. Incoming face added to in-records; Interest is not forwarded again.`,
        state: { Entry: 'Existing', Nonce: 'New (aggregated)', 'In-Records': '2 faces' },
        terminal: true });
      return events;
    }
    events.push({ index: 2, name: 'PitCheck', action: 'Continue',
      detail: `No matching PIT entry. New entry created for ${name}.`,
      state: { Entry: 'New', 'In-Records': '1 face', Lifetime: `${packet.lifetimeMs ?? 4000} ms` },
    });

    // ── Stage 3: Strategy ────────────────────────────────────────────────────
    if (settings.strategy === 'Suppress') {
      events.push({ index: 3, name: 'Strategy', action: 'Nack',
        detail: 'Suppress strategy — Interest suppressed. Sending Nack(NoRoute) downstream.',
        state: { Strategy: 'Suppress', 'FIB Match': 'N/A', Outcome: 'Nack(NoRoute)' },
        terminal: true });
      return events;
    }
    if (settings.faceCount === 0) {
      events.push({ index: 3, name: 'Strategy', action: 'Nack',
        detail: `No FIB entry matches ${name}. Sending Nack(NoRoute) downstream.`,
        state: { Strategy: settings.strategy, 'FIB Match': 'None', Outcome: 'Nack(NoRoute)' },
        terminal: true });
      return events;
    }
    const faceList = Array.from({ length: settings.faceCount }, (_, i) => `face${i + 1}`).join(', ');
    const fibPrefix = '/' + name.split('/').filter(Boolean).slice(0, 2).join('/');
    events.push({ index: 3, name: 'Strategy', action: 'Send',
      detail: `${settings.strategy} strategy — forwarding to ${settings.faceCount} face${settings.faceCount !== 1 ? 's' : ''}. Measured RTT: ${settings.rttMs} ms.`,
      state: {
        Strategy: settings.strategy,
        'FIB Prefix': fibPrefix,
        'Outgoing Faces': faceList,
        'Measured RTT': `${settings.rttMs} ms`,
      },
      terminal: true });
    return events;
  }

  // ── Data pipeline ─────────────────────────────────────────────────────────

  // Stage 0: TlvDecode
  const preview = packet.content
    ? `"${packet.content.slice(0, 32)}${packet.content.length > 32 ? '…' : ''}"`
    : '(empty)';
  events.push({ index: 0, name: 'TlvDecode', action: 'Continue',
    detail: `Decoded Data packet for ${name}.`,
    state: {
      Name: name,
      'Content-Type': 'Blob',
      Content: preview,
      Freshness: `${packet.freshnessMs ?? 0} ms`,
    },
  });

  // Stage 1: PitMatch
  if (!settings.pitPending) {
    events.push({ index: 1, name: 'PitMatch', action: 'Drop',
      detail: `No PIT entry for ${name} — unsolicited Data. Dropped.`,
      state: { 'PIT Match': 'None', Result: 'Drop (unsolicited)' },
      terminal: true });
    return events;
  }
  events.push({ index: 1, name: 'PitMatch', action: 'Continue',
    detail: `Matched PIT entry for ${name}. Collected downstream faces.`,
    state: { 'PIT Match': 'Yes', 'Downstream Faces': '1' },
  });

  // Stage 2: Validation
  if (!settings.sigValid) {
    events.push({ index: 2, name: 'Validation', action: 'Drop',
      detail: 'Cryptographic signature verification failed — Data dropped.',
      state: { Algorithm: 'DigestSha256', Result: 'INVALID', Action: 'Drop' },
      terminal: true });
    return events;
  }
  events.push({ index: 2, name: 'Validation', action: 'Continue',
    detail: 'DigestSha256 signature verified successfully.',
    state: { Algorithm: 'DigestSha256', Result: 'VALID' },
  });

  // Stage 3: CsInsert
  events.push({ index: 3, name: 'CsInsert', action: 'Send',
    detail: `Data cached${packet.freshnessMs ? ` (freshness ${packet.freshnessMs} ms)` : ''} and dispatched to downstream face.`,
    state: {
      Cached: 'Yes',
      Freshness: `${packet.freshnessMs ?? 0} ms`,
      'Sent To': '1 downstream face',
      'CS Entries': String(settings.csSize + 1),
    },
    terminal: true });
  return events;
}

// ── PipelineTrace view ────────────────────────────────────────────────────────

export class PipelineTrace {
  /**
   * @param {HTMLElement} container
   * @param {object} app
   */
  constructor(container, app) {
    this.container = container;
    this.app = app;

    /** @type {SimSettings} */
    this.settings = {
      csHit: false, csSize: 250, pitPending: false, pitNonceCollide: false,
      strategy: 'BestRoute', faceCount: 2, sigValid: true, rttMs: 50,
    };

    /** @type {PacketSpec} */
    this.packet = {
      type: 'interest', name: '/ndn/edu/demo/video',
      lifetimeMs: 4000, canBePrefix: false, mustBeFresh: false,
    };

    /** @type {number} ms per pipeline step (0 = instant) */
    this.stepDelay = 800;

    /** @type {StageEvent[]} */
    this.simEvents = [];

    /** @type {ReturnType<typeof setTimeout>|null} */
    this.simTimer = null;

    /**
     * Multi-packet swimlane rows.
     * @type {Array<{id: number, label: string, color: string, packet: PacketSpec, events: StageEvent[]}>}
     */
    this.swimRows = [];
    /** @type {number} */
    this._nextSwimId = 0;
  }

  /**
   * Called by the app router when navigating to this view.
   * Accepts an optional `packet` param from the Packet Explorer's
   * "Run in Pipeline" button.
   * @param {{ packet?: PacketSpec, scenario?: string } | undefined} params
   */
  onShow(params) {
    if (params?.packet) {
      this.packet = { ...this.packet, ...params.packet };
      this.render();
      setTimeout(() => this._runSimulation(), 80);
    } else if (params?.scenario) {
      this._loadScenario(params.scenario);
    }
    // If no params just show whatever is already rendered.
  }

  render() {
    this._stopTimer();
    this.simEvents = [];

    this.container.innerHTML = `
      <h1 style="margin-bottom:0.4rem">Pipeline Trace</h1>
      <p style="color:var(--text2);font-size:0.85rem;margin-bottom:1.25rem">
        Compose a packet, adjust the scenario knobs, then click <strong>Run</strong> to
        trace it through the NDN forwarding pipeline stage-by-stage.
        Each stage receives a <code>PacketContext</code> by value and returns an <code>Action</code>.
      </p>
      ${this._renderToolbar()}
      <div class="pipeline-panels">
        ${this._renderComposer()}
        ${this._renderKnobs()}
      </div>
      ${this._renderPipelineTrack()}
      <div id="pipe-detail" class="stage-detail">
        <h3>Ready</h3>
        <p>Select a scenario above or configure the packet manually, then click <strong>▶ Run</strong>.</p>
      </div>
      ${this._renderSwimlane()}`;

    this._wireEvents();
  }

  // ── Rendering helpers ─────────────────────────────────────────────────────

  _renderToolbar() {
    return `
      <div class="pipeline-toolbar">
        <label class="toolbar-label" for="scenario-select">Scenario</label>
        <select id="scenario-select" class="pipe-select">
          <option value="">— custom —</option>
          ${Object.entries(SCENARIOS).map(([k, s]) =>
            `<option value="${k}">${s.label}</option>`).join('')}
        </select>
        <button id="run-btn" class="pipe-run-btn">&#9654; Run</button>
        <button id="reset-btn" class="pipe-ctrl-btn">&#8635; Reset</button>
        <button id="swim-add-btn" class="pipe-ctrl-btn pipe-swim-btn" title="Run and add this packet as a new row in the Multi-Packet Timeline below">&#8853; Add to Timeline</button>
        <div class="pipe-speed-group">
          <span class="toolbar-label">Speed</span>
          <select id="speed-select" class="pipe-select pipe-select-sm">
            <option value="1600">0.5×</option>
            <option value="800" selected>1×</option>
            <option value="400">2×</option>
            <option value="0">Instant</option>
          </select>
        </div>
      </div>`;
  }

  _renderComposer() {
    const p = this.packet;
    const isInt = p.type === 'interest';
    return `
      <div class="pipeline-panel" id="composer-panel">
        <div class="panel-title">Packet Composer</div>
        <div class="composer-type-row">
          <label class="radio-label">
            <input type="radio" name="pkt-type" value="interest" ${isInt ? 'checked' : ''}> Interest
          </label>
          <label class="radio-label">
            <input type="radio" name="pkt-type" value="data" ${!isInt ? 'checked' : ''}> Data
          </label>
        </div>
        <div class="composer-field">
          <label class="field-label" for="pkt-name">Name</label>
          <input type="text" id="pkt-name" class="pipe-input" value="${this._esc(p.name)}" placeholder="/ndn/...">
        </div>
        ${isInt ? `
          <div class="composer-field">
            <label class="field-label">Lifetime</label>
            <div class="slider-row">
              <input type="range" id="pkt-lifetime" min="100" max="60000" step="100" value="${p.lifetimeMs ?? 4000}">
              <span class="slider-val" id="pkt-lifetime-val">${p.lifetimeMs ?? 4000} ms</span>
            </div>
          </div>
          <div class="composer-check-row">
            <label class="check-label">
              <input type="checkbox" id="pkt-cbp" ${p.canBePrefix ? 'checked' : ''}> CanBePrefix
            </label>
            <label class="check-label">
              <input type="checkbox" id="pkt-mbf" ${p.mustBeFresh ? 'checked' : ''}> MustBeFresh
            </label>
          </div>
          <div class="composer-field composer-nonce-row">
            <label class="field-label">Nonce</label>
            <span class="nonce-display" id="pkt-nonce">${this._randomNonce()}</span>
            <button class="nonce-regen" id="nonce-regen" title="New nonce">&#8635;</button>
          </div>
        ` : `
          <div class="composer-field">
            <label class="field-label" for="pkt-content">Content</label>
            <textarea id="pkt-content" class="pipe-textarea" rows="2"
              placeholder="packet payload…">${this._esc(p.content ?? '')}</textarea>
          </div>
          <div class="composer-field">
            <label class="field-label">Freshness Period</label>
            <div class="slider-row">
              <input type="range" id="pkt-freshness" min="0" max="86400000" step="1000"
                value="${p.freshnessMs ?? 0}">
              <span class="slider-val" id="pkt-freshness-val">${this._fmtMs(p.freshnessMs ?? 0)}</span>
            </div>
          </div>
        `}
      </div>`;
  }

  _renderKnobs() {
    const s = this.settings;
    /** @param {boolean} v @param {string} knob */
    const tog = (v, knob) =>
      `<button class="toggle-btn ${v ? 'on' : 'off'}" data-knob="${knob}">${v ? 'On' : 'Off'}</button>`;

    return `
      <div class="pipeline-panel" id="knobs-panel">
        <div class="panel-title">Simulation Settings</div>
        <div class="knob-row">
          <span class="knob-label">CS contains this name</span>
          ${tog(s.csHit, 'csHit')}
        </div>
        <div class="knob-row">
          <span class="knob-label">CS size (entries)</span>
          <div class="slider-row">
            <input type="range" id="cs-size" min="0" max="1000" step="50" value="${s.csSize}">
            <span class="slider-val" id="cs-size-val">${s.csSize}</span>
          </div>
        </div>
        <div class="knob-row">
          <span class="knob-label">PIT has pending entry</span>
          ${tog(s.pitPending, 'pitPending')}
        </div>
        <div class="knob-row">
          <span class="knob-label">Nonce loop collision</span>
          ${tog(s.pitNonceCollide, 'pitNonceCollide')}
        </div>
        <div class="knob-row">
          <span class="knob-label">Strategy</span>
          <select class="pipe-select pipe-select-sm" id="strategy-select">
            ${['BestRoute', 'Multicast', 'Suppress'].map(n =>
              `<option value="${n}" ${n === s.strategy ? 'selected' : ''}>${n}</option>`).join('')}
          </select>
        </div>
        <div class="knob-row">
          <span class="knob-label">Face count</span>
          <div class="slider-row">
            <input type="range" id="face-count" min="0" max="4" step="1" value="${s.faceCount}">
            <span class="slider-val" id="face-count-val">${s.faceCount}</span>
          </div>
        </div>
        <div class="knob-row">
          <span class="knob-label">Signature valid</span>
          ${tog(s.sigValid, 'sigValid')}
        </div>
        <div class="knob-row">
          <span class="knob-label">Simulated RTT</span>
          <div class="slider-row">
            <input type="range" id="rtt-slider" min="0" max="2000" step="10" value="${s.rttMs}">
            <span class="slider-val" id="rtt-val">${s.rttMs} ms</span>
          </div>
        </div>
      </div>`;
  }

  _renderPipelineTrack() {
    const type = this.packet.type;
    const stages = STAGE_DEFS[type];
    const pktCls = type === 'interest' ? 'pkt-interest' : 'pkt-data';
    const label  = type === 'interest' ? 'Interest' : 'Data';
    return `
      <div class="pipeline-section" id="pipeline-track-section">
        <div class="pipeline-heading">
          <span class="pkt-badge ${pktCls}">${label}</span>
          Pipeline
        </div>
        <div class="stage-flow" id="stage-flow">
          ${stages.map((s, i) => `
            <div class="stage-box" id="stage-box-${i}" data-idx="${i}">
              <div class="stage-num">Stage ${i + 1}</div>
              <h4>${s.name}</h4>
              <div class="stage-crate">${s.crate}</div>
            </div>
            ${i < stages.length - 1 ? '<div class="stage-arrow">&rarr;</div>' : ''}
          `).join('')}
        </div>
      </div>`;
  }

  _renderSwimlane() {
    return `
      <div class="swimlane-section" id="swimlane-section">
        <div class="swimlane-heading">
          <span class="swimlane-title">Multi-Packet Timeline</span>
          <div class="swimlane-toolbar">
            <label class="toolbar-label" for="swim-scenario-select">Load scenario</label>
            <select id="swim-scenario-select" class="pipe-select pipe-select-sm">
              <option value="">— pick —</option>
              ${Object.entries(SWIMLANE_SCENARIOS).map(([k, s]) =>
                `<option value="${k}">${s.label}</option>`).join('')}
            </select>
            <button id="swim-clear-btn" class="pipe-ctrl-btn">&#10005; Clear</button>
          </div>
        </div>
        <div class="swimlane-hint">
          Click <strong>&#8853; Add to Timeline</strong> above to record packets as rows, or load a pre-built multi-packet scenario.
          Up to 5 rows. Click any cell to see stage details.
        </div>
        <div id="swimlane-grid">
          ${this._renderSwimlaneGrid()}
        </div>
      </div>`;
  }

  _renderSwimlaneGrid() {
    if (this.swimRows.length === 0) {
      return `<div class="swimlane-empty">No packets recorded yet.</div>`;
    }

    // Collect all stage names used across all rows (up to 4 stages per pipeline).
    // Interest: TlvDecode, CsLookup, PitCheck, Strategy
    // Data:     TlvDecode, PitMatch, Validation, CsInsert
    // We display 4 columns always; each row labels its own stages.
    const maxStages = 4;

    const headerCells = Array.from({ length: maxStages }, (_, i) =>
      `<div class="swim-header-cell">Stage ${i + 1}</div>`).join('');

    const rows = this.swimRows.map(row => {
      const stages = STAGE_DEFS[row.packet.type];
      const cells = Array.from({ length: maxStages }, (_, si) => {
        const ev = row.events.find(e => e.index === si);
        const stageName = stages[si]?.name ?? '';
        if (!ev) {
          // Stage not reached
          return `<div class="swim-stage-cell swim-skipped">
            <span class="swim-stage-name">${stageName}</span>
            <span class="swim-skipped-dash">—</span>
          </div>`;
        }
        const actCls = ACTION_CLASSES[ev.action] ?? '';
        const isTerm = ev.terminal ? ' swim-terminal' : '';
        return `<div class="swim-stage-cell${isTerm}" data-swim-id="${row.id}" data-stage-idx="${si}"
          title="${this._esc(ev.detail)}">
          <span class="swim-stage-name">${stageName}</span>
          <span class="action-tag ${actCls}">${ev.action}</span>
        </div>`;
      }).join('');

      const typeCls  = row.packet.type === 'interest' ? 'pkt-interest' : 'pkt-data';
      const typeChar = row.packet.type === 'interest' ? 'I' : 'D';
      const shortName = row.packet.name.length > 22
        ? row.packet.name.slice(0, 20) + '…'
        : row.packet.name;

      return `<div class="swim-row" style="--swim-color:${row.color}">
        <div class="swim-label-cell">
          <span class="swim-color-dot" style="background:${row.color}"></span>
          <span class="swim-pkt-badge ${typeCls}">${typeChar}</span>
          <span class="swim-pkt-name" title="${this._esc(row.packet.name)}">${this._esc(shortName)}</span>
          <span class="swim-row-num">#${row.id}</span>
        </div>
        ${cells}
      </div>`;
    }).join('');

    return `
      <div class="swimlane-grid-inner">
        <div class="swim-row swim-header-row">
          <div class="swim-label-cell swim-header-cell">Packet</div>
          ${headerCells}
        </div>
        ${rows}
      </div>`;
  }

  // ── Event wiring ──────────────────────────────────────────────────────────

  _wireEvents() {
    const q = (/** @type {string} */ sel) => this.container.querySelector(sel);
    const qa = (/** @type {string} */ sel) => this.container.querySelectorAll(sel);

    // Scenario loader
    /** @type {HTMLSelectElement|null} */ (q('#scenario-select'))
      ?.addEventListener('change', e => {
        const key = /** @type {HTMLSelectElement} */ (e.target).value;
        if (key) this._loadScenario(key);
      });

    // Speed selector
    /** @type {HTMLSelectElement|null} */ (q('#speed-select'))
      ?.addEventListener('change', e => {
        this.stepDelay = parseInt(/** @type {HTMLSelectElement} */ (e.target).value);
      });

    // Run / Reset
    q('#run-btn')?.addEventListener('click', () => this._runSimulation());
    q('#reset-btn')?.addEventListener('click', () => this._resetSimulation());

    // Packet type toggle
    qa('input[name="pkt-type"]').forEach(r => {
      r.addEventListener('change', () => {
        const radio = /** @type {HTMLInputElement} */ (r);
        if (radio.checked) {
          this.packet = { ...this.packet, type: /** @type {PacketType} */ (radio.value) };
          this.render();
        }
      });
    });

    // Name
    q('#pkt-name')?.addEventListener('input', e => {
      this.packet = { ...this.packet, name: /** @type {HTMLInputElement} */ (e.target).value };
    });

    // Lifetime
    this._wireSlider('pkt-lifetime', 'pkt-lifetime-val',
      v => { this.packet = { ...this.packet, lifetimeMs: v }; },
      v => `${v} ms`);

    // CanBePrefix / MustBeFresh
    q('#pkt-cbp')?.addEventListener('change', e => {
      this.packet = { ...this.packet, canBePrefix: /** @type {HTMLInputElement} */ (e.target).checked };
    });
    q('#pkt-mbf')?.addEventListener('change', e => {
      this.packet = { ...this.packet, mustBeFresh: /** @type {HTMLInputElement} */ (e.target).checked };
    });

    // Nonce regen
    q('#nonce-regen')?.addEventListener('click', () => {
      const el = q('#pkt-nonce');
      if (el) el.textContent = this._randomNonce();
    });

    // Content / Freshness (Data mode)
    q('#pkt-content')?.addEventListener('input', e => {
      this.packet = { ...this.packet, content: /** @type {HTMLTextAreaElement} */ (e.target).value };
    });
    this._wireSlider('pkt-freshness', 'pkt-freshness-val',
      v => { this.packet = { ...this.packet, freshnessMs: v }; },
      v => this._fmtMs(v));

    // Swimlane controls
    q('#swim-add-btn')?.addEventListener('click', () => this._addToSwimlane());
    q('#swim-clear-btn')?.addEventListener('click', () => this._clearSwimlane());
    /** @type {HTMLSelectElement|null} */ (q('#swim-scenario-select'))
      ?.addEventListener('change', e => {
        const key = /** @type {HTMLSelectElement} */ (e.target).value;
        if (key) { this._loadSwimlaneScenario(key); }
      });

    // Toggle buttons
    qa('.toggle-btn[data-knob]').forEach(btn => {
      btn.addEventListener('click', () => {
        const el = /** @type {HTMLElement} */ (btn);
        const knob = /** @type {keyof SimSettings} */ (el.dataset.knob);
        if (!knob) return;
        const next = !/** @type {any} */ (this.settings)[knob];
        /** @type {any} */ (this.settings)[knob] = next;
        el.textContent = next ? 'On' : 'Off';
        el.classList.toggle('on', next);
        el.classList.toggle('off', !next);
      });
    });

    // Strategy select
    q('#strategy-select')?.addEventListener('change', e => {
      this.settings.strategy = /** @type {StrategyName} */ (
        /** @type {HTMLSelectElement} */ (e.target).value);
    });

    // Sliders: CS size, face count, RTT
    this._wireSlider('cs-size',    'cs-size-val',    v => { this.settings.csSize    = v; });
    this._wireSlider('face-count', 'face-count-val', v => { this.settings.faceCount = v; });
    this._wireSlider('rtt-slider', 'rtt-val',        v => { this.settings.rttMs     = v; }, v => `${v} ms`);

    // Swimlane cell clicks → show detail
    this.container.querySelector('#swimlane-grid')?.addEventListener('click', e => {
      const cell = /** @type {HTMLElement|null} */ (
        /** @type {HTMLElement} */ (e.target).closest('[data-swim-id]'));
      if (!cell) return;
      const id  = parseInt(cell.dataset.swimId ?? '');
      const si  = parseInt(cell.dataset.stageIdx ?? '');
      const row = this.swimRows.find(r => r.id === id);
      if (!row) return;
      const ev = row.events.find(ev => ev.index === si);
      if (ev) this._showDetail(ev);
    });
  }

  // ── Swimlane control ──────────────────────────────────────────────────────

  _addToSwimlane() {
    if (this.swimRows.length >= 5) {
      // Shift oldest row off to make room.
      this.swimRows.shift();
    }
    const events = simulate(this.packet, this.settings);
    const id     = ++this._nextSwimId;
    const color  = SWIM_COLORS[(id - 1) % SWIM_COLORS.length];
    const typeLabel = this.packet.type === 'interest' ? 'Interest' : 'Data';
    this.swimRows.push({ id, label: `${typeLabel} ${id}`, color, packet: { ...this.packet }, events });

    // Also run the main animation so the user sees what was added.
    this._runSimulation();
    this._refreshSwimlane();
  }

  _clearSwimlane() {
    this.swimRows = [];
    this._nextSwimId = 0;
    this._refreshSwimlane();
    // Reset the scenario dropdown.
    const sel = /** @type {HTMLSelectElement|null} */ (
      this.container.querySelector('#swim-scenario-select'));
    if (sel) sel.value = '';
  }

  /** @param {string} key */
  _loadSwimlaneScenario(key) {
    const sc = SWIMLANE_SCENARIOS[key];
    if (!sc) return;
    this.swimRows = [];
    this._nextSwimId = 0;
    const defaultSettings = {
      csHit: false, csSize: 250, pitPending: false, pitNonceCollide: false,
      strategy: /** @type {StrategyName} */ ('BestRoute'), faceCount: 2, sigValid: true, rttMs: 50,
    };
    sc.packets.forEach(({ packet, settings }) => {
      const id    = ++this._nextSwimId;
      const color = SWIM_COLORS[(id - 1) % SWIM_COLORS.length];
      const merged = { ...defaultSettings, ...settings };
      const events = simulate(packet, merged);
      this.swimRows.push({ id, label: packet.type, color, packet: { ...packet }, events });
    });
    this._refreshSwimlane();
    // Load first packet into the composer and run its animation.
    const first = sc.packets[0];
    if (first) {
      this.packet   = { ...this.packet, ...first.packet };
      this.settings = { ...this.settings, ...first.settings };
      this.render();
      // Re-select the scenario in the dropdown after re-render.
      setTimeout(() => {
        const sel = /** @type {HTMLSelectElement|null} */ (
          this.container.querySelector('#swim-scenario-select'));
        if (sel) sel.value = key;
        this._runSimulation();
      }, 10);
    }
  }

  /** Re-render just the swimlane grid without rebuilding the full view. */
  _refreshSwimlane() {
    const grid = this.container.querySelector('#swimlane-grid');
    if (grid) grid.innerHTML = this._renderSwimlaneGrid();
    // Re-attach click listener on the newly created grid content.
    // The delegated listener is on #swimlane-grid which persists.
  }

  /**
   * Wire a range input to a value display span and an onChange callback.
   * @param {string} inputId
   * @param {string} valId
   * @param {(v: number) => void} onChange
   * @param {(v: number) => string} [fmt]
   */
  _wireSlider(inputId, valId, onChange, fmt) {
    const input = /** @type {HTMLInputElement|null} */ (this.container.querySelector(`#${inputId}`));
    const valEl = this.container.querySelector(`#${valId}`);
    if (!input || !valEl) return;
    input.addEventListener('input', () => {
      const v = parseInt(input.value);
      onChange(v);
      valEl.textContent = fmt ? fmt(v) : String(v);
    });
  }

  // ── Simulation control ────────────────────────────────────────────────────

  /** @param {string} key */
  _loadScenario(key) {
    const s = SCENARIOS[key];
    if (!s) return;
    this.packet   = { ...this.packet,   ...s.packet   };
    this.settings = { ...this.settings, ...s.settings };
    this.render();
    // Auto-play after DOM settles.
    setTimeout(() => this._runSimulation(), 80);
  }

  _runSimulation() {
    this._stopTimer();
    this.simEvents = simulate(this.packet, this.settings);

    if (this.simEvents.length === 0) return;

    if (this.stepDelay === 0) {
      // Instant: jump to final state.
      const lastIdx = this.simEvents.length - 1;
      this._applyStageClass(lastIdx, false);
      this._showDetail(this.simEvents[lastIdx]);
      return;
    }

    // Animated step-through.
    let i = 0;
    const advance = () => {
      if (i >= this.simEvents.length) { this.simTimer = null; return; }
      this._applyStageClass(i, true);
      this._showDetail(this.simEvents[i]);
      i++;
      this.simTimer = setTimeout(advance, this.stepDelay);
    };
    advance();
  }

  _resetSimulation() {
    this._stopTimer();
    this.simEvents = [];
    this.container.querySelectorAll('.stage-box').forEach(box => {
      box.classList.remove('sim-current', 'sim-done', 'sim-exit');
    });
    const detail = this.container.querySelector('#pipe-detail');
    if (detail) detail.innerHTML =
      '<h3>Ready</h3><p>Configure the packet and settings above, then click <strong>▶ Run</strong>.</p>';
  }

  _stopTimer() {
    if (this.simTimer !== null) { clearTimeout(this.simTimer); this.simTimer = null; }
  }

  /**
   * Apply sim-current / sim-done / sim-exit classes for event at index i.
   * @param {number} eventIdx
   * @param {boolean} animated - restart CSS animation
   */
  _applyStageClass(eventIdx, animated) {
    const ev = this.simEvents[eventIdx];
    const stageIdx = ev.index;
    const isFail = ev.action === 'Drop' || ev.action === 'Nack';
    const activeCls = isFail ? 'sim-exit' : 'sim-current';

    this.container.querySelectorAll('.stage-box').forEach((box, boxIdx) => {
      box.classList.remove('sim-current', 'sim-done', 'sim-exit');
      if (boxIdx < stageIdx) box.classList.add('sim-done');
    });

    const activeBox = /** @type {HTMLElement|undefined} */ (
      this.container.querySelectorAll('.stage-box')[stageIdx]);
    if (activeBox) {
      if (animated) void activeBox.offsetWidth; // force reflow → restart @keyframes
      activeBox.classList.add(activeCls);
    }
  }

  /**
   * Render the stage detail panel for a simulation event.
   * @param {StageEvent} ev
   */
  _showDetail(ev) {
    const actCls = ACTION_CLASSES[ev.action] ?? '';
    const stateRows = Object.entries(ev.state).map(([k, v]) =>
      `<div class="sim-state-row">
         <span class="sim-state-key">${k}</span>
         <span class="sim-state-val">${this._esc(v)}</span>
       </div>`).join('');

    const termNote = ev.terminal
      ? `<div class="sim-terminal-note">
           Pipeline ends here —
           <span class="action-tag ${actCls}">${ev.action}</span>
         </div>`
      : '';

    const stage = STAGE_DEFS[this.packet.type][ev.index];
    const allActions = stage
      ? `<div class="action-list" style="margin-top:0.35rem">
           <span style="font-size:0.72rem;color:var(--text2);margin-right:0.2rem">
             Possible outcomes:</span>
           ${stage.actions.map(a =>
             `<span class="action-tag ${ACTION_CLASSES[a] ?? ''}">${a}</span>`).join('')}
         </div>`
      : '';

    const detail = this.container.querySelector('#pipe-detail');
    if (!detail) return;
    detail.innerHTML = `
      <h3>Stage ${ev.index + 1}: ${ev.name}</h3>
      <p>${stage?.desc ?? ev.detail}</p>
      ${stateRows ? `<div class="sim-state-grid">${stateRows}</div>` : ''}
      <div class="action-list" style="margin-top:0.5rem">
        <span style="font-size:0.72rem;color:var(--text2);margin-right:0.2rem">This run:</span>
        <span class="action-tag ${actCls}">${ev.action}</span>
        <span style="font-size:0.78rem;color:var(--text2);margin-left:0.35rem">${ev.detail}</span>
      </div>
      ${allActions}
      ${termNote}`;
  }

  // ── Utilities ─────────────────────────────────────────────────────────────

  /** @returns {string} */
  _randomNonce() {
    return (Math.random() * 0xFFFFFFFF >>> 0).toString(16).toUpperCase().padStart(8, '0');
  }

  /**
   * @param {number} ms
   * @returns {string}
   */
  _fmtMs(ms) {
    if (ms === 0) return '0 ms';
    if (ms < 1000) return `${ms} ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)} s`;
    if (ms < 3600000) return `${(ms / 60000).toFixed(1)} min`;
    return `${(ms / 3600000).toFixed(1)} hr`;
  }

  /**
   * Escape HTML special characters for safe innerHTML insertion.
   * @param {string} s
   * @returns {string}
   */
  _esc(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
}
