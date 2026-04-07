// @ts-check
/**
 * Guided Tour — rewritten with:
 *   • Spotlight overlay: dims the page and highlights the relevant UI element
 *   • Embedded mini-demos: inline interactive widgets per step
 *   • Scenario-launch action buttons that deep-link into other views
 */

// ── Spotlight overlay ─────────────────────────────────────────────────────────

class Spotlight {
  constructor() {
    /** @type {SVGSVGElement|null} */ this._svg = null;
    this._bound = this._onResize.bind(this);
  }

  /** @param {string} selector  CSS selector for the element to highlight */
  show(selector) {
    const el = document.querySelector(selector);
    if (!el) { this.hide(); return; }
    this._selector = selector;
    this._render(el);
    window.addEventListener('resize', this._bound);
  }

  hide() {
    window.removeEventListener('resize', this._bound);
    if (this._svg) { this._svg.remove(); this._svg = null; }
  }

  _onResize() {
    if (this._selector) {
      const el = document.querySelector(this._selector);
      if (el) this._render(el);
    }
  }

  /** @param {Element} el */
  _render(el) {
    const r = el.getBoundingClientRect();
    const pad = 8;
    const W = window.innerWidth;
    const H = window.innerHeight;
    const x = Math.max(0, r.left - pad);
    const y = Math.max(0, r.top - pad);
    const w = r.width + pad * 2;
    const h = r.height + pad * 2;

    if (!this._svg) {
      const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      svg.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;z-index:9998;pointer-events:none;transition:opacity 0.25s';
      svg.style.opacity = '0';
      document.body.appendChild(svg);
      this._svg = /** @type {SVGSVGElement} */(svg);
      requestAnimationFrame(() => { if (this._svg) this._svg.style.opacity = '1'; });
    }

    this._svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
    this._svg.innerHTML = `
      <defs>
        <mask id="sl-mask">
          <rect width="${W}" height="${H}" fill="white"/>
          <rect x="${x}" y="${y}" width="${w}" height="${h}" rx="8" fill="black"/>
        </mask>
      </defs>
      <rect width="${W}" height="${H}" fill="rgba(0,0,0,0.6)" mask="url(#sl-mask)"/>
      <rect x="${x}" y="${y}" width="${w}" height="${h}" rx="8"
            fill="none" stroke="#58a6ff" stroke-width="2" opacity="0.85">
        <animate attributeName="opacity" values="0.85;0.5;0.85" dur="2s" repeatCount="indefinite"/>
      </rect>
    `;
  }
}

// ── Mini-demo renderers ───────────────────────────────────────────────────────

/**
 * Inline TLV hex demo — a byte-annotated NDN Interest packet.
 * Hovering / clicking a color band shows the TLV field name.
 * @returns {HTMLElement}
 */
function demoTlv() {
  // Pre-encoded Interest for /ndn/test  (minimal, canonical)
  // 05 19  07 0f 08 03 6e 64 6e  08 04 74 65 73 74  0a 04 ab cd 12 34  0c 02 0f a0
  const bytes = [
    0x05, 0x19,                                    // Interest TLV
    0x07, 0x0f,                                    // Name TLV
      0x08, 0x03, 0x6e, 0x64, 0x6e,               //   "ndn"
      0x08, 0x04, 0x74, 0x65, 0x73, 0x74,         //   "test"
    0x0a, 0x04, 0xab, 0xcd, 0x12, 0x34,           // Nonce
    0x0c, 0x02, 0x0f, 0xa0,                        // InterestLifetime 4000ms
  ];

  // Byte ranges → field info
  const ranges = [
    { start: 0,  end: 1,  label: 'Interest (type 0x05)',     cat: 'container' },
    { start: 2,  end: 3,  label: 'Name (type 0x07)',          cat: 'name' },
    { start: 4,  end: 8,  label: 'NameComponent "ndn"',       cat: 'name' },
    { start: 9,  end: 14, label: 'NameComponent "test"',      cat: 'name' },
    { start: 15, end: 20, label: 'Nonce (type 0x0a)',         cat: 'nonce' },
    { start: 21, end: 24, label: 'InterestLifetime = 4000ms', cat: 'lifetime' },
  ];

  const COLORS = {
    container: '#d2a8ff',
    name:      '#79c0ff',
    nonce:     '#ffa657',
    lifetime:  '#3fb950',
  };

  const wrap = document.createElement('div');
  wrap.className = 'mini-tlv-wrap';

  const tooltip = document.createElement('div');
  tooltip.className = 'mini-tlv-tooltip';
  tooltip.textContent = 'Hover a colored byte to see its field name';

  const hexRow = document.createElement('div');
  hexRow.className = 'mini-tlv-hex';

  bytes.forEach((b, i) => {
    const span = document.createElement('span');
    span.className = 'mini-tlv-byte';
    span.textContent = b.toString(16).padStart(2, '0');

    const range = ranges.find(r => i >= r.start && i <= r.end);
    if (range) {
      span.style.background = COLORS[range.cat] + '33';
      span.style.borderBottom = `2px solid ${COLORS[range.cat]}`;
      span.addEventListener('mouseenter', () => {
        tooltip.textContent = range.label;
        tooltip.style.color = COLORS[range.cat];
        // Highlight all bytes in same range
        hexRow.querySelectorAll('.mini-tlv-byte').forEach((s, j) => {
          /** @type {HTMLElement} */(s).style.opacity = (j >= range.start && j <= range.end) ? '1' : '0.3';
        });
      });
      span.addEventListener('mouseleave', () => {
        hexRow.querySelectorAll('.mini-tlv-byte').forEach(s => {
          /** @type {HTMLElement} */(s).style.opacity = '1';
        });
        tooltip.textContent = 'Hover a colored byte to see its field name';
        tooltip.style.color = '';
      });
    }
    hexRow.appendChild(span);
    if ((i + 1) % 8 === 0 || i === bytes.length - 1) {
      hexRow.appendChild(Object.assign(document.createElement('br'), {}));
    } else {
      hexRow.appendChild(Object.assign(document.createElement('span'), { textContent: ' ', className: 'mini-tlv-sp' }));
    }
  });

  // Legend
  const legend = document.createElement('div');
  legend.className = 'mini-tlv-legend';
  Object.entries(COLORS).forEach(([cat, color]) => {
    const item = document.createElement('span');
    item.className = 'mini-tlv-legend-item';
    item.innerHTML = `<span class="mini-tlv-swatch" style="background:${color}"></span>${cat}`;
    legend.appendChild(item);
  });

  wrap.appendChild(hexRow);
  wrap.appendChild(tooltip);
  wrap.appendChild(legend);
  return wrap;
}

/**
 * Mini pipeline animation — stages light up as the bubble moves through.
 * @returns {HTMLElement}
 */
function demoPipeline() {
  const STAGES = ['TlvDecode', 'CsLookup', 'PitCheck', 'Strategy', 'Dispatch'];
  const COLORS = ['#79c0ff', '#d2a8ff', '#ffa657', '#3fb950', '#58a6ff'];

  const wrap = document.createElement('div');
  wrap.className = 'mini-pipe-wrap';

  const track = document.createElement('div');
  track.className = 'mini-pipe-track';

  const stageEls = STAGES.map((name, i) => {
    const box = document.createElement('div');
    box.className = 'mini-pipe-stage';
    box.textContent = name;
    box.dataset.idx = String(i);
    track.appendChild(box);
    if (i < STAGES.length - 1) {
      const arrow = document.createElement('span');
      arrow.className = 'mini-pipe-arrow';
      arrow.textContent = '→';
      track.appendChild(arrow);
    }
    return box;
  });

  const label = document.createElement('div');
  label.className = 'mini-pipe-label';
  label.textContent = 'Interest: /ndn/example';

  wrap.appendChild(label);
  wrap.appendChild(track);

  // Animation
  let cur = -1;
  /** @type {number|null} */ let timer = null;

  const advance = () => {
    if (cur >= 0 && cur < stageEls.length) {
      stageEls[cur].classList.remove('mini-pipe-active');
      stageEls[cur].classList.add('mini-pipe-done');
    }
    cur++;
    if (cur < stageEls.length) {
      stageEls[cur].classList.add('mini-pipe-active');
      stageEls[cur].style.borderColor = COLORS[cur];
      label.textContent = cur === 1 ? 'CsLookup: miss (forwarding)' :
                          cur === 4 ? 'Dispatched to face 1' : label.textContent;
      timer = window.setTimeout(advance, 600);
    } else {
      // Restart after pause
      timer = window.setTimeout(restart, 1800);
    }
  };

  const restart = () => {
    cur = -1;
    stageEls.forEach(s => { s.classList.remove('mini-pipe-active', 'mini-pipe-done'); s.style.borderColor = ''; });
    label.textContent = 'Interest: /ndn/example';
    timer = window.setTimeout(advance, 400);
  };

  // Start on first paint
  timer = window.setTimeout(advance, 300);

  // Clean up when element is removed
  const obs = new MutationObserver(() => {
    if (!document.body.contains(wrap)) { if (timer) clearTimeout(timer); obs.disconnect(); }
  });
  obs.observe(document.body, { childList: true, subtree: true });

  return wrap;
}

/**
 * Mini FIB trie — BestRoute vs Multicast strategy toggle.
 * @returns {HTMLElement}
 */
function demoStrategy() {
  const wrap = document.createElement('div');
  wrap.className = 'mini-strat-wrap';

  const tabs = document.createElement('div');
  tabs.className = 'mini-strat-tabs';
  ['BestRoute', 'Multicast'].forEach((name, i) => {
    const btn = document.createElement('button');
    btn.className = 'mini-strat-tab' + (i === 0 ? ' active' : '');
    btn.textContent = name;
    btn.addEventListener('click', () => {
      tabs.querySelectorAll('.mini-strat-tab').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      renderFib(name);
    });
    tabs.appendChild(btn);
  });

  const fibView = document.createElement('div');
  fibView.className = 'mini-strat-fib';

  const renderFib = (/** @type {string} */ strategy) => {
    const isBR = strategy === 'BestRoute';
    fibView.innerHTML = `
      <div class="mini-fib-row">
        <span class="mini-fib-prefix">/ndn</span>
        <span class="mini-fib-arrow">→</span>
        <span class="mini-fib-faces">
          <span class="mini-fib-face ${isBR ? 'chosen' : 'chosen'}">face 1 (10ms)</span>
          ${isBR ? '' : ' <span class="mini-fib-face chosen">face 2 (15ms)</span>'}
        </span>
        <span class="mini-fib-action">${isBR ? 'forward on best' : 'forward on all'}</span>
      </div>
      <div class="mini-fib-row">
        <span class="mini-fib-prefix">/ndn/local</span>
        <span class="mini-fib-arrow">→</span>
        <span class="mini-fib-faces"><span class="mini-fib-face">face 3 (loopback)</span></span>
        <span class="mini-fib-action">local only</span>
      </div>
      <div class="mini-strat-note">
        ${isBR
          ? 'BestRoute: pick the nexthop with lowest EWMA RTT. Fall back if probe fails.'
          : 'Multicast: send on every nexthop simultaneously. Used for discovery and live streams.'
        }
      </div>
    `;
  };

  renderFib('BestRoute');
  wrap.appendChild(tabs);
  wrap.appendChild(fibView);
  return wrap;
}

/**
 * Mini topology demo — 3-node chain with animated bubble.
 * @returns {HTMLElement}
 */
function demoTopology() {
  const SVG_W = 320, SVG_H = 80;
  const nodes = [
    { id: 'C', label: 'Consumer', x: 40,  kind: 'consumer' },
    { id: 'R', label: 'Router',   x: 160, kind: 'router' },
    { id: 'P', label: 'Producer', x: 280, kind: 'producer' },
  ];
  const COLORS = { consumer: '#3fb950', router: '#58a6ff', producer: '#f0883e' };

  const wrap = document.createElement('div');
  wrap.className = 'mini-topo-wrap';

  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', `0 0 ${SVG_W} ${SVG_H}`);
  svg.setAttribute('width', String(SVG_W));
  svg.setAttribute('height', String(SVG_H));
  svg.style.display = 'block';

  // Links
  for (let i = 0; i < nodes.length - 1; i++) {
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', String(nodes[i].x)); line.setAttribute('y1', '40');
    line.setAttribute('x2', String(nodes[i+1].x)); line.setAttribute('y2', '40');
    line.setAttribute('stroke', '#30363d'); line.setAttribute('stroke-width', '2');
    svg.appendChild(line);
  }

  // Nodes
  nodes.forEach(n => {
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    const c = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    c.setAttribute('cx', String(n.x)); c.setAttribute('cy', '40'); c.setAttribute('r', '18');
    c.setAttribute('fill', COLORS[n.kind]);
    const t = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    t.setAttribute('x', String(n.x)); t.setAttribute('y', '45');
    t.setAttribute('text-anchor', 'middle'); t.setAttribute('fill', '#0d1117');
    t.setAttribute('font-size', '14'); t.setAttribute('font-weight', 'bold');
    t.textContent = n.id;
    const lbl = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    lbl.setAttribute('x', String(n.x)); lbl.setAttribute('y', '70');
    lbl.setAttribute('text-anchor', 'middle'); lbl.setAttribute('fill', '#8b949e');
    lbl.setAttribute('font-size', '10'); lbl.textContent = n.label;
    g.appendChild(c); g.appendChild(t); g.appendChild(lbl);
    svg.appendChild(g);
  });

  // Bubble element (reused)
  const bub = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  bub.setAttribute('r', '9'); bub.setAttribute('cy', '40'); bub.setAttribute('cx', '-20');
  bub.setAttribute('fill', '#58a6ff'); bub.setAttribute('opacity', '0.9');
  svg.appendChild(bub);

  wrap.appendChild(svg);

  const lbl = document.createElement('div');
  lbl.className = 'mini-topo-label';
  lbl.textContent = 'Interest: /ndn/data/hello';
  wrap.appendChild(lbl);

  // Animation: C→R→P (Interest blue) then P→R→C (Data green)
  const hops = [
    { from: 40, to: 160, color: '#58a6ff', text: 'Interest →',    delay: 0 },
    { from: 160, to: 280, color: '#58a6ff', text: '→ Interest',    delay: 700 },
    { from: 280, to: 160, color: '#3fb950', text: '← Data',        delay: 1400 },
    { from: 160, to: 40,  color: '#3fb950', text: 'Data ←',        delay: 2100 },
  ];

  let hopIdx = 0;
  /** @type {Animation|null} */ let anim = null;

  const runNext = () => {
    if (hopIdx >= hops.length) {
      hopIdx = 0;
      window.setTimeout(runNext, 1200);
      return;
    }
    const h = hops[hopIdx++];
    bub.setAttribute('fill', h.color);
    lbl.textContent = h.text;
    bub.setAttribute('cx', String(h.from));
    if (anim) anim.cancel();
    anim = bub.animate([
      { transform: `translateX(${h.from}px)` },
      { transform: `translateX(${h.to}px)` },
    ], { duration: 500, easing: 'ease-in-out', fill: 'forwards' });
    // Use setAttribute after animation
    anim.addEventListener('finish', () => {
      bub.setAttribute('cx', String(h.to));
      window.setTimeout(runNext, h.delay + 200);
    }, { once: true });
  };

  window.setTimeout(runNext, 500);

  const obs = new MutationObserver(() => {
    if (!document.body.contains(wrap)) { anim?.cancel(); obs.disconnect(); }
  });
  obs.observe(document.body, { childList: true, subtree: true });

  return wrap;
}

/**
 * Condensed signing animation — auto-cycles through 3 steps.
 * @returns {HTMLElement}
 */
function demoSecurity() {
  const steps = [
    {
      label: 'Signed region',
      html: `<div class="mini-sec-fields">
        <span class="mini-sec-field s">Name</span>
        <span class="mini-sec-field s">MetaInfo</span>
        <span class="mini-sec-field s">Content</span>
        <span class="mini-sec-field s">SignatureInfo</span>
        <span class="mini-sec-field x">SignatureValue ??</span>
      </div>`,
    },
    {
      label: 'SHA-256 hash',
      html: `<div class="mini-sec-flow">
        <span class="mini-sec-field s">bytes</span>
        <span class="mini-sec-arr">→</span>
        <span class="mini-sec-box hash">SHA-256</span>
        <span class="mini-sec-arr">→</span>
        <span class="mini-sec-bytes">a3 f8 … (32 B)</span>
      </div>`,
    },
    {
      label: 'Signature appended',
      html: `<div class="mini-sec-fields">
        <span class="mini-sec-field s">Name</span>
        <span class="mini-sec-field s">MetaInfo</span>
        <span class="mini-sec-field s">Content</span>
        <span class="mini-sec-field s">SignatureInfo</span>
        <span class="mini-sec-field done">SignatureValue ✓</span>
      </div>`,
    },
  ];

  const wrap = document.createElement('div');
  wrap.className = 'mini-sec-wrap';

  const stepLabel = document.createElement('div');
  stepLabel.className = 'mini-sec-step-label';

  const content = document.createElement('div');
  content.className = 'mini-sec-content';

  const dots = document.createElement('div');
  dots.className = 'mini-sec-dots';
  steps.forEach((_, i) => {
    const d = document.createElement('span');
    d.className = 'mini-sec-dot';
    dots.appendChild(d);
  });

  wrap.appendChild(stepLabel);
  wrap.appendChild(content);
  wrap.appendChild(dots);

  let cur = 0;
  /** @type {number|null} */ let t = null;

  const show = (i) => {
    cur = i % steps.length;
    const s = steps[cur];
    stepLabel.textContent = `Step ${cur + 1}: ${s.label}`;
    content.innerHTML = s.html;
    dots.querySelectorAll('.mini-sec-dot').forEach((d, j) => {
      d.classList.toggle('active', j === cur);
    });
  };

  const cycle = () => {
    show(cur + 1);
    t = window.setTimeout(cycle, 2000);
  };

  show(0);
  t = window.setTimeout(cycle, 2000);

  const obs = new MutationObserver(() => {
    if (!document.body.contains(wrap)) { if (t) clearTimeout(t); obs.disconnect(); }
  });
  obs.observe(document.body, { childList: true, subtree: true });

  return wrap;
}

// ── Tour step definitions ─────────────────────────────────────────────────────

/**
 * @typedef {{
 *   title: string,
 *   body: string,
 *   spotlight?: string,
 *   demo?: function(): HTMLElement,
 *   action?: { type: string, target: string, label?: string, scenario?: string }
 * }} TourStep
 */

/** @type {TourStep[]} */
const STEPS = [
  {
    title: 'Welcome to ndn-rs',
    body: `<strong>ndn-rs</strong> is a Named Data Networking forwarder stack written in Rust (31 crates, ~50 K lines).
      <br><br>NDN replaces IP addresses with <strong>content names</strong>. Consumers express
      <em>Interests</em> by name; the network routes them toward producers and caches
      <em>Data</em> packets at every hop on the return path.
      <br><br>This explorer lets you navigate the codebase, trace packets through the pipeline,
      and run simulations — all in-browser.`,
  },
  {
    title: 'TLV Wire Format & Packets',
    body: `Everything is encoded as <strong>Type-Length-Value</strong> (TLV) — self-describing,
      extensible binary framing. <code>ndn-tlv</code> provides the writer; <code>ndn-packet</code>
      provides typed Interest, Data, and Name structs.
      <br><br>Both crates are <code>no_std</code> and run on 32 KB microcontrollers.
      Fields are decoded <strong>lazily</strong> via <code>OnceLock</code> — a cache hit
      short-circuits before the nonce is ever parsed.
      <br><br><em>Hover the color-coded bytes →</em>`,
    spotlight: '.nav-btn[data-view="packet-explorer"]',
    demo: demoTlv,
    action: { type: 'view', target: 'packet-explorer', label: 'Open Packet Explorer →' },
  },
  {
    title: 'The Face Abstraction',
    body: `<code>ndn-transport</code> defines the <code>Face</code> trait:
      <br><br><code>async fn recv(&amp;self) → Bytes</code><br><code>async fn send(&amp;self, pkt: Bytes)</code>
      <br><br>Every transport implements it — UDP, TCP, raw Ethernet, Bluetooth, serial,
      WiFi-broadcast, in-process channels. Each face runs its own Tokio task pushing
      frames to a shared <code>mpsc</code> channel. One pipeline runner drains that channel.`,
    spotlight: '.nav-btn[data-view="dep-graph"]',
    action: { type: 'crate', target: 'ndn-transport' },
  },
  {
    title: 'Forwarding Tables: FIB, PIT, CS',
    body: `<code>ndn-store</code> provides the three core NDN tables:
      <br>&bull; <strong>FIB</strong> — <code>NameTrie</code> with per-node <code>RwLock</code>;
        concurrent longest-prefix match without holding parent locks
      <br>&bull; <strong>PIT</strong> — <code>DashMap</code> for sharded, lock-free Interest aggregation
        with O(1) expiry via hierarchical timing wheel
      <br>&bull; <strong>CS</strong> — trait-based with <code>LruCs</code>, <code>ShardedCs</code>,
        and <code>FjallCs</code> (disk-backed via RocksDB/redb)`,
    spotlight: '.nav-btn[data-view="layer-map"]',
    action: { type: 'crate', target: 'ndn-store' },
  },
  {
    title: 'The Packet Pipeline',
    body: `Packets flow through <code>PipelineStage</code>s <strong>by value</strong> — ownership
      transfer makes short-circuits compiler-enforced, not runtime-checked.
      Each stage returns an <code>Action</code> enum: <em>Continue, Send, Satisfy, Drop, Nack.</em>
      <br><br><strong>Interest:</strong> TlvDecode → CsLookup → PitCheck → Strategy → Dispatch
      <br><strong>Data:</strong> TlvDecode → PitMatch → Validation → CsInsert → Dispatch
      <br><br><em>Watch the mini pipeline animate →</em>`,
    spotlight: '.nav-btn[data-view="pipeline-trace"]',
    demo: demoPipeline,
    action: { type: 'view', target: 'pipeline-trace', label: 'Run Pipeline →', scenario: 'cache-hit' },
  },
  {
    title: 'Forwarding Strategies',
    body: `<code>ndn-strategy</code> provides <strong>BestRoute</strong>, <strong>Multicast</strong>,
      <strong>ASF</strong> (Adaptive SRTT-based Forwarding), and composed strategies.
      Strategies receive an <em>immutable</em> context and return a <code>ForwardingAction</code>.
      <br><br>A second name-trie maps prefixes to <code>Arc&lt;dyn Strategy&gt;</code>. Strategies
      are hot-swappable at runtime and can even be loaded from WASM modules.
      A measurements table tracks EWMA RTT and satisfaction rate per face/prefix.`,
    spotlight: '.nav-btn[data-view="pipeline-trace"]',
    demo: demoStrategy,
    action: { type: 'crate', target: 'ndn-strategy' },
  },
  {
    title: 'NDN Security & Signing',
    body: `Every NDN Data packet is <strong>signed</strong> — not just transport-layer TLS, but
      content-layer cryptographic binding. The <em>signed region</em> covers Name + MetaInfo +
      Content + SignatureInfo; SignatureValue holds the result.
      <br><br>Supported algorithms: <code>DigestSha256</code>, <code>ECDSA-P256</code>,
      <code>HMAC-SHA256</code>. Keys are identified by NDN name (KeyLocator), enabling
      a hierarchical <em>trust schema</em> rooted at a pre-installed trust anchor.`,
    spotlight: '.nav-btn[data-view="security"]',
    demo: demoSecurity,
    action: { type: 'view', target: 'security', label: 'Open Security View →' },
  },
  {
    title: 'Multi-Node Simulation',
    body: `<code>ndn-sim</code> builds multi-node topologies entirely in-process.
      <code>SimFace</code> implements the Face trait via Tokio channels with configurable
      delay, loss, bandwidth, and jitter.
      <br><br>The Topology view runs the same simulation logic in-browser — no server needed.
      Watch Interest packets traverse Consumer → Router → Producer and Data return along the
      reverse path, with in-network caching at the router on repeat requests.
      <br><br><em>Watch the animation →</em>`,
    spotlight: '.nav-btn[data-view="topology"]',
    demo: demoTopology,
    action: { type: 'view', target: 'topology', label: 'Open Topology →' },
  },
  {
    title: 'Explore!',
    body: `You've seen the highlights. Dive deeper:
      <br>&bull; <strong>Layers</strong> — all 31 crates sorted by architectural layer
      <br>&bull; <strong>Graph</strong> — interactive dependency graph with hover highlighting
      <br>&bull; <strong>Pipeline</strong> — run scenarios through the Interest/Data pipeline with live stage state
      <br>&bull; <strong>Packets</strong> — TLV encoder and hex inspector
      <br>&bull; <strong>Topology</strong> — multi-node NDN network simulation
      <br>&bull; <strong>Security</strong> — step-by-step signing and cert chain
      <br>&bull; <strong>Search</strong> — find any crate or type (press <code>/</code>)`,
    action: { type: 'view', target: 'layer-map', label: 'Start Exploring →' },
  },
];

// ── Tour class ────────────────────────────────────────────────────────────────

export class Tour {
  /** @param {HTMLElement} container @param {any} app */
  constructor(container, app) {
    this.container = container;
    this.app = app;
    this.current = 0;
    this.steps = STEPS;
    this._spotlight = new Spotlight();
    this._rendered = false;
  }

  /** Called once at startup (view is hidden) — build DOM without activating spotlight. */
  render() {
    this._rendered = true;
    this._renderStep(/* skipSpotlight= */ true);
  }

  /** Called when user navigates to the tour — activate spotlight for current step. */
  onShow() {
    if (!this._rendered) { this._rendered = true; this._renderStep(true); }
    const s = this.steps[this.current];
    if (s.spotlight) this._spotlight.show(s.spotlight);
    else this._spotlight.hide();
    // Hide spotlight when user navigates away via any nav button
    if (!this._navListener) {
      this._navListener = () => {
        if (this.app.currentView !== 'tour') this._spotlight.hide();
      };
      document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', /** @type {any} */(this._navListener));
      });
      document.querySelector('.logo')?.addEventListener('click', /** @type {any} */(this._navListener));
    }
  }

  // ── Step rendering ──────────────────────────────────────────────────────────

  /** @param {boolean} [skipSpotlight] */
  _renderStep(skipSpotlight = false) {
    const s = this.steps[this.current];
    const total = this.steps.length;
    const pct = ((this.current + 1) / total * 100).toFixed(0);

    this.container.innerHTML = `
      <div class="tour-header">
        <div class="tour-progress">
          Step ${this.current + 1} of ${total}
          <div class="tour-progress-bar">
            <div class="tour-progress-fill" style="width:${pct}%"></div>
          </div>
        </div>
      </div>
      <div class="tour-body ${s.demo ? 'tour-body-split' : ''}">
        <div class="tour-text-col">
          <div class="tour-card">
            <h2>${s.title}</h2>
            <p>${s.body}</p>
            ${s.action ? `<button class="tour-action" id="tour-action-btn">
              ${s.action.label ?? (s.action.type === 'crate' ? `View ${s.action.target} →` : `Open ${s.action.target} →`)}
            </button>` : ''}
          </div>
          <div class="tour-nav">
            ${this.current > 0 ? '<button class="tour-btn tour-btn-secondary" data-dir="prev">← Previous</button>' : ''}
            ${this.current < total - 1
              ? '<button class="tour-btn tour-btn-primary" data-dir="next">Next →</button>'
              : '<button class="tour-btn tour-btn-primary" data-dir="finish">Start Exploring</button>'}
          </div>
        </div>
        ${s.demo ? '<div class="tour-demo-col" id="tour-demo-col"></div>' : ''}
      </div>
    `;

    // Inject mini-demo
    if (s.demo) {
      const col = this.container.querySelector('#tour-demo-col');
      if (col) col.appendChild(s.demo());
    }

    // Spotlight — only when the tour is actively visible
    if (!skipSpotlight) {
      if (s.spotlight) this._spotlight.show(s.spotlight);
      else this._spotlight.hide();
    }

    // Action button
    const actionBtn = this.container.querySelector('#tour-action-btn');
    if (actionBtn && s.action) {
      actionBtn.addEventListener('click', () => {
        this._spotlight.hide();
        if (s.action?.type === 'crate') {
          this.app.showCrate(s.action.target);
        } else {
          this.app.navigate(s.action?.target);
        }
      });
    }

    // Nav buttons
    this.container.querySelectorAll('.tour-nav button').forEach(btn => {
      btn.addEventListener('click', () => {
        const dir = /** @type {HTMLElement} */(btn).dataset.dir;
        if (dir === 'next') { this.current++; this._renderStep(); }
        else if (dir === 'prev') { this.current--; this._renderStep(); }
        else { this._spotlight.hide(); this.app.navigate('layer-map'); }
      });
    });
  }
}
