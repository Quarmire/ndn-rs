// @ts-check
/**
 * Topology view — WASM-powered multi-node NDN network sandbox.
 *
 * Renders a live SVG topology of routers, consumers, and producers.
 * Packet bubbles (Interest blue, Data green, Nack red) animate along
 * links as the simulation runs. Clicking a node opens a live stats
 * panel (PIT / FIB / CS). Links color-code RTT after enough samples.
 *
 * Falls back to a pure-JS simulation when the WASM module is not built.
 */

// ── JS-side data types (mirror Rust's Serialize output) ───────────────────────

/**
 * @typedef {{ id: number, kind: 'router'|'consumer'|'producer', name: string,
 *             pitCount: number, csCount: number, csCapacity: number,
 *             servedPrefixes: string[] }} NodeSnap
 * @typedef {{ id: number, nodeA: number, nodeB: number, faceA: number, faceB: number,
 *             delayMs: number, bandwidthBps: number, lossRate: number }} LinkSnap
 * @typedef {{ kind: string, fromNode: number, toNode: number, linkId: number,
 *             name: string, detail: any, timeMs: number }} TopoEvent
 * @typedef {{ interestName: string, fromNode: number, satisfied: boolean,
 *             events: TopoEvent[], hops: number, totalRttMs: number }} TopoTrace
 * @typedef {{ name: string, description: string, consumerNode: number,
 *             interestName: string, nodes: NodeSnap[], links: LinkSnap[] }} ScenarioDesc
 */

// ── Pure-JS topology simulation (fallback when WASM not built) ─────────────────

class JsFibTable {
  constructor() {
    /** @type {Array<{prefix: string, faceId: number, cost: number}>} */
    this.routes = [];
  }
  /** @param {string} prefix @param {number} faceId @param {number} cost */
  add(prefix, faceId, cost) { this.routes.push({ prefix, faceId, cost }); }
  /** Longest-prefix match → [{faceId, cost}] sorted by cost ascending. */
  lpm(name) {
    let best = '';
    for (const r of this.routes) if (name === r.prefix || name.startsWith(r.prefix + '/') || name.startsWith(r.prefix)) {
      if (r.prefix.length >= best.length) best = r.prefix;
    }
    return this.routes.filter(r => r.prefix === best).sort((a, b) => a.cost - b.cost);
  }
}

class JsPitTable {
  constructor() { /** @type {Map<string, {inFace: number}>} */ this.entries = new Map(); }
  has(name) { return this.entries.has(name); }
  insert(name, inFace) { this.entries.set(name, { inFace }); }
  remove(name) { this.entries.delete(name); }
  snapshot() {
    return [...this.entries.entries()].map(([name, e]) => ({ name, inFace: e.inFace }));
  }
}

class JsCsTable {
  constructor(capacity = 100) {
    this.capacity = capacity;
    /** @type {Map<string, {name:string,content:string,freshnessMs:number}>} */
    this.entries = new Map();
  }
  insert(name, content, freshnessMs) {
    if (this.entries.size >= this.capacity) {
      const first = this.entries.keys().next().value;
      if (first !== undefined) this.entries.delete(first);
    }
    this.entries.set(name, { name, content, freshnessMs });
  }
  lookup(name) { return this.entries.get(name) ?? null; }
  snapshot() { return [...this.entries.values()]; }
}

class JsNode {
  /**
   * @param {number} id @param {'router'|'consumer'|'producer'} kind @param {string} name
   */
  constructor(id, kind, name) {
    this.id = id;
    this.kind = kind;
    this.name = name;
    this.fib = new JsFibTable();
    this.pit = new JsPitTable();
    this.cs = new JsCsTable(100);
    this.servedPrefixes = /** @type {string[]} */ ([]);
    /** @type {Array<{prefix:string,face:number,rttMs:number,count:number,satisfied:number}>} */
    this.measurements = [];
  }
  serves(name) { return this.servedPrefixes.some(p => name === p || name.startsWith(p + '/') || name.startsWith(p)); }
}

class JsTopologySim {
  constructor() {
    /** @type {Map<number, JsNode>} */ this.nodes = new Map();
    /** @type {Map<number, LinkSnap>} */ this.links = new Map();
    this._nextNode = 1;
    this._nextFace = 100;
    this._nextLink = 1;
    /** @type {Map<number,{ewmaRtt:number,count:number,satisfied:number,total:number}>} */
    this.linkMeasurements = new Map();
  }

  addRouter(name) { return this._addNode('router', name); }
  addConsumer(name) { return this._addNode('consumer', name); }
  addProducer(name, prefix = '') {
    const id = this._addNode('producer', name);
    if (prefix) this.nodes.get(id)?.servedPrefixes.push(prefix);
    return id;
  }
  _addNode(kind, name) {
    const id = this._nextNode++;
    this.nodes.set(id, new JsNode(id, /** @type {any} */(kind), name));
    return id;
  }

  addLink(nodeA, nodeB, delayMs = 10, bandwidthBps = 1e6, lossRate = 0) {
    const id = this._nextLink++;
    const faceA = this._nextFace++;
    const faceB = this._nextFace++;
    this.links.set(id, { id, nodeA, nodeB, faceA, faceB, delayMs, bandwidthBps, lossRate });
    return id;
  }

  addFibRoute(nodeId, prefix, linkId, cost = 0) {
    const link = this.links.get(linkId);
    if (!link) return;
    const faceId = link.nodeA === nodeId ? link.faceA : link.faceB;
    this.nodes.get(nodeId)?.fib.add(prefix, faceId, cost);
  }

  autoConfigureFib() {
    // BFS from each producer outward, installing routes on neighbors.
    for (const [, node] of this.nodes) {
      for (const prefix of node.servedPrefixes) {
        this._propagateRoute(node.id, prefix, 0, new Set([node.id]));
      }
    }
  }

  _propagateRoute(sourceId, prefix, cost, visited) {
    for (const [, link] of this.links) {
      const neighborId = link.nodeA === sourceId ? link.nodeB
                       : link.nodeB === sourceId ? link.nodeA : null;
      if (neighborId == null || visited.has(neighborId)) continue;
      const neighbor = this.nodes.get(neighborId);
      if (!neighbor) continue;
      const faceTowardSource = link.nodeA === neighborId ? link.faceA : link.faceB;
      const existing = neighbor.fib.lpm(prefix);
      if (existing.length === 0) {
        neighbor.fib.add(prefix, faceTowardSource, cost + 1);
        visited.add(neighborId);
        this._propagateRoute(neighborId, prefix, cost + 1, visited);
      }
    }
  }

  /**
   * @param {number} fromNode @param {string} interestName
   * @returns {TopoTrace}
   */
  sendInterest(fromNode, interestName) {
    /** @type {TopoEvent[]} */ const events = [];
    let timeMs = 0;
    const nonce = (Date.now() & 0xFFFFFFFF) >>> 0;

    const result = this._routeInterest(
      fromNode, null, interestName, nonce, 4000, 0, events, { t: timeMs }, 0
    );
    timeMs = result.timeMs;

    // Update link measurements
    const firstLink = [...this.links.values()].find(l => l.nodeA === fromNode || l.nodeB === fromNode);
    if (firstLink) {
      const m = this.linkMeasurements.get(firstLink.id) ?? { ewmaRtt: 0, count: 0, satisfied: 0, total: 0 };
      const alpha = 0.125;
      m.ewmaRtt = m.count === 0 ? timeMs : (1 - alpha) * m.ewmaRtt + alpha * timeMs;
      m.count++;
      m.total++;
      m.satisfied += result.satisfied ? 1 : 0;
      this.linkMeasurements.set(firstLink.id, m);
    }

    const hops = events.filter(e => e.kind === 'interest').length;
    return { interestName, fromNode, satisfied: result.satisfied, events, hops, totalRttMs: timeMs };
  }

  /**
   * @param {number} nodeId @param {number|null} inLinkId @param {string} name
   * @param {number} nonce @param {number} lifetimeMs @param {number} depth
   * @param {TopoEvent[]} events @param {{t: number}} timeMsRef @param {number} inFace
   * @returns {{satisfied: boolean, timeMs: number}}
   */
  _routeInterest(nodeId, inLinkId, name, nonce, lifetimeMs, depth, events, timeMsRef, inFace) {
    if (depth > 16) return { satisfied: false, timeMs: timeMsRef.t };

    const node = this.nodes.get(nodeId);
    if (!node) return { satisfied: false, timeMs: timeMsRef.t };

    if (node.serves(name)) {
      // Producer responds
      node.cs.insert(name, `Content for ${name}`, 10000);
      return { satisfied: true, timeMs: timeMsRef.t };
    }

    // CS lookup
    const csHit = node.cs.lookup(name);
    if (csHit) {
      if (inLinkId !== null) {
        const link = this.links.get(inLinkId);
        if (link) {
          const fromN = link.nodeA === nodeId ? link.nodeB : link.nodeA;
          events.push({ kind: 'cs-hit', fromNode: nodeId, toNode: fromN, linkId: inLinkId,
                        name, detail: { hitName: name }, timeMs: timeMsRef.t });
        }
      }
      return { satisfied: true, timeMs: timeMsRef.t };
    }

    // PIT check (aggregation)
    if (node.pit.has(name) && inLinkId !== null) {
      const link = this.links.get(inLinkId);
      if (link) {
        const fromN = link.nodeA === nodeId ? link.nodeB : link.nodeA;
        events.push({ kind: 'pit-aggregate', fromNode: nodeId, toNode: fromN, linkId: inLinkId,
                      name, detail: {}, timeMs: timeMsRef.t });
      }
      return { satisfied: false, timeMs: timeMsRef.t }; // pending, aggregated
    }

    // FIB lookup
    const nexthops = node.fib.lpm(name);
    if (nexthops.length === 0) return { satisfied: false, timeMs: timeMsRef.t };

    // Exclude in-face to avoid forwarding back
    const inFaceFromLink = inLinkId !== null ? (() => {
      const l = this.links.get(inLinkId);
      return l ? (l.nodeA === nodeId ? l.faceA : l.faceB) : 0;
    })() : 0;
    const chosen = nexthops.find(nh => nh.faceId !== inFaceFromLink) ?? nexthops[0];

    const outLink = [...this.links.values()].find(l =>
      (l.nodeA === nodeId && l.faceA === chosen.faceId) ||
      (l.nodeB === nodeId && l.faceB === chosen.faceId)
    );
    if (!outLink) return { satisfied: false, timeMs: timeMsRef.t };

    const nextNodeId = outLink.nodeA === nodeId ? outLink.nodeB : outLink.nodeA;
    const inFaceNext = outLink.nodeA === nodeId ? outLink.faceB : outLink.faceA;
    const delay = outLink.delayMs;

    events.push({ kind: 'interest', fromNode: nodeId, toNode: nextNodeId, linkId: outLink.id,
                  name, detail: { face: chosen.faceId, delay_ms: delay }, timeMs: timeMsRef.t });
    timeMsRef.t += delay;

    // PIT entry
    node.pit.insert(name, inFace);

    const inner = this._routeInterest(
      nextNodeId, outLink.id, name, nonce, lifetimeMs, depth + 1, events, timeMsRef, inFaceNext
    );

    if (inner.satisfied) {
      events.push({ kind: 'data', fromNode: nextNodeId, toNode: nodeId, linkId: outLink.id,
                    name, detail: { freshness_ms: 10000 }, timeMs: timeMsRef.t });
      timeMsRef.t += delay;
      node.cs.insert(name, `Content for ${name}`, 10000);
      node.pit.remove(name);
    } else {
      events.push({ kind: 'nack', fromNode: nextNodeId, toNode: nodeId, linkId: outLink.id,
                    name, detail: { reason: 'NoRoute' }, timeMs: timeMsRef.t });
      timeMsRef.t += delay;
      node.pit.remove(name);
    }

    return inner;
  }

  resetState() {
    for (const [, node] of this.nodes) {
      node.pit = new JsPitTable();
      node.cs = new JsCsTable(node.cs.capacity);
      node.measurements = [];
    }
    this.linkMeasurements.clear();
  }

  resetAll() {
    this.nodes.clear();
    this.links.clear();
    this._nextNode = 1;
    this._nextFace = 100;
    this._nextLink = 1;
    this.linkMeasurements.clear();
  }

  /** @returns {NodeSnap[]} */
  nodesSnapshot() {
    return [...this.nodes.values()].sort((a, b) => a.id - b.id).map(n => ({
      id: n.id, kind: n.kind, name: n.name,
      pitCount: n.pit.entries.size, csCount: n.cs.entries.size,
      csCapacity: n.cs.capacity, servedPrefixes: n.servedPrefixes,
    }));
  }
  /** @returns {LinkSnap[]} */
  linksSnapshot() {
    return [...this.links.values()].sort((a, b) => a.id - b.id);
  }
}

// ── Pre-built scenarios ───────────────────────────────────────────────────────

/** @type {Record<string, {label: string, desc: string, setup: function(JsTopologySim): ScenarioDesc}>} */
const SCENARIOS = {
  'linear': {
    label: 'Linear: Consumer → Router → Producer',
    desc: 'Basic 3-node chain. Each Interest travels 2 hops and the Data returns the same way.',
    setup(sim) {
      const c = sim.addConsumer('Consumer');
      const r = sim.addRouter('Router');
      const p = sim.addProducer('Producer', '/ndn/data');
      const l1 = sim.addLink(c, r, 10);
      const l2 = sim.addLink(r, p, 10);
      sim.addFibRoute(c, '/ndn', l1, 0);
      sim.addFibRoute(r, '/ndn', l2, 0);
      return { name: 'linear', description: 'Consumer → Router → Producer (10ms per hop)',
               consumerNode: c, interestName: '/ndn/data/hello',
               nodes: sim.nodesSnapshot(), links: sim.linksSnapshot() };
    },
  },
  'triangle-cache': {
    label: 'Cache Hit: Second Interest served from Router CS',
    desc: 'Send the Interest twice. First fetch goes to Producer (20ms). Second is served from Router CS (5ms).',
    setup(sim) {
      const c = sim.addConsumer('Consumer');
      const r = sim.addRouter('Router');
      const p = sim.addProducer('Producer', '/ndn/media');
      sim.nodes.get(r)?.cs && (sim.nodes.get(r).cs = new JsCsTable(50));
      const l1 = sim.addLink(c, r, 5);
      const l2 = sim.addLink(r, p, 20);
      sim.addFibRoute(c, '/ndn', l1, 0);
      sim.addFibRoute(r, '/ndn', l2, 0);
      return { name: 'triangle-cache',
               description: 'Send twice — second Interest hits Router CS',
               consumerNode: c, interestName: '/ndn/media/video.mp4',
               nodes: sim.nodesSnapshot(), links: sim.linksSnapshot() };
    },
  },
  'multipath': {
    label: 'Multipath: BestRoute vs two equal-cost paths',
    desc: 'Router has two links toward Producer. BestRoute picks the lower-cost one.',
    setup(sim) {
      const c = sim.addConsumer('Consumer');
      const r = sim.addRouter('Router');
      const p = sim.addProducer('Producer', '/ndn/stream');
      const l1 = sim.addLink(c, r, 5);
      const l2 = sim.addLink(r, p, 10);
      const l3 = sim.addLink(r, p, 15); // higher latency path
      sim.addFibRoute(c, '/ndn', l1, 0);
      sim.addFibRoute(r, '/ndn', l2, 1);
      sim.addFibRoute(r, '/ndn', l3, 2);
      return { name: 'multipath', description: 'BestRoute selects lowest-cost path (10ms over 15ms)',
               consumerNode: c, interestName: '/ndn/stream/live',
               nodes: sim.nodesSnapshot(), links: sim.linksSnapshot() };
    },
  },
  'aggregation': {
    label: 'Interest Aggregation: Two Consumers, same name',
    desc: 'Consumer-1 sends first. Consumer-2 sends the same name while PIT entry is pending — the Interest is aggregated at the Router.',
    setup(sim) {
      const c1 = sim.addConsumer('Consumer-1');
      const c2 = sim.addConsumer('Consumer-2');
      const r = sim.addRouter('Router');
      const p = sim.addProducer('Producer', '/ndn/shared');
      const l1 = sim.addLink(c1, r, 5);
      const l2 = sim.addLink(c2, r, 5);
      const l3 = sim.addLink(r, p, 20);
      sim.addFibRoute(c1, '/ndn', l1, 0);
      sim.addFibRoute(c2, '/ndn', l2, 0);
      sim.addFibRoute(r, '/ndn', l3, 0);
      return { name: 'aggregation',
               description: 'Consumer-2 Interest collapses in Router PIT',
               consumerNode: c1, interestName: '/ndn/shared/data',
               nodes: sim.nodesSnapshot(), links: sim.linksSnapshot() };
    },
  },
};

// ── Discovery walkthrough phases ──────────────────────────────────────────────

/** @type {Array<{title: string, body: string}>} */
const DISCOVERY_PHASES = [
  {
    title: '1 / 8 — Neighbor Discovery (Hello)',
    body: 'Routers periodically send <strong>Hello</strong> messages on every link. ' +
          'Each router builds a <em>neighbor table</em> from received Hellos. ' +
          'A missed heartbeat (timeout) signals link failure. No routing happens yet — ' +
          'this is purely a reachability probe.',
  },
  {
    title: '2 / 8 — Producer Registers Prefix',
    body: 'The Producer calls <code>registerPrefix("/ndn/edu/demo")</code> on its local face. ' +
          'A FIB entry is created at the Producer pointing toward the AppFace. ' +
          'This is the seed from which routes will propagate outward.',
  },
  {
    title: '3 / 8 — Prefix Announcement Propagation',
    body: 'The prefix <strong>/ndn/edu/demo</strong> propagates hop-by-hop as <em>FIB-update</em> ' +
          'messages. Router-B installs a route toward Producer (cost 1). ' +
          'Router-A installs two routes: via Router-B (cost 2) and a direct backup link (cost 3). ' +
          'Consumer installs a route toward Router-A (cost 0).',
  },
  {
    title: '4 / 8 — First Interest — Routed',
    body: 'With routes established, the Consumer sends <code>/ndn/edu/demo/file</code>. ' +
          'BestRoute selects <strong>Consumer → Router-A → Router-B → Producer</strong> ' +
          '(primary path, 26 ms RTT). Data returns the same way. Router-A and Router-B ' +
          'both cache the Data in their Content Stores.',
  },
  {
    title: '5 / 8 — Cache Hit at Router-B',
    body: 'The same Interest is sent again. <strong>Router-B</strong> finds the Data in its ' +
          'Content Store and satisfies the Interest locally — the Producer is never contacted. ' +
          'RTT drops from 26 ms to 13 ms. This is the core NDN in-network caching benefit.',
  },
  {
    title: '6 / 8 — Link Failure (Router-A ↔ Router-B)',
    body: 'The Router-A ↔ Router-B link goes down. Both routers detect the failure ' +
          'because the Hello heartbeat times out. The failed link is shown in red. ' +
          'Router-A\'s route via Router-B becomes unreachable.',
  },
  {
    title: '7 / 8 — Route Withdrawal',
    body: 'Router-A removes the broken route from its FIB. A <em>withdrawal message</em> ' +
          'propagates toward Consumer, invalidating routes that went via Router-B. ' +
          'Only the <strong>direct backup link</strong> (Router-A → Producer, 30 ms) remains in Router-A\'s FIB.',
  },
  {
    title: '8 / 8 — Fallback Path Active',
    body: 'Consumer sends the same Interest. With the primary path gone, Router-A forwards ' +
          'via the <strong>direct backup link</strong> to Producer (30 ms one-way vs. 13 ms one-way primary). ' +
          'RTT is 60 ms instead of 26 ms — higher latency but content is still reachable. ' +
          'ASF strategy would detect this and prefer the faster path once it recovers.',
  },
];

// ── Layout algorithm ──────────────────────────────────────────────────────────

const SVG_W = 700;
const SVG_H = 340;
const NODE_R = 28;

/**
 * Auto-layout nodes in a left-to-right tree rooted at consumers.
 * @param {NodeSnap[]} nodes @param {LinkSnap[]} links
 * @returns {Map<number,{x:number,y:number}>}
 */
function layoutNodes(nodes, links) {
  /** @type {Map<number,{x:number,y:number}>} */
  const pos = new Map();

  // Build adjacency list
  /** @type {Map<number,number[]>} */
  const adj = new Map(nodes.map(n => [n.id, []]));
  for (const l of links) {
    adj.get(l.nodeA)?.push(l.nodeB);
    adj.get(l.nodeB)?.push(l.nodeA);
  }

  // BFS layers starting from consumers
  const consumers = nodes.filter(n => n.kind === 'consumer');
  const producers = nodes.filter(n => n.kind === 'producer');
  const visited = new Set();

  // Assign column by BFS from consumers
  /** @type {Map<number,number>} */
  const depth = new Map();
  const queue = consumers.map(n => { depth.set(n.id, 0); visited.add(n.id); return n.id; });
  while (queue.length) {
    const cur = /** @type {number} */(queue.shift());
    const d = depth.get(cur) ?? 0;
    for (const nb of adj.get(cur) ?? []) {
      if (!visited.has(nb)) {
        visited.add(nb);
        depth.set(nb, d + 1);
        queue.push(nb);
      }
    }
  }
  // Unvisited nodes (isolated)
  for (const n of nodes) if (!depth.has(n.id)) depth.set(n.id, 1);

  // Group by depth
  /** @type {Map<number,number[]>} */
  const layers = new Map();
  for (const [id, d] of depth) {
    if (!layers.has(d)) layers.set(d, []);
    layers.get(d)?.push(id);
  }

  const maxDepth = Math.max(...depth.values());
  const numLayers = maxDepth + 1;
  const xStep = Math.min(200, (SVG_W - 80) / Math.max(1, numLayers - 1));
  const xStart = 60;

  for (const [d, ids] of layers) {
    const x = xStart + d * xStep;
    const yStep = SVG_H / (ids.length + 1);
    ids.forEach((id, i) => pos.set(id, { x, y: yStep * (i + 1) }));
  }

  return pos;
}

// ── Topology view ─────────────────────────────────────────────────────────────

export class TopologyView {
  /** @param {HTMLElement} container @param {any} app */
  constructor(container, app) {
    this.container = container;
    this.app = app;
    this._rendered = false;

    this._sim = new JsTopologySim();
    /** @type {ScenarioDesc|null} */
    this._scenario = null;
    /** @type {Map<number,{x:number,y:number}>} */
    this._positions = new Map();

    this._speed = 1.0; // animation speed multiplier
    this._running = false;
    this._packetCount = 0;
    /** @type {number|null} */
    this._selectedNode = null;
    /** @type {SVGSVGElement|null} */
    this._svg = null;
    /** Link id → total RTT samples for heatmap */
    /** @type {Map<number,{ewmaRtt:number,count:number}>} */
    this._linkStats = new Map();

    // Discovery walkthrough state
    this._discoveryMode = false;
    this._discoveryPhase = 0;
    /** @type {Set<number>} */
    this._failedLinks = new Set();
    /** @type {{consumer:number,r1:number,r2:number,producer:number}|null} */
    this._discNodeIds = null;
    /** @type {{l1:number,l2:number,l3:number,l4:number}|null} */
    this._discLinkIds = null;
    // Saved button refs for enable/disable during discovery
    /** @type {HTMLButtonElement|null} */ this._sendBtn = null;
    /** @type {HTMLButtonElement|null} */ this._resetStateBtn = null;
    /** @type {HTMLSelectElement|null} */ this._scenarioSelect = null;
  }

  onShow() {
    if (!this._rendered) {
      this._rendered = true;
      this._buildDOM();
      this._loadScenario('linear');
    }
  }

  // ── DOM construction ────────────────────────────────────────────────────────

  _buildDOM() {
    this.container.innerHTML = '';
    this.container.className = 'view topo-root';

    // Toolbar
    const toolbar = document.createElement('div');
    toolbar.className = 'topo-toolbar';
    toolbar.innerHTML = `
      <select class="topo-scenario-select" title="Choose a pre-built topology scenario">
        <optgroup label="Interactive Sandbox">
          ${Object.entries(SCENARIOS).map(([k, s]) =>
            `<option value="${k}">${s.label}</option>`
          ).join('')}
        </optgroup>
        <optgroup label="Discovery Walkthrough">
          <option value="discovery">NDN Discovery Bootstrap</option>
        </optgroup>
      </select>
      <button class="topo-btn topo-btn-send" title="Send an Interest from the Consumer node">Send Interest</button>
      <button class="topo-btn topo-btn-reset-state" title="Clear PIT/CS/measurements, keep topology">Reset State</button>
      <label class="topo-speed-label">
        Speed
        <select class="topo-speed-select">
          <option value="0.5">0.5×</option>
          <option value="1" selected>1×</option>
          <option value="2">2×</option>
          <option value="0">Instant</option>
        </select>
      </label>
    `;
    this._sendBtn = /** @type {HTMLButtonElement|null} */ (toolbar.querySelector('.topo-btn-send'));
    this._resetStateBtn = /** @type {HTMLButtonElement|null} */ (toolbar.querySelector('.topo-btn-reset-state'));
    this._scenarioSelect = /** @type {HTMLSelectElement|null} */ (toolbar.querySelector('.topo-scenario-select'));
    this.container.appendChild(toolbar);

    // Description bar
    const descBar = document.createElement('div');
    descBar.className = 'topo-desc-bar';
    this._descBar = descBar;
    this.container.appendChild(descBar);

    // Main area: canvas + stats panel
    const main = document.createElement('div');
    main.className = 'topo-main';

    const canvasWrap = document.createElement('div');
    canvasWrap.className = 'topo-canvas-wrap';
    this._canvasWrap = canvasWrap;
    main.appendChild(canvasWrap);

    const statsPanel = document.createElement('div');
    statsPanel.className = 'topo-stats-panel';
    statsPanel.innerHTML = '<p class="topo-stats-hint">Click a node to see its state.</p>';
    this._statsPanel = statsPanel;
    main.appendChild(statsPanel);

    this.container.appendChild(main);

    // Events log
    const log = document.createElement('div');
    log.className = 'topo-event-log';
    this._log = log;
    this.container.appendChild(log);

    // Wire up controls
    this._scenarioSelect?.addEventListener('change', (e) => {
      const val = /** @type {HTMLSelectElement} */(e.target).value;
      if (val === 'discovery') this._startDiscovery();
      else this._loadScenario(val);
    });
    toolbar.querySelector('.topo-btn-send')?.addEventListener('click', () => this._sendInterest());
    toolbar.querySelector('.topo-btn-reset-state')?.addEventListener('click', () => {
      this._sim.resetState();
      this._linkStats.clear();
      this._packetCount = 0;
      this._renderTopology();
      this._clearLog();
      this._appendLog('State reset — PIT, CS, and measurements cleared.');
    });
    toolbar.querySelector('.topo-speed-select')?.addEventListener('change', (e) => {
      this._speed = parseFloat(/** @type {HTMLSelectElement} */(e.target).value);
    });
  }

  // ── Scenario loading ────────────────────────────────────────────────────────

  /** @param {string} key */
  _loadScenario(key) {
    const def = SCENARIOS[key];
    if (!def) return;

    this._sim.resetAll();
    this._linkStats.clear();
    this._packetCount = 0;
    this._selectedNode = null;

    this._scenario = def.setup(this._sim);
    this._positions = layoutNodes(this._scenario.nodes, this._scenario.links);

    if (this._descBar) {
      this._descBar.textContent = def.desc;
    }
    if (this._statsPanel) {
      this._statsPanel.innerHTML = '<p class="topo-stats-hint">Click a node to see its state.</p>';
    }
    this._clearLog();
    this._appendLog(`Loaded scenario: ${def.label}`);
    this._renderTopology();
  }

  // ── SVG topology rendering ──────────────────────────────────────────────────

  _renderTopology() {
    if (!this._canvasWrap || !this._scenario) return;
    this._canvasWrap.innerHTML = '';

    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', `0 0 ${SVG_W} ${SVG_H}`);
    svg.setAttribute('width', String(SVG_W));
    svg.setAttribute('height', String(SVG_H));
    svg.className.baseVal = 'topo-svg';
    this._svg = svg;

    // Defs: arrowhead marker
    const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
    defs.innerHTML = `
      <marker id="topo-arrow-interest" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
        <path d="M0,0 L0,6 L8,3 z" fill="#58a6ff"/>
      </marker>
      <marker id="topo-arrow-data" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
        <path d="M0,0 L0,6 L8,3 z" fill="#3fb950"/>
      </marker>
      <marker id="topo-arrow-nack" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
        <path d="M0,0 L0,6 L8,3 z" fill="#f85149"/>
      </marker>
    `;
    svg.appendChild(defs);

    // Links layer
    const linksG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    linksG.className.baseVal = 'topo-links';
    for (const link of this._scenario.links) {
      const pa = this._positions.get(link.nodeA);
      const pb = this._positions.get(link.nodeB);
      if (!pa || !pb) continue;
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      const isFailed = this._failedLinks.has(link.id);
      line.setAttribute('x1', String(pa.x));
      line.setAttribute('y1', String(pa.y));
      line.setAttribute('x2', String(pb.x));
      line.setAttribute('y2', String(pb.y));
      line.setAttribute('stroke', isFailed ? '#f85149' : this._linkColor(link.id));
      line.setAttribute('stroke-width', isFailed ? '2' : '3');
      if (isFailed) line.setAttribute('stroke-dasharray', '8,5');
      line.dataset.linkId = String(link.id);
      line.className.baseVal = 'topo-link-line';
      linksG.appendChild(line);

      // Link label (delay)
      const mx = (pa.x + pb.x) / 2;
      const my = (pa.y + pb.y) / 2;
      const lbl = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      lbl.setAttribute('x', String(mx));
      lbl.setAttribute('y', String(my - 7));
      lbl.setAttribute('text-anchor', 'middle');
      lbl.setAttribute('fill', '#8b949e');
      lbl.setAttribute('font-size', '11');
      const stats = this._linkStats.get(link.id);
      lbl.textContent = stats ? `${Math.round(stats.ewmaRtt)}ms RTT` : `${link.delayMs}ms`;
      linksG.appendChild(lbl);
    }
    svg.appendChild(linksG);

    // Nodes layer
    const nodesG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    nodesG.className.baseVal = 'topo-nodes';
    const latestNodes = this._sim.nodesSnapshot();
    for (const node of latestNodes) {
      const p = this._positions.get(node.id);
      if (!p) continue;
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.className.baseVal = `topo-node topo-node-${node.kind}`;
      g.setAttribute('transform', `translate(${p.x},${p.y})`);
      g.dataset.nodeId = String(node.id);
      g.style.cursor = 'pointer';

      // Node circle
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('r', String(NODE_R));
      circle.setAttribute('fill', nodeColor(node.kind));
      circle.setAttribute('stroke', this._selectedNode === node.id ? '#ffffff' : 'transparent');
      circle.setAttribute('stroke-width', '2');
      g.appendChild(circle);

      // Icon text
      const icon = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      icon.setAttribute('text-anchor', 'middle');
      icon.setAttribute('dominant-baseline', 'middle');
      icon.setAttribute('fill', '#0d1117');
      icon.setAttribute('font-size', '18');
      icon.setAttribute('font-weight', 'bold');
      icon.textContent = nodeIcon(node.kind);
      g.appendChild(icon);

      // Name label below
      const lbl = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      lbl.setAttribute('text-anchor', 'middle');
      lbl.setAttribute('y', String(NODE_R + 14));
      lbl.setAttribute('fill', '#e6edf3');
      lbl.setAttribute('font-size', '12');
      lbl.textContent = node.name;
      g.appendChild(lbl);

      // PIT/CS badge
      if (node.pitCount > 0 || node.csCount > 0) {
        const badge = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        badge.setAttribute('text-anchor', 'middle');
        badge.setAttribute('y', String(NODE_R + 27));
        badge.setAttribute('fill', '#8b949e');
        badge.setAttribute('font-size', '10');
        badge.textContent = `PIT:${node.pitCount} CS:${node.csCount}`;
        g.appendChild(badge);
      }

      g.addEventListener('click', () => this._selectNode(node.id));
      nodesG.appendChild(g);
    }
    svg.appendChild(nodesG);

    // Bubble layer (empty initially — bubbles appended during animation)
    const bubblesG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    bubblesG.className.baseVal = 'topo-bubbles';
    svg.appendChild(bubblesG);

    this._canvasWrap.appendChild(svg);
  }

  /** RTT-based link color: green (fast) → yellow (medium) → red (slow). */
  _linkColor(linkId) {
    const stats = this._linkStats.get(linkId);
    if (!stats || stats.count < 3) return '#30363d';
    const rtt = stats.ewmaRtt;
    if (rtt < 30) return '#3fb950';
    if (rtt < 80) return '#d29922';
    return '#f85149';
  }

  // ── Sending interests + animation ───────────────────────────────────────────

  _sendInterest() {
    if (this._running || !this._scenario) return;
    const interestName = this._scenario.interestName;
    const fromNode = this._scenario.consumerNode;

    this._running = true;
    this._packetCount++;

    const trace = this._sim.sendInterest(fromNode, interestName);
    this._logTrace(trace);

    // Update link stats for heatmap
    for (const ev of trace.events) {
      if (ev.kind === 'interest' || ev.kind === 'data') {
        const ls = this._linkStats.get(ev.linkId) ?? { ewmaRtt: 0, count: 0 };
        const alpha = 0.2;
        const rtt = trace.totalRttMs;
        ls.ewmaRtt = ls.count === 0 ? rtt : (1 - alpha) * ls.ewmaRtt + alpha * rtt;
        ls.count++;
        this._linkStats.set(ev.linkId, ls);
      }
    }

    if (this._speed === 0) {
      // Instant: just re-render final state
      this._renderTopology();
      this._running = false;
      if (this._selectedNode !== null) this._updateStatsPanel(this._selectedNode);
    } else {
      this._animateTrace(trace, () => {
        this._renderTopology();
        this._running = false;
        if (this._selectedNode !== null) this._updateStatsPanel(this._selectedNode);
      });
    }
  }

  /**
   * Animate the trace events as bubbles sliding along link lines.
   * @param {TopoTrace} trace @param {() => void} done
   */
  _animateTrace(trace, done) {
    if (!this._svg) { done(); return; }
    const bubblesG = this._svg.querySelector('.topo-bubbles');
    if (!bubblesG) { done(); return; }

    const speedFactor = this._speed;
    // Base delay per ms of simulated time (scaled to real ms for animation)
    const msPerSimMs = 12 / speedFactor; // 12 real-ms per simulated-ms at 1×

    let maxEnd = 0;

    for (const ev of trace.events) {
      if (ev.kind !== 'interest' && ev.kind !== 'data' && ev.kind !== 'nack') continue;

      const pa = this._positions.get(ev.fromNode);
      const pb = this._positions.get(ev.toNode);
      if (!pa || !pb) continue;

      const link = this._scenario?.links.find(l => l.id === ev.linkId);
      const travelMs = (link?.delayMs ?? 10) * msPerSimMs;
      const startRealMs = ev.timeMs * msPerSimMs;
      const endRealMs = startRealMs + travelMs;
      if (endRealMs > maxEnd) maxEnd = endRealMs;

      const color = ev.kind === 'interest' ? '#58a6ff' : ev.kind === 'data' ? '#3fb950' : '#f85149';
      const label = ev.kind === 'interest' ? 'I' : ev.kind === 'data' ? 'D' : 'N';

      setTimeout(() => {
        if (!bubblesG) return;
        const bubble = this._createBubble(pa.x, pa.y, pb.x, pb.y, color, label, travelMs);
        bubblesG.appendChild(bubble);
        setTimeout(() => bubble.remove(), travelMs + 100);
      }, startRealMs);
    }

    // CS-hit event: flash the node
    for (const ev of trace.events) {
      if (ev.kind !== 'cs-hit') continue;
      const realMs = ev.timeMs * msPerSimMs;
      setTimeout(() => this._flashNode(ev.fromNode, '#d2a8ff', 600 / speedFactor), realMs);
    }

    // PIT-aggregate: flash the aggregating node
    for (const ev of trace.events) {
      if (ev.kind !== 'pit-aggregate') continue;
      const realMs = ev.timeMs * msPerSimMs;
      setTimeout(() => this._flashNode(ev.fromNode, '#d29922', 600 / speedFactor), realMs);
    }

    setTimeout(done, maxEnd + 200);
  }

  /**
   * Create an SVG group that animates a bubble from (x1,y1) to (x2,y2).
   * @param {number} x1 @param {number} y1 @param {number} x2 @param {number} y2
   * @param {string} color @param {string} label @param {number} durationMs
   * @returns {SVGGElement}
   */
  _createBubble(x1, y1, x2, y2, color, label, durationMs) {
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('r', '12');
    circle.setAttribute('fill', color);
    circle.setAttribute('opacity', '0.9');
    g.appendChild(circle);

    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('text-anchor', 'middle');
    text.setAttribute('dominant-baseline', 'middle');
    text.setAttribute('fill', '#0d1117');
    text.setAttribute('font-size', '11');
    text.setAttribute('font-weight', 'bold');
    text.textContent = label;
    g.appendChild(text);

    // Web Animations API: animate transform
    const kf = [
      { transform: `translate(${x1}px, ${y1}px)` },
      { transform: `translate(${x2}px, ${y2}px)` },
    ];
    g.animate(kf, { duration: durationMs, easing: 'linear', fill: 'forwards' });

    return /** @type {SVGGElement} */ (g);
  }

  /**
   * Briefly flash a node to indicate an event (CS hit, aggregation).
   * @param {number} nodeId @param {string} color @param {number} durationMs
   */
  _flashNode(nodeId, color, durationMs) {
    if (!this._svg) return;
    const g = this._svg.querySelector(`[data-node-id="${nodeId}"]`);
    if (!g) return;
    const circle = g.querySelector('circle');
    if (!circle) return;
    const orig = circle.getAttribute('fill') ?? '';
    circle.setAttribute('fill', color);
    setTimeout(() => circle.setAttribute('fill', orig), durationMs);
  }

  // ── Node stats panel ────────────────────────────────────────────────────────

  /** @param {number} nodeId */
  _selectNode(nodeId) {
    this._selectedNode = nodeId;
    this._renderTopology(); // re-render to show selection ring
    this._updateStatsPanel(nodeId);
  }

  /** @param {number} nodeId */
  _updateStatsPanel(nodeId) {
    if (!this._statsPanel) return;
    const node = this._sim.nodes.get(nodeId);
    if (!node) return;

    const fib = node.fib.routes;
    const pit = node.pit.snapshot();
    const cs = node.cs.snapshot();

    const fibRows = fib.length ? fib.map(r =>
      `<tr><td>${r.prefix}</td><td>face ${r.faceId}</td><td>${r.cost}</td></tr>`
    ).join('') : '<tr><td colspan="3" class="topo-empty">empty</td></tr>';

    const pitRows = pit.length ? pit.map(r =>
      `<tr><td>${r.name}</td><td>face ${r.inFace}</td></tr>`
    ).join('') : '<tr><td colspan="2" class="topo-empty">empty</td></tr>';

    const csRows = cs.length ? cs.map(r =>
      `<tr><td>${r.name}</td><td>${r.freshnessMs}ms</td></tr>`
    ).join('') : '<tr><td colspan="2" class="topo-empty">empty</td></tr>';

    const kindLabel = node.kind.charAt(0).toUpperCase() + node.kind.slice(1);

    this._statsPanel.innerHTML = `
      <h3 class="topo-stats-title">
        <span class="topo-node-badge topo-node-badge-${node.kind}">${kindLabel}</span>
        ${node.name}
      </h3>
      ${node.servedPrefixes.length ? `<div class="topo-stats-prefix">Serves: ${node.servedPrefixes.join(', ')}</div>` : ''}

      <div class="topo-stats-section">
        <h4>FIB (${fib.length} entries)</h4>
        <table class="topo-table"><thead><tr><th>Prefix</th><th>Face</th><th>Cost</th></tr></thead>
        <tbody>${fibRows}</tbody></table>
      </div>

      <div class="topo-stats-section">
        <h4>PIT (${pit.length} pending)</h4>
        <table class="topo-table"><thead><tr><th>Name</th><th>In-face</th></tr></thead>
        <tbody>${pitRows}</tbody></table>
      </div>

      <div class="topo-stats-section">
        <h4>CS (${cs.length} / ${node.cs.capacity})</h4>
        <table class="topo-table"><thead><tr><th>Name</th><th>Freshness</th></tr></thead>
        <tbody>${csRows}</tbody></table>
      </div>
    `;
  }

  // ── Discovery walkthrough ────────────────────────────────────────────────────

  _startDiscovery() {
    this._sim.resetAll();
    this._linkStats.clear();
    this._failedLinks.clear();
    this._packetCount = 0;
    this._selectedNode = null;
    this._discoveryMode = true;
    this._discoveryPhase = 0;

    // Build 4-node topology: Consumer ─ Router-A ─ Router-B ─ Producer
    //                                         └─────────────────────┘  (backup link)
    const c  = this._sim.addConsumer('Consumer');
    const r1 = this._sim.addRouter('Router-A');
    const r2 = this._sim.addRouter('Router-B');
    const p  = this._sim.addProducer('Producer', '/ndn/edu/demo');
    const l1 = this._sim.addLink(c,  r1, 10);   // Consumer ─ Router-A
    const l2 = this._sim.addLink(r1, r2, 8);    // Router-A ─ Router-B  (primary)
    const l3 = this._sim.addLink(r2, p,  8);    // Router-B ─ Producer
    const l4 = this._sim.addLink(r1, p,  30);   // Router-A ─ Producer  (backup)
    this._discNodeIds = { consumer: c, r1, r2, producer: p };
    this._discLinkIds = { l1, l2, l3, l4 };

    // Manual positions for a clean topology layout (override BFS)
    this._positions = new Map([
      [c,  { x: 70,  y: 170 }],
      [r1, { x: 240, y: 170 }],
      [r2, { x: 430, y: 80  }],
      [p,  { x: 610, y: 170 }],
    ]);

    // Snapshot for _renderTopology
    this._scenario = {
      name: 'discovery', description: 'NDN Discovery Bootstrap',
      consumerNode: c, interestName: '/ndn/edu/demo/file',
      nodes: this._sim.nodesSnapshot(), links: this._sim.linksSnapshot(),
    };

    if (this._descBar) this._descBar.textContent = 'NDN Discovery Bootstrap — step through each phase below.';

    // Disable interactive controls during walkthrough
    if (this._sendBtn) this._sendBtn.disabled = true;
    if (this._resetStateBtn) this._resetStateBtn.disabled = true;

    this._clearLog();
    this._renderTopology();
    this._showDiscoveryPhase(0);
  }

  _stopDiscovery() {
    this._discoveryMode = false;
    this._failedLinks.clear();
    if (this._sendBtn) this._sendBtn.disabled = false;
    if (this._resetStateBtn) this._resetStateBtn.disabled = false;
    if (this._scenarioSelect) this._scenarioSelect.value = 'linear';
    this._loadScenario('linear');
  }

  /** @param {number} i */
  _showDiscoveryPhase(i) {
    const phase = DISCOVERY_PHASES[i];
    if (!phase) return;
    this._discoveryPhase = i;

    // Apply synchronous state mutations for this phase before animating
    const ids = this._discNodeIds;
    const lids = this._discLinkIds;
    if (ids && lids) {
      if (i === 2) {
        // FIB Wave: install all routes
        this._sim.addFibRoute(ids.consumer, '/ndn', lids.l1, 0);
        this._sim.addFibRoute(ids.r1, '/ndn', lids.l2, 1);   // via Router-B (primary)
        this._sim.addFibRoute(ids.r1, '/ndn', lids.l4, 2);   // direct to Producer (backup)
        this._sim.addFibRoute(ids.r2, '/ndn', lids.l3, 0);
        this._scenario && (this._scenario.nodes = this._sim.nodesSnapshot());
      }
      if (i === 5) {
        // Link failure: mark L2 failed, remove routes via L2 from Router-A
        this._failedLinks.add(lids.l2);
        const r1node = this._sim.nodes.get(ids.r1);
        const l2snap = this._sim.links.get(lids.l2);
        if (r1node && l2snap) {
          const failFace = l2snap.nodeA === ids.r1 ? l2snap.faceA : l2snap.faceB;
          r1node.fib.routes = r1node.fib.routes.filter(r => r.faceId !== failFace);
        }
        this._renderTopology(); // redraw link as dashed red
      }
    }

    // Render the narrative panel
    if (this._statsPanel) {
      this._statsPanel.innerHTML = `
        <div class="topo-disc-panel">
          <h3 class="topo-disc-title">${phase.title}</h3>
          <p class="topo-disc-body">${phase.body}</p>
          <div class="topo-disc-nav">
            <button class="topo-btn topo-disc-prev" ${i === 0 ? 'disabled' : ''}>&#8592; Prev</button>
            <button class="topo-btn topo-disc-replay">&#8635; Replay</button>
            <button class="topo-btn topo-disc-next" ${i === DISCOVERY_PHASES.length - 1 ? 'disabled' : ''}>Next &#8594;</button>
            <button class="topo-btn topo-disc-stop">&#10005; Exit</button>
          </div>
        </div>`;

      this._statsPanel.querySelector('.topo-disc-prev')?.addEventListener('click', () =>
        this._showDiscoveryPhase(this._discoveryPhase - 1));
      this._statsPanel.querySelector('.topo-disc-next')?.addEventListener('click', () =>
        this._showDiscoveryPhase(this._discoveryPhase + 1));
      this._statsPanel.querySelector('.topo-disc-replay')?.addEventListener('click', () =>
        this._playDiscoveryAnim(i));
      this._statsPanel.querySelector('.topo-disc-stop')?.addEventListener('click', () =>
        this._stopDiscovery());
    }

    this._playDiscoveryAnim(i);
  }

  /** Run the animation for discovery phase i (non-blocking). @param {number} i */
  _playDiscoveryAnim(i) {
    const ids = this._discNodeIds;
    const lids = this._discLinkIds;
    if (!ids || !lids) return;
    const sf = Math.max(0.1, this._speed === 0 ? 4 : this._speed);

    switch (i) {
      case 0: { // Hello gossip on all 4 links, both directions
        const links = [lids.l1, lids.l2, lids.l3, lids.l4];
        const pairs = [
          [ids.consumer, ids.r1, lids.l1], [ids.r1, ids.consumer, lids.l1],
          [ids.r1, ids.r2, lids.l2],       [ids.r2, ids.r1, lids.l2],
          [ids.r2, ids.producer, lids.l3], [ids.producer, ids.r2, lids.l3],
          [ids.r1, ids.producer, lids.l4], [ids.producer, ids.r1, lids.l4],
        ];
        /** @type {Array<{fromNode:number,toNode:number,linkId:number,color:string,label:string,startMs:number,durationMs:number}>} */
        const specs = pairs.map(([from, to, lid], idx) => ({
          fromNode: /** @type {number} */ (from),
          toNode: /** @type {number} */ (to),
          linkId: /** @type {number} */ (lid),
          color: '#8b949e', label: 'H',
          startMs: idx * 80, durationMs: 300,
        }));
        this._animateDiscBubbles(specs);
        this._appendLog('Phase 1: Hello messages exchanged on all 4 links.');
        break;
      }
      case 1: { // Flash Producer
        this._flashNode(ids.producer, '#d2a8ff', 1000 / sf);
        this._appendLog('Phase 2: Producer registered /ndn/edu/demo on AppFace.');
        break;
      }
      case 2: { // FIB wave: P→R2, then R2→R1, then P→R1 (backup)
        const specs = [
          { fromNode: ids.producer, toNode: ids.r2,       linkId: lids.l3, color: '#3fb950', label: 'F', startMs: 0,   durationMs: 350 },
          { fromNode: ids.r2,       toNode: ids.r1,       linkId: lids.l2, color: '#3fb950', label: 'F', startMs: 400, durationMs: 350 },
          { fromNode: ids.producer, toNode: ids.r1,       linkId: lids.l4, color: '#3fb950', label: 'F', startMs: 400, durationMs: 500 },
          { fromNode: ids.r1,       toNode: ids.consumer, linkId: lids.l1, color: '#3fb950', label: 'F', startMs: 820, durationMs: 300 },
        ];
        this._animateDiscBubbles(specs, () => {
          this._scenario && (this._scenario.nodes = this._sim.nodesSnapshot());
          this._renderTopology();
        });
        this._appendLog('Phase 3: FIB routes propagated from Producer outward.');
        break;
      }
      case 3: { // First Interest — run real sim
        const trace = this._sim.sendInterest(ids.consumer, '/ndn/edu/demo/file');
        this._logTrace(trace);
        this._animateTrace(trace, () => {
          this._scenario && (this._scenario.nodes = this._sim.nodesSnapshot());
          this._renderTopology();
        });
        this._appendLog(`Phase 4: Interest routed primary path (${Math.round(trace.totalRttMs)}ms RTT).`);
        break;
      }
      case 4: { // Cache hit — run sim again
        const trace = this._sim.sendInterest(ids.consumer, '/ndn/edu/demo/file');
        this._logTrace(trace);
        this._animateTrace(trace, () => {
          this._scenario && (this._scenario.nodes = this._sim.nodesSnapshot());
          this._renderTopology();
        });
        this._appendLog(`Phase 5: Cache hit at Router-B (${Math.round(trace.totalRttMs)}ms RTT).`);
        break;
      }
      case 5: { // Link failure — flash both endpoints red
        setTimeout(() => this._flashNode(ids.r1, '#f85149', 800 / sf), 0);
        setTimeout(() => this._flashNode(ids.r2, '#f85149', 800 / sf), 0);
        this._appendLog('Phase 6: Link Router-A ↔ Router-B failed (Hello timeout).');
        break;
      }
      case 6: { // Withdrawal — W bubbles backward
        const specs = [
          { fromNode: ids.r2,       toNode: ids.r1,       linkId: lids.l2, color: '#f85149', label: 'W', startMs: 0,   durationMs: 300 },
          { fromNode: ids.r1,       toNode: ids.consumer, linkId: lids.l1, color: '#f85149', label: 'W', startMs: 350, durationMs: 250 },
        ];
        this._animateDiscBubbles(specs);
        this._appendLog('Phase 7: Route withdrawal propagated toward Consumer.');
        break;
      }
      case 7: { // Fallback — sim routes via backup link now
        const trace = this._sim.sendInterest(ids.consumer, '/ndn/edu/demo/file2');
        this._logTrace(trace);
        this._animateTrace(trace, () => {
          this._scenario && (this._scenario.nodes = this._sim.nodesSnapshot());
          this._renderTopology();
        });
        this._appendLog(`Phase 8: Fallback path active via backup link (${Math.round(trace.totalRttMs)}ms RTT).`);
        break;
      }
    }
  }

  /**
   * Animate a set of bubble specs on the SVG canvas (non-blocking).
   * @param {Array<{fromNode:number,toNode:number,linkId:number,color:string,label:string,startMs:number,durationMs:number}>} specs
   * @param {()=>void} [onDone]
   */
  _animateDiscBubbles(specs, onDone) {
    if (!this._svg) { onDone?.(); return; }
    const bubblesG = this._svg.querySelector('.topo-bubbles');
    if (!bubblesG) { onDone?.(); return; }

    const sf = Math.max(0.1, this._speed === 0 ? 4 : this._speed);
    let maxEnd = 0;

    for (const spec of specs) {
      const pa = this._positions.get(spec.fromNode);
      const pb = this._positions.get(spec.toNode);
      if (!pa || !pb) continue;
      const realStart = spec.startMs / sf;
      const realDur   = spec.durationMs / sf;
      const realEnd   = realStart + realDur;
      if (realEnd > maxEnd) maxEnd = realEnd;

      setTimeout(() => {
        const g = this._svg?.querySelector('.topo-bubbles');
        if (!g) return;
        const bubble = this._createBubble(pa.x, pa.y, pb.x, pb.y, spec.color, spec.label, realDur);
        g.appendChild(bubble);
        setTimeout(() => bubble.remove(), realDur + 100);
      }, realStart);
    }

    if (onDone) setTimeout(onDone, maxEnd + 150);
  }

  // ── Event log ───────────────────────────────────────────────────────────────

  /** @param {string} msg */
  _appendLog(msg) {
    if (!this._log) return;
    const line = document.createElement('div');
    line.className = 'topo-log-line';
    line.textContent = msg;
    this._log.appendChild(line);
    this._log.scrollTop = this._log.scrollHeight;
  }

  _clearLog() {
    if (this._log) this._log.innerHTML = '';
  }

  /** @param {TopoTrace} trace */
  _logTrace(trace) {
    const result = trace.satisfied ? '✓ satisfied' : '✗ unsatisfied';
    this._appendLog(`#${this._packetCount} ${trace.interestName}  → ${result}  (${trace.hops} hops, ${Math.round(trace.totalRttMs)}ms RTT)`);
    for (const ev of trace.events) {
      const detail = ev.kind === 'cs-hit' ? ' [CS HIT]'
                   : ev.kind === 'pit-aggregate' ? ' [PIT aggregate]'
                   : '';
      const from = this._sim.nodes.get(ev.fromNode)?.name ?? ev.fromNode;
      const to = this._sim.nodes.get(ev.toNode)?.name ?? ev.toNode;
      this._appendLog(`  ${ev.kind.padEnd(14)} ${from} → ${to}${detail}`);
    }
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** @param {'router'|'consumer'|'producer'} kind @returns {string} */
function nodeColor(kind) {
  return kind === 'router' ? '#58a6ff'
       : kind === 'consumer' ? '#3fb950'
       : '#f0883e';
}

/** @param {'router'|'consumer'|'producer'} kind @returns {string} */
function nodeIcon(kind) {
  return kind === 'router' ? 'R' : kind === 'consumer' ? 'C' : 'P';
}
