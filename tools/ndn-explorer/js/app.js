import { LayerMap } from './views/layer-map.js';
import { initWasm } from './wasm-types.js';
import { CrateDetail } from './views/crate-detail.js';
import { TypeDetail } from './views/type-detail.js';
import { DepGraph } from './views/dep-graph.js';
import { PipelineTrace } from './views/pipeline-trace.js';
import { PacketExplorer } from './views/packet-explorer.js';
import { TopologyView } from './views/topology.js';
import { SecurityAnim } from './views/security-anim.js';
import { Search } from './views/search.js';
import { Tour } from './views/tour.js';

// Hex colors for each layer — used in canvas, inline styles, and CSS backgrounds.
export const LAYER_COLORS = {
  foundation:  '#79c0ff',
  faces:       '#3fb950',
  pipeline:    '#d2a8ff',
  engine:      '#58a6ff',
  binaries:    '#f0883e',
  simulation:  '#ff7b72',
  research:    '#ffa657',
  embedded:    '#7ee787',
  bindings:    '#d2a8ff',
  examples:    '#8b949e',
};

class App {
  constructor() {
    this.data = null;
    this.currentView = null;
    this.views = {};
    this.history = [];
  }

  async init() {
    const resp = await fetch('data/crates.json');
    this.data = await resp.json();

    const containers = {};
    document.querySelectorAll('.view').forEach(el => {
      containers[el.id] = el;
    });

    this.views = {
      'layer-map':      new LayerMap(containers['layer-map'], this),
      'crate-detail':   new CrateDetail(containers['crate-detail'], this),
      'type-detail':    new TypeDetail(containers['type-detail'], this),
      'dep-graph':      new DepGraph(containers['dep-graph'], this),
      'pipeline-trace':  new PipelineTrace(containers['pipeline-trace'], this),
      'packet-explorer': new PacketExplorer(containers['packet-explorer'], this),
      'topology':        new TopologyView(containers['topology'], this),
      'security':        new SecurityAnim(containers['security'], this),
      'search':          new Search(containers['search'], this),
      'tour':           new Tour(containers['tour'], this),
    };

    this.views['layer-map'].render();
    this.views['pipeline-trace'].render();
    this.views['tour'].render();

    // Nav buttons
    document.querySelectorAll('.nav-btn').forEach(btn => {
      btn.addEventListener('click', () => this.navigate(btn.dataset.view));
    });

    // Logo → home
    document.querySelector('.logo').addEventListener('click', () => this.navigate('layer-map'));

    // Search input
    const searchBox = document.getElementById('search-box');
    searchBox.addEventListener('input', () => {
      const q = searchBox.value.trim();
      if (q.length === 0) {
        this.navigate('layer-map');
      } else {
        this.views['search'].search(q);
        this.show('search');
      }
    });
    searchBox.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        searchBox.value = '';
        this.navigate('layer-map');
        searchBox.blur();
      }
    });

    // Keyboard shortcut: / to focus search
    document.addEventListener('keydown', (e) => {
      if (e.key === '/' && document.activeElement !== searchBox) {
        e.preventDefault();
        searchBox.focus();
      }
    });

    this.navigate('layer-map');

    // Attempt WASM load in the background — views fall back to pure-JS if absent.
    this._initWasm();
  }

  async _initWasm() {
    const badge = /** @type {HTMLElement|null} */ (document.getElementById('wasm-badge'));
    const loaded = await initWasm();
    if (badge) {
      badge.textContent = loaded ? 'WASM ✓' : 'WASM —';
      badge.classList.toggle('wasm-badge-on', loaded);
      badge.title = loaded
        ? 'Rust WASM simulation loaded — real NDN packet processing active'
        : 'WASM not built — using pure-JS simulation fallback.\n' +
          'Run: wasm-pack build crates/ndn-wasm --target web --out-dir tools/ndn-explorer/wasm';
    }
  }

  navigate(viewId, params) {
    if (this.currentView && this.currentView !== viewId) {
      this.history.push({ view: this.currentView, params: this._lastParams });
    }
    this._lastParams = params;
    this.show(viewId, params);
  }

  show(viewId, params) {
    this.currentView = viewId;

    document.querySelectorAll('.view').forEach(el => {
      el.classList.toggle('active', el.id === viewId);
    });

    document.querySelectorAll('.nav-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.view === viewId);
    });

    const view = this.views[viewId];
    if (view && view.onShow) view.onShow(params);
  }

  back() {
    if (this.history.length > 0) {
      const prev = this.history.pop();
      this.show(prev.view, prev.params);
    } else {
      this.show('layer-map');
    }
  }

  showCrate(name) {
    this.navigate('crate-detail', { name });
  }

  showType(typeName, crateName) {
    this.navigate('type-detail', { typeName, crateName });
  }

  getCrate(name) {
    return this.data.crates.find(c => c.name === name);
  }

  getLayer(id) {
    return this.data.layers.find(l => l.id === id);
  }

  getReverseDeps(name) {
    return this.data.crates.filter(c => c.workspace_deps.includes(name));
  }
}

const app = new App();
app.init();

// ── Theme toggle ──────────────────────────────────────────────────────────────

(function initTheme() {
  const STORAGE_KEY = 'ndn-explorer-theme';
  const btn = /** @type {HTMLButtonElement|null} */ (document.getElementById('theme-toggle'));
  const root = document.documentElement;

  const saved = localStorage.getItem(STORAGE_KEY) ?? 'dark';
  root.setAttribute('data-theme', saved);
  if (btn) btn.textContent = saved === 'light' ? '☾' : '☀';

  btn?.addEventListener('click', () => {
    const next = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    root.setAttribute('data-theme', next);
    localStorage.setItem(STORAGE_KEY, next);
    btn.textContent = next === 'light' ? '☾' : '☀';
  });
})();
