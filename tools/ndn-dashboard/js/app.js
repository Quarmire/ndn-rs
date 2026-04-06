import { NdnClient } from './ndn/client.js';
import { OverviewView } from './views/overview.js';
import { FacesView } from './views/faces.js';
import { RoutesView } from './views/routes.js';
import { CsView } from './views/cs.js';
import { StrategyView } from './views/strategy.js';
import { DiscoveryView } from './views/discovery.js';

class Dashboard {
  constructor() {
    this.client = new NdnClient();
    this.views = {};
    this.currentView = null;
    this.pollTimer = null;
  }

  init() {
    // Get DOM containers
    const containers = {};
    document.querySelectorAll('.view').forEach(el => containers[el.id] = el);

    // Instantiate views
    this.views = {
      overview:  new OverviewView(containers.overview, this),
      faces:     new FacesView(containers.faces, this),
      routes:    new RoutesView(containers.routes, this),
      cs:        new CsView(containers.cs, this),
      strategy:  new StrategyView(containers.strategy, this),
      discovery: new DiscoveryView(containers.discovery, this),
    };

    // Nav buttons
    document.querySelectorAll('.nav-btn').forEach(btn => {
      btn.addEventListener('click', () => this.navigate(btn.dataset.view));
    });
    document.querySelector('.logo').addEventListener('click', () => this.navigate('overview'));

    // Connection status
    const connDot = document.querySelector('.conn-dot');
    const connLabel = document.getElementById('conn-label');
    this.client.onStatusChange = (connected) => {
      connDot.classList.toggle('connected', connected);
      connLabel.textContent = connected ? 'Connected' : 'Disconnected';
      if (connected) this._refresh();
    };

    // URL input
    const urlInput = document.getElementById('ws-url');
    const connectBtn = document.getElementById('connect-btn');
    connectBtn.addEventListener('click', () => {
      this.client.disconnect();
      this.client.connect(urlInput.value);
    });

    // Connect on Enter
    urlInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') connectBtn.click();
    });

    // Start connection
    this.client.connect(urlInput.value);

    // Auto-refresh every 3s
    this.pollTimer = setInterval(() => {
      if (this.client.connected && this.currentView) {
        const view = this.views[this.currentView];
        if (view && view.refresh) view.refresh();
      }
    }, 3000);

    this.navigate('overview');
  }

  navigate(viewId) {
    this.currentView = viewId;
    document.querySelectorAll('.view').forEach(el => {
      el.classList.toggle('active', el.id === viewId);
    });
    document.querySelectorAll('.nav-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.view === viewId);
    });
    const view = this.views[viewId];
    if (view) {
      view.render();
      if (this.client.connected && view.refresh) view.refresh();
    }
  }

  _refresh() {
    const view = this.views[this.currentView];
    if (view && view.refresh) view.refresh();
  }

  toast(message, type = 'success') {
    const container = document.querySelector('.toast-container');
    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.textContent = message;
    container.appendChild(el);
    setTimeout(() => el.remove(), 4000);
  }
}

const dashboard = new Dashboard();
dashboard.init();
