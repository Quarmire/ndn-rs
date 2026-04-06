export class DiscoveryView {
  constructor(container, app) {
    this.container = container;
    this.app = app;
  }

  render() {
    this.container.innerHTML = `
      <h1 style="margin-bottom:1rem">Discovery</h1>
      <div class="panel-grid">
        <div class="panel">
          <div class="panel-title">Neighbors</div>
          <div class="btn-row">
            <button class="btn" id="neighbors-refresh">Refresh</button>
          </div>
          <div id="neighbors-list" class="loading">Loading...</div>
        </div>
        <div class="panel">
          <div class="panel-title">Services</div>
          <div class="btn-row">
            <button class="btn" id="services-refresh">Refresh</button>
            <button class="btn" id="services-browse">Browse</button>
          </div>
          <div id="services-list" class="loading">Loading...</div>
        </div>
      </div>
      <div class="panel" style="margin-top:0.75rem">
        <div class="panel-title">Announce Service</div>
        <div class="form-row">
          <span class="form-label">Prefix</span>
          <input class="form-input" id="svc-prefix" placeholder="/ndn/my-service" style="flex:1">
          <button class="btn btn-primary" id="svc-announce-btn">Announce</button>
        </div>
      </div>`;

    this.container.querySelector('#neighbors-refresh').addEventListener('click', () => this._refreshNeighbors());
    this.container.querySelector('#services-refresh').addEventListener('click', () => this._refreshServices());
    this.container.querySelector('#services-browse').addEventListener('click', () => this._browse());
    this.container.querySelector('#svc-announce-btn').addEventListener('click', () => this._announce());
  }

  async refresh() {
    await Promise.all([this._refreshNeighbors(), this._refreshServices()]);
  }

  async _refreshNeighbors() {
    const el = this.container.querySelector('#neighbors-list');
    try {
      const resp = await this.app.client.listNeighbors();
      const text = resp.statusText || resp.raw || '';
      const lines = text.split('\n').filter(l => l.trim().length > 0);

      if (lines.length === 0 || !text.trim()) {
        el.innerHTML = '<span style="color:var(--text2)">No neighbors discovered</span>';
        return;
      }

      // Parse neighbor entries: "neighbor faceid=N addr=X state=Y rtt=Z"
      const neighbors = [];
      for (const line of lines) {
        const m = {};
        line.replace(/(\w+)=(\S+)/g, (_, k, v) => { m[k] = v; });
        if (m.faceid || m.addr || m.state) {
          neighbors.push(m);
        }
      }

      if (neighbors.length > 0) {
        el.innerHTML = `<div class="neighbor-grid">${neighbors.map(n => {
          const stateClass = n.state === 'Established' ? 'stat-green'
            : n.state === 'Stale' ? 'stat-orange' : '';
          return `
            <div class="stat-card ${stateClass}">
              <div class="stat-value" style="font-size:0.9rem">${esc(n.addr || n.faceid || '?')}</div>
              <div class="stat-label">${esc(n.state || 'unknown')}</div>
              ${n.rtt ? `<div style="font-size:0.72rem;color:var(--text2)">RTT: ${n.rtt}</div>` : ''}
              ${n.faceid ? `<div style="font-size:0.72rem;color:var(--text2)">Face: ${n.faceid}</div>` : ''}
            </div>`;
        }).join('')}</div>`;
      } else {
        el.innerHTML = `<pre style="font-size:0.82rem;color:var(--text2);white-space:pre-wrap">${esc(text)}</pre>`;
      }
    } catch (e) {
      el.innerHTML = `<span style="color:var(--red)">${esc(e.message)}</span>`;
    }
  }

  async _refreshServices() {
    const el = this.container.querySelector('#services-list');
    try {
      const resp = await this.app.client.listServices();
      const text = resp.statusText || resp.raw || '';
      const lines = text.split('\n').filter(l => l.trim().length > 0);

      if (lines.length === 0 || !text.trim()) {
        el.innerHTML = '<span style="color:var(--text2)">No services registered</span>';
        return;
      }

      // Parse service entries: "service prefix=/x producer=Y [ttl=Z]"
      const services = [];
      for (const line of lines) {
        const m = {};
        line.replace(/(\w+)=(\S+)/g, (_, k, v) => { m[k] = v; });
        if (m.prefix || m.name) {
          services.push(m);
        }
      }

      if (services.length > 0) {
        el.innerHTML = `
          <table class="data-table">
            <tr><th>Prefix</th><th>Producer</th><th>Face</th></tr>
            ${services.map(s => `
              <tr>
                <td class="name">${esc(s.prefix || s.name || '--')}</td>
                <td class="uri">${esc(s.producer || s.origin || '--')}</td>
                <td class="mono">${s.faceid || s.face || '--'}</td>
              </tr>`).join('')}
          </table>`;
      } else {
        el.innerHTML = `<pre style="font-size:0.82rem;color:var(--text2);white-space:pre-wrap">${esc(text)}</pre>`;
      }
    } catch (e) {
      el.innerHTML = `<span style="color:var(--red)">${esc(e.message)}</span>`;
    }
  }

  async _browse() {
    const el = this.container.querySelector('#services-list');
    try {
      const resp = await this.app.client.browseServices();
      const text = resp.statusText || resp.raw || '';
      if (text.trim()) {
        el.innerHTML = `<pre style="font-size:0.82rem;color:var(--text2);white-space:pre-wrap">${esc(text)}</pre>`;
      } else {
        el.innerHTML = '<span style="color:var(--text2)">No services found</span>';
      }
      this.app.toast('Service browse complete');
    } catch (e) {
      this.app.toast(e.message, 'error');
    }
  }

  async _announce() {
    const prefix = this.container.querySelector('#svc-prefix').value.trim();
    if (!prefix) return;
    try {
      await this.app.client.command('service', 'announce', { name: prefix });
      this.app.toast(`Service announced: ${prefix}`);
      this.container.querySelector('#svc-prefix').value = '';
      this._refreshServices();
    } catch (e) {
      this.app.toast(e.message, 'error');
    }
  }
}

function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
