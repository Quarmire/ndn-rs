export class CsView {
  constructor(container, app) {
    this.container = container;
    this.app = app;
  }

  render() {
    this.container.innerHTML = `
      <h1 style="margin-bottom:1rem">Content Store</h1>
      <div class="panel-grid">
        <div class="panel">
          <div class="panel-title">Statistics</div>
          <div id="cs-stats" class="loading">Loading...</div>
        </div>
        <div class="panel">
          <div class="panel-title">Configuration</div>
          <div class="form-row">
            <span class="form-label">Capacity</span>
            <input class="form-input" id="cs-capacity" type="number" placeholder="65536" style="width:120px">
            <button class="btn btn-primary" id="cs-set-cap">Set</button>
          </div>
          <div class="form-row" style="margin-top:0.5rem">
            <span class="form-label">Erase prefix</span>
            <input class="form-input" id="cs-erase-prefix" placeholder="/ndn/stale" style="flex:1">
            <button class="btn btn-danger" id="cs-erase-btn">Erase</button>
          </div>
        </div>
      </div>
      <div class="btn-row">
        <button class="btn" id="cs-refresh">Refresh</button>
      </div>`;

    this.container.querySelector('#cs-refresh').addEventListener('click', () => this.refresh());
    this.container.querySelector('#cs-set-cap').addEventListener('click', () => this._setCapacity());
    this.container.querySelector('#cs-erase-btn').addEventListener('click', () => this._erase());
  }

  async refresh() {
    try {
      const resp = await this.app.client.csInfo();
      const text = resp.statusText || resp.raw || '';
      const el = this.container.querySelector('#cs-stats');

      // Try to parse "variant=X capacity=N size=N hits=N misses=N"
      const m = {};
      text.replace(/(\w+)=(\S+)/g, (_, k, v) => { m[k] = v; });

      if (m.capacity || m.size || m.hits) {
        const hitRate = (m.hits && m.misses)
          ? ((parseInt(m.hits) / (parseInt(m.hits) + parseInt(m.misses))) * 100).toFixed(1)
          : null;

        el.innerHTML = `
          <div class="stat-row">
            <div class="stat-card stat-green"><div class="stat-value">${m.size || '--'}</div><div class="stat-label">Entries</div></div>
            <div class="stat-card stat-blue"><div class="stat-value">${m.capacity || '--'}</div><div class="stat-label">Capacity</div></div>
          </div>
          <div class="stat-row">
            <div class="stat-card"><div class="stat-value">${m.hits || '--'}</div><div class="stat-label">Hits</div></div>
            <div class="stat-card"><div class="stat-value">${m.misses || '--'}</div><div class="stat-label">Misses</div></div>
            ${hitRate !== null ? `<div class="stat-card stat-green"><div class="stat-value">${hitRate}%</div><div class="stat-label">Hit Rate</div></div>` : ''}
          </div>
          <div style="margin-top:0.4rem;font-size:0.78rem;color:var(--text2)">
            Backend: <code>${esc(m.variant || 'unknown')}</code>
            ${m.bytes ? ` | Memory: ${formatBytes(parseInt(m.bytes))}` : ''}
          </div>`;
      } else {
        el.innerHTML = `<pre style="font-size:0.82rem;color:var(--text2);white-space:pre-wrap">${esc(text)}</pre>`;
      }
    } catch (e) {
      this.container.querySelector('#cs-stats').innerHTML =
        `<span style="color:var(--red)">${esc(e.message)}</span>`;
    }
  }

  async _setCapacity() {
    const cap = parseInt(this.container.querySelector('#cs-capacity').value);
    if (isNaN(cap) || cap < 0) return;
    try {
      await this.app.client.command('cs', 'config', { capacity: cap });
      this.app.toast(`CS capacity set to ${cap}`);
      this.refresh();
    } catch (e) {
      this.app.toast(e.message, 'error');
    }
  }

  async _erase() {
    const prefix = this.container.querySelector('#cs-erase-prefix').value.trim();
    if (!prefix) return;
    try {
      await this.app.client.command('cs', 'erase', { name: prefix });
      this.app.toast(`Erased CS entries under ${prefix}`);
      this.container.querySelector('#cs-erase-prefix').value = '';
      this.refresh();
    } catch (e) {
      this.app.toast(e.message, 'error');
    }
  }
}

function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function formatBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  return (b / 1048576).toFixed(1) + ' MB';
}
