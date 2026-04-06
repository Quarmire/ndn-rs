export class StrategyView {
  constructor(container, app) {
    this.container = container;
    this.app = app;
  }

  render() {
    this.container.innerHTML = `
      <h1 style="margin-bottom:1rem">Strategy Management</h1>
      <div class="panel" style="margin-bottom:0.75rem">
        <div class="panel-title">Set Strategy</div>
        <div class="form-row">
          <span class="form-label">Prefix</span>
          <input class="form-input" id="strat-prefix" placeholder="/ndn/example" style="flex:1">
        </div>
        <div class="form-row">
          <span class="form-label">Strategy</span>
          <select class="form-input" id="strat-name" style="flex:1">
            <option value="/localhost/nfd/strategy/best-route">Best Route</option>
            <option value="/localhost/nfd/strategy/multicast">Multicast</option>
            <option value="/localhost/nfd/strategy/ncc">NCC</option>
            <option value="/localhost/nfd/strategy/access">Access</option>
            <option value="/localhost/nfd/strategy/self-learning">Self-Learning</option>
          </select>
          <button class="btn btn-primary" id="strat-set-btn">Set</button>
        </div>
        <div style="font-size:0.72rem;color:var(--text2);margin-top:0.3rem">
          Or enter a custom strategy name in the dropdown
        </div>
      </div>
      <div class="panel">
        <div class="panel-title">Strategy Assignments</div>
        <div class="btn-row">
          <button class="btn" id="strat-refresh">Refresh</button>
        </div>
        <div id="strat-table" class="loading">Loading...</div>
      </div>`;

    this.container.querySelector('#strat-set-btn').addEventListener('click', () => this._set());
    this.container.querySelector('#strat-refresh').addEventListener('click', () => this.refresh());
  }

  async refresh() {
    try {
      const resp = await this.app.client.listStrategy();
      const text = resp.statusText || resp.raw || '';
      const el = this.container.querySelector('#strat-table');

      // Parse "prefix /x strategy /localhost/nfd/strategy/best-route"
      const lines = text.split('\n').filter(l => l.trim().length > 0);
      const entries = [];
      for (const line of lines) {
        const m = line.match(/prefix\s+(\/\S*)\s+strategy\s+(\/\S*)/);
        if (m) {
          entries.push({ prefix: m[1], strategy: m[2] });
        }
      }

      if (entries.length === 0) {
        if (text.trim()) {
          el.innerHTML = `<pre style="font-size:0.82rem;color:var(--text2);white-space:pre-wrap">${esc(text)}</pre>`;
        } else {
          el.innerHTML = '<span style="color:var(--text2)">No strategy assignments</span>';
        }
        return;
      }

      el.innerHTML = `
        <table class="data-table">
          <tr><th>Prefix</th><th>Strategy</th><th></th></tr>
          ${entries.map(e => `
            <tr>
              <td class="name">${esc(e.prefix)}</td>
              <td class="uri">${esc(this._shortName(e.strategy))}</td>
              <td><button class="btn btn-danger btn-unset" data-prefix="${esc(e.prefix)}">Unset</button></td>
            </tr>`).join('')}
        </table>`;

      el.querySelectorAll('.btn-unset').forEach(btn => {
        btn.addEventListener('click', () => this._unset(btn.dataset.prefix));
      });
    } catch (e) {
      this.container.querySelector('#strat-table').innerHTML =
        `<span style="color:var(--red)">${esc(e.message)}</span>`;
    }
  }

  _shortName(strategy) {
    // "/localhost/nfd/strategy/best-route" → "best-route"
    const parts = strategy.split('/');
    return parts[parts.length - 1] || strategy;
  }

  async _set() {
    const prefix = this.container.querySelector('#strat-prefix').value.trim();
    const strategy = this.container.querySelector('#strat-name').value;
    if (!prefix || !strategy) return;
    try {
      await this.app.client.setStrategy(prefix, strategy);
      this.app.toast(`Strategy set: ${prefix} → ${this._shortName(strategy)}`);
      this.container.querySelector('#strat-prefix').value = '';
      this.refresh();
    } catch (e) {
      this.app.toast(e.message, 'error');
    }
  }

  async _unset(prefix) {
    try {
      await this.app.client.command('strategy-choice', 'unset', { name: prefix });
      this.app.toast(`Strategy unset for ${prefix}`);
      this.refresh();
    } catch (e) {
      this.app.toast(e.message, 'error');
    }
  }
}

function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
