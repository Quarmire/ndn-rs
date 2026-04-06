export class RoutesView {
  constructor(container, app) {
    this.container = container;
    this.app = app;
  }

  render() {
    this.container.innerHTML = `
      <h1 style="margin-bottom:1rem">Route Management</h1>
      <div class="panel" style="margin-bottom:0.75rem">
        <div class="panel-title">Add Route</div>
        <div class="form-row">
          <span class="form-label">Prefix</span>
          <input class="form-input" id="route-prefix" placeholder="/ndn/example" style="flex:1">
        </div>
        <div class="form-row">
          <span class="form-label">Face ID</span>
          <input class="form-input" id="route-face" type="number" placeholder="0" style="width:80px">
          <span class="form-label" style="margin-left:0.5rem">Cost</span>
          <input class="form-input" id="route-cost" type="number" placeholder="10" style="width:80px" value="10">
          <button class="btn btn-primary" id="route-add-btn">Add Route</button>
        </div>
      </div>
      <div class="panel">
        <div class="panel-title">FIB / RIB</div>
        <div class="btn-row">
          <button class="btn" id="routes-refresh">Refresh</button>
        </div>
        <div id="routes-table" class="loading">Loading...</div>
      </div>`;

    this.container.querySelector('#route-add-btn').addEventListener('click', () => this._add());
    this.container.querySelector('#routes-refresh').addEventListener('click', () => this.refresh());
  }

  async refresh() {
    try {
      const resp = await this.app.client.listFib();
      const text = resp.statusText || resp.raw || '';
      const el = this.container.querySelector('#routes-table');

      // Parse FIB listing: "prefix /x nexthops=[face=N cost=N, ...]"
      const lines = text.split('\n').filter(l => l.trim().length > 0 && !l.match(/^\d+ /));
      const entries = [];
      for (const line of lines) {
        const prefixMatch = line.match(/prefix\s+(\/\S*)/);
        if (!prefixMatch) continue;
        const prefix = prefixMatch[1];
        const nhMatches = [...line.matchAll(/face=(\d+)\s+cost=(\d+)/g)];
        for (const m of nhMatches) {
          entries.push({ prefix, face: m[1], cost: m[2] });
        }
        if (nhMatches.length === 0) {
          entries.push({ prefix, face: '--', cost: '--' });
        }
      }

      if (entries.length === 0) {
        // Try raw display
        if (text.trim()) {
          el.innerHTML = `<pre style="font-size:0.82rem;color:var(--text2);white-space:pre-wrap">${esc(text)}</pre>`;
        } else {
          el.innerHTML = '<span style="color:var(--text2)">No routes configured</span>';
        }
        return;
      }

      el.innerHTML = `
        <table class="data-table">
          <tr><th>Prefix</th><th>Face</th><th>Cost</th><th></th></tr>
          ${entries.map(e => `
            <tr>
              <td class="name">${esc(e.prefix)}</td>
              <td class="mono">${e.face}</td>
              <td class="mono">${e.cost}</td>
              <td>${e.face !== '--' ? `<button class="btn btn-danger btn-remove" data-prefix="${esc(e.prefix)}" data-face="${e.face}">Remove</button>` : ''}</td>
            </tr>`).join('')}
        </table>`;

      el.querySelectorAll('.btn-remove').forEach(btn => {
        btn.addEventListener('click', () => this._remove(btn.dataset.prefix, parseInt(btn.dataset.face)));
      });
    } catch (e) {
      this.container.querySelector('#routes-table').innerHTML =
        `<span style="color:var(--red)">${esc(e.message)}</span>`;
    }
  }

  async _add() {
    const prefix = this.container.querySelector('#route-prefix').value.trim();
    const face = parseInt(this.container.querySelector('#route-face').value);
    const cost = parseInt(this.container.querySelector('#route-cost').value) || 10;
    if (!prefix || isNaN(face)) return;
    try {
      await this.app.client.addRoute(prefix, face, cost);
      this.app.toast(`Route added: ${prefix} -> face ${face}`);
      this.container.querySelector('#route-prefix').value = '';
      this.refresh();
    } catch (e) {
      this.app.toast(e.message, 'error');
    }
  }

  async _remove(prefix, faceId) {
    try {
      await this.app.client.removeRoute(prefix, faceId);
      this.app.toast(`Route removed: ${prefix} face ${faceId}`);
      this.refresh();
    } catch (e) {
      this.app.toast(e.message, 'error');
    }
  }
}

function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
