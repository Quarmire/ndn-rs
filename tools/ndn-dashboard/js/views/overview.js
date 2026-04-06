export class OverviewView {
  constructor(container, app) {
    this.container = container;
    this.app = app;
  }

  render() {
    this.container.innerHTML = `
      <h1 style="margin-bottom:1rem">Router Overview</h1>
      <div class="stat-row" id="overview-stats">
        <div class="stat-card stat-blue"><div class="stat-value" id="stat-faces">--</div><div class="stat-label">Faces</div></div>
        <div class="stat-card stat-purple"><div class="stat-value" id="stat-fib">--</div><div class="stat-label">FIB Entries</div></div>
        <div class="stat-card stat-orange"><div class="stat-value" id="stat-pit">--</div><div class="stat-label">PIT Entries</div></div>
        <div class="stat-card stat-green"><div class="stat-value" id="stat-cs">--</div><div class="stat-label">CS Entries</div></div>
      </div>
      <div class="panel-grid">
        <div class="panel">
          <div class="panel-title">Content Store</div>
          <div id="overview-cs" class="loading">Loading...</div>
        </div>
        <div class="panel">
          <div class="panel-title">Quick Actions</div>
          <div style="display:flex;flex-direction:column;gap:0.4rem">
            <button class="btn" id="btn-refresh">Refresh All</button>
            <button class="btn" id="btn-go-faces">Manage Faces</button>
            <button class="btn" id="btn-go-routes">Manage Routes</button>
            <button class="btn btn-danger" id="btn-shutdown">Shutdown Router</button>
          </div>
        </div>
        <div class="panel full">
          <div class="panel-title">Faces</div>
          <div id="overview-faces" class="loading">Loading...</div>
        </div>
      </div>`;

    this.container.querySelector('#btn-refresh').addEventListener('click', () => this.refresh());
    this.container.querySelector('#btn-go-faces').addEventListener('click', () => this.app.navigate('faces'));
    this.container.querySelector('#btn-go-routes').addEventListener('click', () => this.app.navigate('routes'));
    this.container.querySelector('#btn-shutdown').addEventListener('click', async () => {
      if (confirm('Shut down the router?')) {
        try {
          await this.app.client.command('status', 'shutdown');
          this.app.toast('Shutdown command sent');
        } catch (e) {
          this.app.toast(e.message, 'error');
        }
      }
    });
  }

  async refresh() {
    try {
      const [status, cs, faces] = await Promise.all([
        this.app.client.statusGeneral(),
        this.app.client.csInfo(),
        this.app.client.listFaces(),
      ]);

      // Parse general status: "faces=N fib=N pit=N cs=N"
      const statusText = status.statusText || status.raw || '';
      const nums = {};
      statusText.replace(/(\w+)=(\d+)/g, (_, k, v) => { nums[k] = parseInt(v); });

      this._el('stat-faces').textContent = nums.faces ?? '--';
      this._el('stat-fib').textContent = nums.fib ?? '--';
      this._el('stat-pit').textContent = nums.pit ?? '--';
      this._el('stat-cs').textContent = nums.cs ?? '--';

      // CS info
      const csText = cs.statusText || cs.raw || '';
      this._el('overview-cs').innerHTML = `<pre style="font-size:0.82rem;color:var(--text2);white-space:pre-wrap">${esc(csText)}</pre>`;

      // Faces summary table
      const facesText = faces.statusText || faces.raw || '';
      this._renderFacesTable(facesText);

    } catch (e) {
      this._el('overview-cs').innerHTML = `<span style="color:var(--red)">${esc(e.message)}</span>`;
    }
  }

  _renderFacesTable(text) {
    const lines = text.split('\n').filter(l => l.trim().startsWith('faceid='));
    if (lines.length === 0) {
      this._el('overview-faces').innerHTML = '<span style="color:var(--text2)">No faces</span>';
      return;
    }

    const rows = lines.map(line => {
      const m = {};
      line.replace(/(\w+)=([^\s]+)/g, (_, k, v) => { m[k] = v; });
      return m;
    });

    this._el('overview-faces').innerHTML = `
      <table class="data-table">
        <tr><th>ID</th><th>Remote</th><th>Local</th><th>Persistency</th></tr>
        ${rows.map(r => `
          <tr>
            <td class="mono">${r.faceid || '--'}</td>
            <td class="uri">${esc(r.remote || r.kind || 'N/A')}</td>
            <td class="uri">${esc(r.local || 'N/A')}</td>
            <td><span class="badge">${r.persistency || '--'}</span></td>
          </tr>`).join('')}
      </table>`;
  }

  _el(id) { return this.container.querySelector(`#${id}`); }
}

function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
