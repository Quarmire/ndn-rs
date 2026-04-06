export class FacesView {
  constructor(container, app) {
    this.container = container;
    this.app = app;
  }

  render() {
    this.container.innerHTML = `
      <h1 style="margin-bottom:1rem">Face Management</h1>
      <div class="panel" style="margin-bottom:0.75rem">
        <div class="panel-title">Create Face</div>
        <div class="form-row">
          <span class="form-label">URI</span>
          <input class="form-input" id="face-uri" placeholder="udp4://192.168.1.2:6363" style="flex:1;min-width:200px">
          <button class="btn btn-primary" id="face-create-btn">Create</button>
        </div>
        <div style="font-size:0.72rem;color:var(--text2);margin-top:0.3rem">
          Supported: udp4://, tcp4://, shm://
        </div>
      </div>
      <div class="panel">
        <div class="panel-title">Active Faces</div>
        <div class="btn-row">
          <button class="btn" id="faces-refresh">Refresh</button>
        </div>
        <div id="faces-table" class="loading">Loading...</div>
      </div>`;

    this.container.querySelector('#face-create-btn').addEventListener('click', () => this._create());
    this.container.querySelector('#face-uri').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') this._create();
    });
    this.container.querySelector('#faces-refresh').addEventListener('click', () => this.refresh());
  }

  async refresh() {
    try {
      const resp = await this.app.client.listFaces();
      const text = resp.statusText || resp.raw || '';
      const lines = text.split('\n').filter(l => l.trim().startsWith('faceid='));
      const rows = lines.map(line => {
        const m = {};
        line.replace(/(\w+)=([^\s]+)/g, (_, k, v) => { m[k] = v; });
        return m;
      });

      const el = this.container.querySelector('#faces-table');
      if (rows.length === 0) {
        el.innerHTML = '<span style="color:var(--text2)">No faces registered</span>';
        return;
      }

      el.innerHTML = `
        <table class="data-table">
          <tr><th>ID</th><th>Remote URI</th><th>Local URI</th><th>Kind</th><th>Persistency</th><th></th></tr>
          ${rows.map(r => `
            <tr>
              <td class="mono">${r.faceid || '--'}</td>
              <td class="uri">${esc(r.remote || 'N/A')}</td>
              <td class="uri">${esc(r.local || 'N/A')}</td>
              <td>${esc(r.kind || '--')}</td>
              <td><span class="badge">${r.persistency || '--'}</span></td>
              <td><button class="btn btn-danger btn-destroy" data-face="${r.faceid}">Destroy</button></td>
            </tr>`).join('')}
        </table>`;

      el.querySelectorAll('.btn-destroy').forEach(btn => {
        btn.addEventListener('click', () => this._destroy(parseInt(btn.dataset.face)));
      });
    } catch (e) {
      this.container.querySelector('#faces-table').innerHTML =
        `<span style="color:var(--red)">${esc(e.message)}</span>`;
    }
  }

  async _create() {
    const uri = this.container.querySelector('#face-uri').value.trim();
    if (!uri) return;
    try {
      await this.app.client.createFace(uri);
      this.app.toast(`Face created: ${uri}`);
      this.container.querySelector('#face-uri').value = '';
      this.refresh();
    } catch (e) {
      this.app.toast(e.message, 'error');
    }
  }

  async _destroy(faceId) {
    if (!confirm(`Destroy face ${faceId}?`)) return;
    try {
      await this.app.client.destroyFace(faceId);
      this.app.toast(`Face ${faceId} destroyed`);
      this.refresh();
    } catch (e) {
      this.app.toast(e.message, 'error');
    }
  }
}

function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
