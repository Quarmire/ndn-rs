import { LAYER_COLORS } from '../app.js';

// GitHub search URL for a type name
const ghSearch = name =>
  `https://github.com/Quarmire/ndn-rs/search?q=${encodeURIComponent(name)}&type=code`;

export class TypeDetail {
  constructor(container, app) {
    this.container = container;
    this.app = app;
  }

  onShow(params) {
    if (!params || !params.typeName) return;
    this.render(params.typeName, params.crateName);
  }

  render(typeName, fromCrate) {
    const defining = this.app.getCrate(fromCrate);
    const color = defining ? (LAYER_COLORS[defining.layer] || '#8b949e') : '#8b949e';

    // Find all crates that export this type
    const exporters = this.app.data.crates.filter(c =>
      c.key_types.includes(typeName)
    );

    // Find crates that depend on any exporter (consumers)
    const exporterNames = new Set(exporters.map(c => c.name));
    const consumers = this.app.data.crates.filter(c =>
      !exporterNames.has(c.name) &&
      c.workspace_deps.some(d => exporterNames.has(d))
    );

    this.container.innerHTML = `
      <button class="back-btn" id="type-back">&larr; Back</button>

      <div class="detail-header">
        <h1 style="color:var(--purple);font-family:'SFMono-Regular',monospace">${this._esc(typeName)}</h1>
        <div class="desc">Public type exported from the ndn-rs workspace</div>
        <div class="badges" style="margin-top:0.5rem">
          <span class="badge" style="color:var(--purple);border-color:var(--purple)">type</span>
          ${defining ? `<span class="badge" style="color:${color};border-color:${color}">${defining.layer}</span>` : ''}
          <a class="badge badge-accent"
             href="${ghSearch(typeName)}"
             target="_blank"
             rel="noopener"
             title="Search source code on GitHub">Source on GitHub ↗</a>
        </div>
      </div>

      <div class="detail-grid">

        <!-- Defined in -->
        <div class="detail-panel">
          <div class="panel-title">Exported by (${exporters.length})</div>
          ${exporters.length > 0
            ? `<ul class="dep-list">${exporters.map(c => `
                <li>
                  <span class="dep-arrow" style="color:${LAYER_COLORS[c.layer]||'#8b949e'}">●</span>
                  <button class="dep-link" data-crate="${this._esc(c.name)}">${this._esc(c.name)}</button>
                </li>`).join('')}</ul>`
            : '<p style="color:var(--text2);font-size:0.85rem">Not found in any crate\'s key_types</p>'}
        </div>

        <!-- Consumers -->
        <div class="detail-panel">
          <div class="panel-title">Used by (${consumers.length})</div>
          ${consumers.length > 0
            ? `<ul class="dep-list">${consumers.map(c => `
                <li>
                  <span class="dep-arrow" style="color:${LAYER_COLORS[c.layer]||'#8b949e'}">●</span>
                  <button class="dep-link" data-crate="${this._esc(c.name)}">${this._esc(c.name)}</button>
                </li>`).join('')}</ul>`
            : '<p style="color:var(--text2);font-size:0.85rem">No direct workspace consumers found</p>'}
        </div>

        <!-- Context note -->
        <div class="detail-panel full-width">
          <div class="panel-title">About this view</div>
          <p style="font-size:0.82rem;color:var(--text2);line-height:1.65">
            This view shows which crates export <code>${this._esc(typeName)}</code> as a public type
            and which workspace crates depend on those crates (potential consumers). For full
            doc comments, trait impls, and method signatures, see the
            <a href="${ghSearch(typeName)}" target="_blank" rel="noopener">GitHub source search</a>
            or the
            ${exporters.length > 0
              ? `<a href="../api/${exporters[0].name.replace(/-/g, '_')}/" target="_blank" rel="noopener">API docs for ${exporters[0].name}</a>`
              : 'hosted API docs'}.
          </p>
        </div>

      </div>`;

    this.container.querySelector('#type-back').addEventListener('click', () => this.app.back());
    this.container.querySelectorAll('.dep-link').forEach(btn => {
      btn.addEventListener('click', () => this.app.showCrate(btn.dataset.crate));
    });
  }

  _esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
}
