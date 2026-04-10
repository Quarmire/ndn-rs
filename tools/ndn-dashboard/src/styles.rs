/// Global stylesheet injected into the Dioxus desktop window.
/// Colors are defined as CSS custom properties so light/dark mode can be
/// toggled by adding/removing the `light-mode` class on `<html>`.
pub const CSS: &str = "
*{box-sizing:border-box;margin:0;padding:0}
html{height:100%}

/* ── Color tokens (dark mode defaults) ──────────────────────────── */
:root{
  --bg:#0d1117;
  --surface:#161b22;
  --surface2:#1c2128;
  --border:#30363d;
  --border-subtle:#21262d;
  --text:#c9d1d9;
  --text-muted:#8b949e;
  --text-faint:#484f58;
  --accent:#58a6ff;
  --accent-solid:#1f6feb;
  --accent-dim:#1f6feb22;
  --accent-bg:#0c2d6b;
  --green:#3fb950;
  --green-bg:#1a4731;
  --green-dark:#0f2a16;
  --yellow:#d29922;
  --yellow-bg:#3d3000;
  --red:#f85149;
  --red-bg:#4e1717;
  --orange:#f0883e;
  --orange-bg:#3d1f00;
  --purple:#a371f7;
  --purple-bg:#2a1a4e;
  --btn-p:#238636;
  --btn-p-h:#2ea043;
  --btn-d:#da3633;
  --btn-d-h:#f85149;
  --shadow:rgba(0,0,0,.8);
}

/* ── Light mode overrides ────────────────────────────────────────── */
html.light-mode{
  --bg:#ffffff;
  --surface:#f6f8fa;
  --surface2:#f0f3f6;
  --border:#d0d7de;
  --border-subtle:#e8ebef;
  --text:#1f2328;
  --text-muted:#656d76;
  --text-faint:#9198a1;
  --accent:#0969da;
  --accent-solid:#0550ae;
  --accent-dim:#0969da18;
  --accent-bg:#ddf4ff;
  --green:#1a7f37;
  --green-bg:#dafbe1;
  --green-dark:#ccffd8;
  --yellow:#9a6700;
  --yellow-bg:#fff8c5;
  --red:#cf222e;
  --red-bg:#ffebe9;
  --orange:#bc4c00;
  --orange-bg:#fff1e5;
  --purple:#8250df;
  --purple-bg:#fbefff;
  --btn-p:#1a7f37;
  --btn-p-h:#2da44e;
  --btn-d:#cf222e;
  --btn-d-h:#a40e26;
  --shadow:rgba(0,0,0,.18);
}

body{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);display:flex;height:100%;overflow:hidden}
/* Dioxus desktop mounts into a bare <div> inside body with no size — override it. */
body>div{height:100%;width:100%;overflow:hidden}
.layout{display:flex;width:100%;height:100%}
.sidebar{width:200px;min-width:200px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column}
.sidebar-logo{padding:16px;font-size:15px;font-weight:600;color:var(--accent);border-bottom:1px solid var(--border);letter-spacing:.5px}
.nav-item{padding:10px 16px;cursor:pointer;color:var(--text-muted);font-size:13px;border-left:3px solid transparent;transition:all .15s}
.nav-item:hover{background:var(--border-subtle);color:var(--text)}
.nav-item.active{background:var(--accent-dim);color:var(--accent);border-left-color:var(--accent)}
.main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-height:0}
.conn-bar{display:flex;align-items:center;gap:10px;background:var(--surface);border-bottom:1px solid var(--border);padding:10px 20px;font-size:13px;flex-shrink:0}
.conn-bar input{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:5px 10px;border-radius:4px;font-size:13px;font-family:monospace;flex:1;max-width:280px;min-width:120px}
.conn-bar input:focus{outline:none;border-color:var(--accent)}
.content{flex:1;overflow-y:auto;padding:24px;min-height:0}
.badge{display:inline-block;padding:2px 9px;border-radius:10px;font-size:11px;font-weight:600}
.badge-green{background:var(--green-bg);color:var(--green)}
.badge-red{background:var(--red-bg);color:var(--red)}
.badge-yellow{background:var(--yellow-bg);color:var(--yellow)}
.badge-blue{background:var(--accent-bg);color:var(--accent)}
.badge-gray{background:var(--border-subtle);color:var(--text-muted)}
.badge-purple{background:var(--purple-bg);color:var(--purple)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:24px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px}
.card-label{font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}
.card-value{font-size:30px;font-weight:600;color:var(--text);line-height:1}
.card-sub{font-size:12px;color:var(--text-muted);margin-top:6px}
.section{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px}
.section-title{font-size:13px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:14px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:6px 12px;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;border-bottom:1px solid var(--border)}
td{padding:8px 12px;border-bottom:1px solid var(--border-subtle);color:var(--text);vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:var(--surface2)}
.form-row{display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;margin-top:14px;padding-top:14px;border-top:1px solid var(--border-subtle)}
.form-group{display:flex;flex-direction:column;gap:4px}
label{font-size:11px;color:var(--text-muted)}
input,select,textarea{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:4px;font-size:13px;font-family:inherit}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent)}
.btn{padding:7px 14px;border-radius:6px;border:none;cursor:pointer;font-size:13px;font-weight:500;font-family:inherit;transition:background .15s}
.btn-primary{background:var(--btn-p);color:#fff}
.btn-primary:hover{background:var(--btn-p-h)}
.btn-danger{background:var(--btn-d);color:#fff}
.btn-danger:hover{background:var(--btn-d-h)}
.btn-secondary{background:var(--border-subtle);color:var(--text);border:1px solid var(--border)}
.btn-secondary:hover{background:var(--border)}
.btn-sm{padding:4px 10px;font-size:12px}
.error-banner{background:var(--red-bg);border:1px solid var(--red);border-radius:6px;padding:10px 16px;margin-bottom:16px;color:var(--red);font-size:13px;display:flex;justify-content:space-between;align-items:center}
.mono{font-family:'SF Mono',Consolas,monospace;font-size:12px}
.empty{color:var(--text-muted);font-size:13px;padding:20px 0;text-align:center}
[data-tooltip]{position:relative;cursor:help}
[data-tooltip]::after{content:attr(data-tooltip);position:absolute;bottom:calc(100% + 6px);left:50%;transform:translateX(-50%);background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:5px 10px;font-size:11px;color:var(--text);white-space:pre-wrap;max-width:280px;pointer-events:none;opacity:0;transition:opacity .15s;z-index:200;line-height:1.5;text-align:left}
[data-tooltip]:hover::after{opacity:1}
.restart-banner{background:var(--yellow-bg);border:1px solid var(--yellow);border-radius:6px;padding:8px 14px;margin-bottom:14px;color:var(--yellow);font-size:12px;display:flex;align-items:center;gap:8px}
/* ── Onboarding overlay ─────────────────────────────────────────── */
.onboarding-overlay{position:fixed;inset:0;background:rgba(0,0,0,.88);z-index:1000;display:flex;align-items:center;justify-content:center;animation:fade-in .25s ease}
.onboarding-card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:40px 44px;width:580px;max-width:92vw;position:relative;animation:slide-up .3s ease}
@keyframes slide-up{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
@keyframes fade-in{from{opacity:0}to{opacity:1}}
.onboarding-step{animation:step-in .25s ease}
@keyframes step-in{from{opacity:0;transform:translateX(18px)}to{opacity:1;transform:translateX(0)}}
.step-dots{display:flex;gap:8px;margin-top:28px;justify-content:center}
.step-dot{width:8px;height:8px;border-radius:50%;background:var(--border);transition:background .25s,transform .25s}
.step-dot.active{background:var(--accent);transform:scale(1.3)}
.step-dot.done{background:var(--green)}
/* ── Packet flow animation ─────────────────────────────────────── */
@keyframes packet-fly{0%{left:-60px;opacity:0}15%{opacity:1}85%{opacity:1}100%{left:calc(100% + 20px);opacity:0}}
.packet-lane{position:relative;height:28px;overflow:hidden;background:var(--bg);border-radius:4px;margin:6px 0}
.packet-bubble{position:absolute;top:4px;background:var(--accent-solid);color:#fff;border-radius:3px;padding:2px 8px;font-size:10px;font-family:monospace;white-space:nowrap;animation:packet-fly 2.8s ease-in-out infinite}
.packet-bubble.data{background:var(--green-bg);color:var(--green);animation-delay:.9s}
.packet-bubble.nack{background:var(--red-bg);color:var(--red);animation-delay:1.8s}
html.light-mode .packet-bubble.data{background:var(--green);color:#fff}
html.light-mode .packet-bubble.nack{background:var(--red);color:#fff}
/* ── Trust chain ────────────────────────────────────────────────── */
.trust-chain{display:flex;align-items:center;gap:0;margin:16px 0;flex-wrap:wrap}
.chain-node{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 14px;text-align:center;min-width:110px;transition:border-color .2s}
.chain-node.ok{border-color:var(--green)}
.chain-node.warn{border-color:var(--yellow)}
.chain-node.missing{border-color:var(--border);opacity:.5}
.chain-arrow{font-size:18px;color:var(--border);padding:0 4px;flex-shrink:0}
/* ── Education snippets ────────────────────────────────────────── */
.edu-card{background:linear-gradient(135deg,#0c2d6b1a,#1a472a1a);border:1px solid #1f4f8a44;border-radius:8px;padding:14px 16px;margin-bottom:16px;position:relative;overflow:hidden}
html.light-mode .edu-card{background:linear-gradient(135deg,#cce5ff22,#ccffd822);border-color:#0969da33}
.edu-dismiss{position:absolute;top:8px;right:10px;background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:16px;padding:0;line-height:1}
.edu-dismiss:hover{color:var(--text)}
@keyframes sig-glow{0%,100%{box-shadow:0 0 0 0 transparent}50%{box-shadow:0 0 8px 3px #3fb95044}}
.signed-packet{display:inline-flex;align-items:center;gap:5px;background:var(--green-dark);border:1px solid var(--green);border-radius:4px;padding:3px 9px;font-size:11px;font-family:monospace;animation:sig-glow 2.4s ease infinite}
@keyframes trust-pulse{0%,100%{opacity:.4}50%{opacity:1}}
.trust-link{display:inline-block;width:28px;height:2px;background:var(--accent);border-radius:1px;animation:trust-pulse 1.8s ease infinite;margin:0 4px;vertical-align:middle}
/* ── Progress steps ────────────────────────────────────────────── */
.enroll-steps{display:flex;align-items:center;gap:0;margin:14px 0;font-size:11px;flex-wrap:wrap}
.enroll-step{display:flex;flex-direction:column;align-items:center;gap:4px;min-width:64px;text-align:center}
.enroll-step-dot{width:11px;height:11px;border-radius:50%;background:var(--border);flex-shrink:0;transition:background .3s}
.enroll-step-dot.done{background:var(--green)}
.enroll-step-dot.active{background:var(--accent);box-shadow:0 0 0 3px var(--accent-dim);animation:ping .9s ease infinite}
@keyframes ping{0%,100%{box-shadow:0 0 0 3px var(--accent-dim)}50%{box-shadow:0 0 0 6px var(--accent-dim)}}
.enroll-step-line{flex:1;height:2px;background:var(--border);min-width:24px}
.enroll-step-line.done{background:var(--green)}
/* ── YubiKey ───────────────────────────────────────────────────── */
.yk-seed{background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:10px 12px;font-family:'SF Mono',monospace;font-size:11px;color:var(--green);word-break:break-all;margin:8px 0;line-height:1.7}
.yk-cmd{background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:8px 12px;font-family:'SF Mono',monospace;font-size:11px;color:var(--accent);word-break:break-all;margin:6px 0;user-select:all}
/* ── DID ───────────────────────────────────────────────────────── */
.did-value{background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:8px 12px;font-family:'SF Mono',monospace;font-size:12px;color:var(--purple);word-break:break-all;margin:6px 0}
.did-copy-btn{background:none;border:1px solid var(--border);color:var(--text-muted);border-radius:4px;padding:3px 8px;font-size:11px;cursor:pointer}
.did-copy-btn:hover{border-color:var(--accent);color:var(--accent)}
/* ── Fleet edu animation ───────────────────────────────────────── */
.edu-flow-row{display:flex;align-items:center;justify-content:center;gap:6px;margin:4px 0}
.edu-flow-label{font-size:8px;color:var(--text-muted);text-align:center;letter-spacing:.5px}
.edu-router{width:24px;height:20px;background:var(--surface2);border:1px solid var(--border);border-radius:3px;display:flex;align-items:center;justify-content:center;font-size:8px;font-weight:600;color:var(--text)}
.edu-router-ca{border-color:var(--accent-solid);color:var(--accent)}
.edu-cert-glow{border-color:var(--green);color:var(--green)}
@keyframes arrow-pulse{0%,100%{opacity:.3}50%{opacity:1}}
.edu-arrow{font-size:10px;color:var(--text-muted);animation:arrow-pulse 1.6s ease infinite}
.edu-arrow-right{color:var(--accent-solid)}
.edu-anim-delay1{animation-delay:.4s}
/* ── Overview edu animation ────────────────────────────────────── */
@keyframes drop-packet{0%{transform:translateY(-10px);opacity:0}30%{opacity:1}60%{transform:translateY(0);opacity:1}80%{opacity:0;filter:blur(2px)}100%{opacity:0}}
.drop-packet{font-size:11px;background:var(--red-bg);border:1px solid var(--red)66;border-radius:3px;padding:2px 7px;display:inline-block;animation:drop-packet 2.2s ease infinite;font-family:monospace}
/* ── Log view ──────────────────────────────────────────────────── */
.log-entry{display:flex;align-items:flex-start;gap:8px;padding:3px 4px;border-bottom:1px solid var(--surface2);font-size:12px;font-family:'SF Mono',monospace;min-width:0}
.log-entry:last-child{border-bottom:none}
.log-ts{color:var(--text-faint);font-size:10px;white-space:nowrap;flex-shrink:0}
.log-lvl{padding:1px 5px;border-radius:3px;font-size:10px;font-weight:700;min-width:44px;text-align:center;flex-shrink:0;white-space:nowrap}
.log-target{color:var(--text-muted);flex-shrink:0;white-space:nowrap;max-width:220px;overflow:hidden;text-overflow:ellipsis}
.log-msg{color:var(--text);flex:1;min-width:0;white-space:pre-wrap;word-break:break-word}
.log-list{display:flex;flex-direction:column;overflow-y:auto;overflow-x:hidden;flex:1;min-height:0}
.log-toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.filter-controls-section{background:var(--bg);border:1px solid var(--border-subtle);border-radius:6px;padding:12px;margin-bottom:12px}
.col-toggle{padding:2px 7px;border-radius:4px;border:1px solid var(--border);background:var(--bg);color:var(--text-muted);font-size:10px;cursor:pointer;font-family:inherit;transition:all .15s}
.col-toggle.on{background:var(--accent-dim);border-color:var(--accent);color:var(--accent)}
/* ── Split / floating panes ────────────────────────────────────── */
.split-divider{background:var(--border-subtle);flex-shrink:0;transition:background .15s}
.split-divider:hover{background:var(--accent)}
.split-divider-h{width:4px;cursor:col-resize}
.split-divider-v{height:4px;cursor:row-resize}
.log-pane{display:flex;flex-direction:column;flex:1;min-width:0;min-height:0;overflow:hidden;padding:12px}
.floating-pane{position:fixed;z-index:200;background:var(--surface);border:1px solid var(--border);border-radius:8px;box-shadow:0 12px 40px var(--shadow);display:flex;flex-direction:column;resize:both;overflow:hidden;min-width:420px;min-height:280px}
.floating-title{background:var(--border-subtle);border-bottom:1px solid var(--border);padding:6px 10px;display:flex;align-items:center;justify-content:space-between;cursor:move;user-select:none;flex-shrink:0;font-size:12px;color:var(--text)}
.floating-body{flex:1;min-height:0;overflow:hidden;display:flex;flex-direction:column}
/* ── Overview expandable cards ─────────────────────────────── */
.overview-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:16px}
.ov-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px 16px;cursor:pointer;transition:all .15s;user-select:none}
.ov-card:hover{background:var(--surface2);border-color:var(--accent)44}
.ov-card-active{background:var(--accent-dim);border-color:var(--accent);box-shadow:0 0 0 1px var(--accent-dim)}
.ov-card-static{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px 16px;cursor:default}
.ov-card-label{font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px}
.ov-card-value{font-size:26px;font-weight:600;color:var(--text);line-height:1}
.ov-card-hint{font-size:10px;color:var(--text-faint);margin-top:5px}
.section-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
.mini-stat{background:var(--bg);border:1px solid var(--border-subtle);border-radius:6px;padding:10px 12px}
.mini-stat-label{font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}
.mini-stat-value{font-size:20px;font-weight:600;color:var(--text)}
.mini-stat-sub{font-size:11px;color:var(--text-muted);margin-top:3px}
/* ── Modals ────────────────────────────────────────────────── */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:500;display:flex;align-items:center;justify-content:center}
html.light-mode .modal-overlay{background:rgba(0,0,0,.45)}
.modal-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:24px;width:520px;max-width:92vw;max-height:86vh;overflow-y:auto;animation:slide-up .2s ease}
.modal-card-wide{width:620px}
.modal-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
.modal-title{font-size:15px;font-weight:600;color:var(--text)}
.modal-close{background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:18px;padding:0;line-height:1}
.modal-close:hover{color:var(--text)}
.modal-footer{display:flex;justify-content:flex-end;gap:8px;margin-top:20px;padding-top:14px;border-top:1px solid var(--border-subtle)}
/* ── Tab pills ─────────────────────────────────────────────── */
.tab-pills{display:flex;gap:4px;margin-bottom:16px;flex-wrap:wrap}
.tab-pill{padding:5px 12px;border-radius:20px;border:1px solid var(--border);background:transparent;color:var(--text-muted);font-size:12px;cursor:pointer;transition:all .15s;font-family:inherit}
.tab-pill:hover{border-color:var(--accent);color:var(--text)}
.tab-pill.active{border-color:var(--accent);background:var(--accent-dim);color:var(--accent)}
/* ── Face type grid ────────────────────────────────────────── */
.face-type-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:16px}
.face-type-btn{padding:10px 8px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text-muted);cursor:pointer;text-align:center;font-size:12px;transition:all .15s;font-family:inherit}
.face-type-btn:hover{border-color:var(--accent);color:var(--text)}
.face-type-btn.selected{border-color:var(--accent);background:var(--accent-dim);color:var(--accent);font-weight:500}
/* ── Face monitor toggles ──────────────────────────────────── */
.face-toggle-row{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px}
.face-toggle{padding:3px 10px;border-radius:12px;border:1px solid var(--border);background:transparent;color:var(--text-muted);font-size:11px;cursor:pointer;transition:all .15s;font-family:monospace}
.face-toggle:hover{border-color:var(--accent);color:var(--text)}
.face-toggle.on{border-color:var(--accent);background:var(--accent-dim);color:var(--accent)}
/* ── Icon buttons ──────────────────────────────────────────── */
.icon-btn{background:none;border:1px solid var(--border);color:var(--text-muted);border-radius:6px;padding:4px 8px;cursor:pointer;font-size:14px;line-height:1;transition:all .15s;font-family:inherit}
.icon-btn:hover{background:var(--border-subtle);color:var(--text);border-color:var(--accent)}
/* ── Theme toggle ──────────────────────────────────────────── */
.theme-toggle{background:none;border:1px solid var(--border);color:var(--text-muted);border-radius:6px;padding:4px 8px;cursor:pointer;font-size:14px;line-height:1;transition:all .15s;font-family:inherit;flex-shrink:0}
.theme-toggle:hover{background:var(--border-subtle);color:var(--text);border-color:var(--accent)}
/* ── Security health dot ───────────────────────────────────── */
.sec-dot{width:8px;height:8px;border-radius:50%;display:inline-block;flex-shrink:0;margin-left:8px;cursor:default;transition:opacity .15s}
.sec-dot:hover{opacity:.7}
.sec-dot-green{background:var(--green)}
.sec-dot-yellow{background:var(--yellow)}
.sec-dot-red{background:var(--red)}
.sec-dot-gray{background:var(--text-faint)}
/* ── Sidebar bottom + gear ─────────────────────────────────── */
.sidebar-spacer{flex:1}
.sidebar-bottom{padding:12px 14px;border-top:1px solid var(--border);position:relative}
.gear-menu{position:absolute;bottom:calc(100% + 4px);left:12px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;min-width:170px;box-shadow:0 8px 24px var(--shadow);z-index:300;overflow:hidden}
.gear-menu-item{padding:9px 14px;font-size:13px;color:var(--text);cursor:pointer;transition:background .15s}
.gear-menu-item:hover{background:var(--border)}
/* ── Range slider ──────────────────────────────────────────── */
input[type=range]{-webkit-appearance:none;height:4px;background:var(--border);border-radius:2px;border:none;padding:0;width:100%}
input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:14px;height:14px;border-radius:50%;background:var(--accent);cursor:pointer}
input[type=range]:focus{outline:none;border-color:transparent}
/* ── Toasts ────────────────────────────────────────────────── */
@keyframes toast-in{from{opacity:0;transform:translateX(24px)}to{opacity:1;transform:translateX(0)}}
.toast-container{position:fixed;bottom:20px;right:20px;z-index:600;display:flex;flex-direction:column;gap:8px;max-width:340px;pointer-events:none}
.toast{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 14px;display:flex;align-items:flex-start;justify-content:space-between;gap:10px;pointer-events:all;animation:toast-in .2s ease;box-shadow:0 4px 16px var(--shadow);min-width:240px}
.toast-success{border-color:var(--green);background:var(--green-bg)}
.toast-warning{border-color:var(--yellow);background:var(--yellow-bg)}
.toast-error{border-color:var(--red);background:var(--red-bg)}
.toast-info{border-color:var(--accent);background:var(--accent-bg)}
html.light-mode .toast-success{background:var(--green-bg)}
html.light-mode .toast-warning{background:var(--yellow-bg)}
html.light-mode .toast-error{background:var(--red-bg)}
html.light-mode .toast-info{background:var(--accent-bg)}
.toast-body{display:flex;align-items:flex-start;gap:8px;flex:1;min-width:0}
.toast-icon{font-size:13px;flex-shrink:0;line-height:1.5}
.toast-msg{font-size:12px;color:var(--text);line-height:1.5;word-break:break-word}
.toast-close{background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:14px;padding:0;line-height:1;flex-shrink:0;align-self:flex-start}
.toast-close:hover{color:var(--text)}
/* ── Autocomplete ──────────────────────────────────────────── */
.autocomplete-wrap{position:relative}
.autocomplete-list{background:var(--surface2);border:1px solid var(--border);border-top:none;border-radius:0 0 4px 4px;overflow:hidden;margin-top:-1px}
.autocomplete-item{padding:5px 10px;font-size:12px;font-family:'SF Mono',monospace;color:var(--text-muted);cursor:pointer;transition:background .1s}
.autocomplete-item:hover{background:var(--border);color:var(--accent)}
/* ── Face templates ────────────────────────────────────────── */
.face-templates{display:flex;flex-wrap:wrap;gap:5px;margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid var(--border-subtle)}
.face-tpl-btn{padding:3px 9px;border-radius:10px;border:1px solid var(--border);background:transparent;color:var(--text-muted);font-size:11px;cursor:pointer;transition:all .15s;white-space:nowrap;font-family:inherit}
.face-tpl-btn:hover{border-color:var(--accent);color:var(--text)}
/* ── Build config section ──────────────────────────────────── */
.bc-section{background:var(--bg);border:1px solid var(--border-subtle);border-radius:6px;padding:12px 14px;margin-bottom:12px}
.bc-section-title{font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px;font-weight:600}
.bc-face-row{display:flex;align-items:center;gap:8px;padding:5px 8px;background:var(--surface2);border-radius:4px;margin-bottom:4px;font-size:12px;font-family:monospace}
.bc-face-row:last-child{margin-bottom:0}
";
