use std::collections::{BTreeMap, BTreeSet, HashMap};

use dioxus::prelude::*;
use dioxus::desktop::Config;

use crate::app::{
    LOG_FILTER, LOG_SPLIT_MODE, LOG_SPLIT_RATIO, PENDING_LOG_FILTER, ROUTER_LOG, ROUTER_RUNNING,
};
use crate::types::{LogEntry, LogLevel};

// ── Dynamic module tree ───────────────────────────────────────────────────────

#[derive(Clone, PartialEq)]
struct ModuleGroup {
    prefix: String,
    subs:   Vec<String>,
}

fn build_module_tree(targets: &BTreeSet<String>) -> Vec<ModuleGroup> {
    let mut by_crate: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for t in targets {
        let crate_name = t.split("::").next().unwrap_or(t).to_string();
        let entry = by_crate.entry(crate_name).or_default();
        if t.contains("::") {
            entry.insert(t.clone());
        }
    }
    by_crate
        .into_iter()
        .map(|(prefix, subs)| ModuleGroup { prefix, subs: subs.into_iter().collect() })
        .collect()
}

// ── Export format ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum ExportFormat { PlainText, Json, Csv }

impl ExportFormat {
    fn ext(self) -> &'static str {
        match self { Self::PlainText => "log", Self::Json => "json", Self::Csv => "csv" }
    }
    fn render(self, entries: &[LogEntry]) -> String {
        match self {
            Self::PlainText => entries
                .iter()
                .map(|e| format!("{} {:5} {} {}", e.timestamp, e.level.as_str(), e.target, e.message))
                .collect::<Vec<_>>()
                .join("\n"),
            Self::Csv => {
                let mut out = "timestamp,level,target,message\n".to_string();
                for e in entries {
                    out.push_str(&format!(
                        "{},{},{},{}\n",
                        e.timestamp,
                        e.level.as_str(),
                        e.target,
                        csv_escape(&e.message),
                    ));
                }
                out
            }
            Self::Json => {
                let rows: Vec<String> = entries
                    .iter()
                    .map(|e| {
                        format!(
                            "  {{\"ts\":{},\"level\":{},\"target\":{},\"msg\":{}}}",
                            json_str(&e.timestamp),
                            json_str(e.level.as_str()),
                            json_str(&e.target),
                            json_str(&e.message),
                        )
                    })
                    .collect();
                format!("[\n{}\n]", rows.join(",\n"))
            }
        }
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn json_str(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n");
    format!("\"{escaped}\"")
}

// ── Level override panel verbs ─────────────────────────────────────────────────

const LEVEL_OPTIONS: &[(&str, &str)] = &[
    ("",      "inherit"),
    ("trace", "TRACE"),
    ("debug", "DEBUG"),
    ("info",  "INFO"),
    ("warn",  "WARN"),
    ("error", "ERROR"),
    ("off",   "off"),
];

// ── Split mode helper ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum SplitMode { Single, Horizontal, Vertical }

impl SplitMode {
    fn from_u8(v: u8) -> Self {
        match v { 1 => Self::Horizontal, 2 => Self::Vertical, _ => Self::Single }
    }
    fn to_u8(self) -> u8 {
        match self { Self::Single => 0, Self::Horizontal => 1, Self::Vertical => 2 }
    }
}

// ── CSS for pop-out windows ───────────────────────────────────────────────────

const LOG_WINDOW_CSS: &str = "
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;overflow:hidden;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,sans-serif}
body>div{height:100%;width:100%;overflow:hidden;display:flex;flex-direction:column}
input,select{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:5px 9px;border-radius:4px;font-size:12px;font-family:inherit}
input:focus,select:focus{outline:none;border-color:var(--accent)}
.btn{padding:5px 12px;border-radius:6px;border:none;cursor:pointer;font-size:12px;font-weight:500;font-family:inherit;transition:background .15s}
.btn-primary{background:var(--btn-p);color:#fff}.btn-primary:hover{background:var(--btn-p-h)}
.btn-secondary{background:var(--border-subtle);color:var(--text);border:1px solid var(--border)}.btn-secondary:hover{background:var(--border)}
.btn-danger{background:var(--btn-d);color:#fff}.btn-danger:hover{background:var(--red)}
.btn-sm{padding:3px 9px;font-size:11px}
.mono{font-family:'SF Mono',Consolas,monospace;font-size:11px}
.empty{color:var(--text-muted);font-size:12px;padding:16px 0;text-align:center}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:4px 8px;font-size:10px;color:var(--text-muted);text-transform:uppercase;border-bottom:1px solid var(--border)}
td{padding:6px 8px;border-bottom:1px solid var(--border-subtle);color:var(--text);vertical-align:middle}
tr:last-child td{border-bottom:none}
.log-entry{display:flex;align-items:flex-start;gap:6px;padding:2px 4px;border-bottom:1px solid var(--surface2);font-size:11px;font-family:'SF Mono',monospace;min-width:0}
.log-entry:last-child{border-bottom:none}
.log-ts{color:var(--text-faint);font-size:10px;white-space:nowrap;flex-shrink:0}
.log-tid{color:var(--text-faint);font-size:10px;white-space:nowrap;flex-shrink:0}
.log-lvl{padding:1px 4px;border-radius:3px;font-size:10px;font-weight:700;min-width:40px;text-align:center;flex-shrink:0;white-space:nowrap}
.log-target{color:var(--text-muted);flex-shrink:0;white-space:nowrap;max-width:200px;overflow:hidden;text-overflow:ellipsis}
.log-msg{color:var(--text);flex:1;min-width:0;white-space:pre-wrap;word-break:break-word}
.log-list{display:flex;flex-direction:column;overflow-y:auto;overflow-x:hidden;flex:1;min-height:0;scroll-behavior:smooth}
.log-toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px}
.filter-panel{background:var(--bg);border:1px solid var(--border-subtle);border-radius:6px;padding:10px;margin-bottom:8px;flex-shrink:0}
.col-toggle{padding:2px 7px;border-radius:4px;border:1px solid var(--border);background:var(--bg);color:var(--text-muted);font-size:10px;cursor:pointer;font-family:inherit;transition:all .15s}
.col-toggle.on{background:var(--accent-dim);border-color:var(--accent);color:var(--accent)}
.log-pane{display:flex;flex-direction:column;flex:1;min-width:0;min-height:0;overflow:hidden;padding:10px}
.modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.8);z-index:500;display:flex;align-items:center;justify-content:center}
.modal-box{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;display:flex;flex-direction:column;gap:12px;max-height:85vh}
.hint{font-size:11px;color:var(--text-faint)}
";

// ── LogPane ───────────────────────────────────────────────────────────────────
//
// Reads only from GlobalSignals + local state. Works identically in the main
// window and in pop-out OS windows. Writing to PENDING_LOG_FILTER is done only
// from an explicit user action (Apply overrides button) — never from dropdowns
// that might be held across async boundaries.

#[component]
pub fn LogPane(pane_id: usize) -> Element {
    // ── Display filters (local to this pane) ─────────────────────────────────
    let mut threshold  = use_signal(|| LogLevel::Info);
    // false = show level ≥ threshold (default); true = exact level only
    let mut exact_lvl  = use_signal(|| false);
    let mut search     = use_signal(String::new);
    let mut mod_prefix: Signal<Option<String>> = use_signal(|| None);
    let mut hide_mgmt  = use_signal(|| true);

    // ── Column visibility ─────────────────────────────────────────────────────
    let mut show_ts  = use_signal(|| true);
    let mut show_tid = use_signal(|| false);
    let mut show_lvl = use_signal(|| true);
    let mut show_tgt = use_signal(|| true);

    // ── Panel state ───────────────────────────────────────────────────────────
    let mut show_overrides  = use_signal(|| false);
    let mut show_export     = use_signal(|| false);
    let mut show_confirm    = use_signal(|| false);   // confirm before sending to router

    // Per-module level overrides (module path → level string, "" = inherit)
    let mut module_overrides: Signal<HashMap<String, String>> = use_signal(HashMap::new);

    // Export options
    let mut export_fmt:    Signal<ExportFormat>       = use_signal(|| ExportFormat::PlainText);
    let mut export_lvl:    Signal<LogLevel>            = use_signal(|| LogLevel::Trace);
    let mut export_prefix: Signal<Option<String>>      = use_signal(|| None);

    // ── Module tree (dynamic, from observed targets) ──────────────────────────
    let module_tree = use_memo(move || -> Vec<ModuleGroup> {
        let log = ROUTER_LOG.read();
        let mut targets: BTreeSet<String> = BTreeSet::new();
        for e in log.iter() { targets.insert(e.target.clone()); }
        build_module_tree(&targets)
    });

    // ── Filtered entries (main display) ──────────────────────────────────────
    let filtered = use_memo(move || -> Vec<LogEntry> {
        let log     = ROUTER_LOG.read();
        let thr     = *threshold.read();
        let exact   = *exact_lvl.read();
        let srch    = search.read().to_lowercase();
        let pfx     = mod_prefix.read().clone();
        let no_mgmt = *hide_mgmt.read();
        log.iter()
            .filter(|e| {
                (if exact { e.level == thr } else { e.level >= thr })
                    && pfx.as_deref().is_none_or(|p| e.target.starts_with(p))
                    && !(no_mgmt
                        && e.target.starts_with("ndn_router::mgmt_ndn")
                        && e.level == LogLevel::Debug)
                    && (srch.is_empty()
                        || e.message.to_lowercase().contains(srch.as_str())
                        || e.target.to_lowercase().contains(srch.as_str()))
            })
            .cloned()
            .collect()
    });

    // ── Auto-scroll to bottom when new entries arrive ─────────────────────────
    let list_id = format!("log-list-{pane_id}");
    let list_id2 = list_id.clone();
    use_effect(move || {
        let _ = filtered.read();   // subscribe — re-run when filtered changes
        document::eval(&format!(
            "var el=document.getElementById('{list_id2}');\
             if(el)el.scrollTop=el.scrollHeight;"
        ));
    });

    // ── Snapshot values for rsx (avoids holding guards across the block) ──────
    let total    = ROUTER_LOG.read().len();
    let entries  = filtered.cloned();
    let shown    = entries.len();
    let running  = *ROUTER_RUNNING.read();
    let cur_filt = LOG_FILTER.read().clone();
    let col_ts   = *show_ts.read();
    let col_tid  = *show_tid.read();
    let col_lvl  = *show_lvl.read();
    let col_tgt  = *show_tgt.read();

    // ── Export content (computed only when export modal is open) ──────────────
    let export_entries: Vec<LogEntry> = if *show_export.read() {
        let exp_thr = *export_lvl.read();
        let exp_pfx = export_prefix.read().clone();
        entries
            .iter()
            .filter(|e| {
                e.level >= exp_thr
                    && exp_pfx.as_deref().is_none_or(|p| e.target.starts_with(p))
            })
            .cloned()
            .collect()
    } else {
        vec![]
    };

    rsx! {
        div { class: "log-pane",

            // ── Status bar ────────────────────────────────────────────────────
            div { style: "display:flex;align-items:center;gap:6px;margin-bottom:6px;flex-shrink:0;flex-wrap:wrap;",
                if running {
                    span {
                        style: "font-size:10px;background:var(--green-bg);color:var(--green);border-radius:4px;padding:1px 7px;flex-shrink:0;",
                        title: "Logs captured from in-process router (live pipe)",
                        "● live"
                    }
                } else {
                    span {
                        style: "font-size:10px;background:var(--border-subtle);color:var(--text-muted);border-radius:4px;padding:1px 7px;flex-shrink:0;",
                        title: "Polling router's in-memory ring buffer every 3 s via log/get-recent",
                        "● buffered"
                    }
                }
                if !cur_filt.is_empty() {
                    span {
                        class: "mono",
                        style: "background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:1px 7px;font-size:10px;color:var(--text-muted);",
                        title: "Active runtime filter on the router",
                        "router filter: {cur_filt}"
                    }
                }
                // Column toggles (right-aligned)
                div { style: "display:flex;gap:3px;margin-left:auto;flex-wrap:wrap;",
                    button {
                        class: if col_ts  { "col-toggle on" } else { "col-toggle" },
                        title: "Toggle timestamp column",
                        onclick: move |_| { let v = *show_ts.read(); show_ts.set(!v); }, "time"
                    }
                    button {
                        class: if col_tid { "col-toggle on" } else { "col-toggle" },
                        title: "Toggle thread ID column",
                        onclick: move |_| { let v = *show_tid.read(); show_tid.set(!v); }, "thread"
                    }
                    button {
                        class: if col_lvl { "col-toggle on" } else { "col-toggle" },
                        title: "Toggle log level column",
                        onclick: move |_| { let v = *show_lvl.read(); show_lvl.set(!v); }, "level"
                    }
                    button {
                        class: if col_tgt { "col-toggle on" } else { "col-toggle" },
                        title: "Toggle module column",
                        onclick: move |_| { let v = *show_tgt.read(); show_tgt.set(!v); }, "module"
                    }
                    button {
                        class: if *hide_mgmt.read() { "col-toggle on" } else { "col-toggle" },
                        title: "Hide ndn_router::mgmt_ndn DEBUG (dashboard polling noise)",
                        onclick: move |_| { let v = *hide_mgmt.read(); hide_mgmt.set(!v); },
                        "hide mgmt"
                    }
                }
            }

            // ── Toolbar ───────────────────────────────────────────────────────
            div { class: "log-toolbar",
                // Level filter (display only — does NOT send anything to router)
                label { class: "hint", "Show:" }
                select {
                    style: "font-size:12px;",
                    title: "Filter displayed entries by level. Does not change the router's output level.",
                    onchange: move |e| {
                        if let Some(lvl) = LogLevel::parse(&e.value()) { threshold.set(lvl); }
                    },
                    option { value: "TRACE", selected: *threshold.read() == LogLevel::Trace, "TRACE" }
                    option { value: "DEBUG", selected: *threshold.read() == LogLevel::Debug, "DEBUG" }
                    option { value: "INFO",  selected: *threshold.read() == LogLevel::Info,  "INFO"  }
                    option { value: "WARN",  selected: *threshold.read() == LogLevel::Warn,  "WARN"  }
                    option { value: "ERROR", selected: *threshold.read() == LogLevel::Error, "ERROR" }
                }
                // Exact vs ≥ toggle
                button {
                    class: if *exact_lvl.read() { "col-toggle on" } else { "col-toggle" },
                    title: "Toggle: show only the selected level (exact) vs that level and above (≥)",
                    onclick: move |_| { let v = *exact_lvl.read(); exact_lvl.set(!v); },
                    if *exact_lvl.read() { "exact" } else { "≥" }
                }

                // Module filter (dynamic optgroup select)
                label { class: "hint", style: "margin-left:4px;", "Module:" }
                select {
                    style: "font-size:12px;",
                    onchange: move |e| {
                        let v = e.value();
                        mod_prefix.set(if v == "all" || v.is_empty() { None } else { Some(v) });
                    },
                    option { value: "all", selected: mod_prefix.read().is_none(), "All" }
                    {
                        let tree = module_tree.cloned();
                        let cur  = mod_prefix.read().clone();
                        rsx! {
                            for group in tree.into_iter() {
                                if group.subs.is_empty() {
                                    option {
                                        key: "{group.prefix}",
                                        value: "{group.prefix}",
                                        selected: cur.as_deref() == Some(group.prefix.as_str()),
                                        "{group.prefix}"
                                    }
                                } else {
                                    optgroup {
                                        key: "{group.prefix}",
                                        label: "{group.prefix}",
                                        option {
                                            value: "{group.prefix}",
                                            selected: cur.as_deref() == Some(group.prefix.as_str()),
                                            "{group.prefix} (all)"
                                        }
                                        for sub in group.subs.into_iter() {
                                            {
                                                let short = sub.trim_start_matches(&group.prefix).trim_start_matches("::").to_string();
                                                let is_sel = cur.as_deref() == Some(sub.as_str());
                                                rsx! {
                                                    option {
                                                        key: "{sub}",
                                                        value: "{sub}",
                                                        selected: is_sel,
                                                        "  ↳ {short}"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Search
                input {
                    r#type: "text",
                    placeholder: "Search message / module…",
                    style: "flex:1;min-width:80px;max-width:220px;font-size:12px;",
                    value: "{search}",
                    oninput: move |e| search.set(e.value()),
                }

                // Count
                span { class: "hint", style: "margin-left:auto;white-space:nowrap;",
                    "{shown} / {total}"
                }

                // Action buttons
                button {
                    class: if *show_overrides.read() { "btn btn-primary btn-sm" } else { "btn btn-secondary btn-sm" },
                    title: "Configure per-module log level overrides sent to the router",
                    onclick: move |_| { let v = *show_overrides.read(); show_overrides.set(!v); },
                    "Router filter…"
                }
                button {
                    class: "btn btn-secondary btn-sm",
                    onclick: move |_| show_export.set(true),
                    "Export…"
                }
            }

            // ── Per-module overrides panel ────────────────────────────────────
            if *show_overrides.read() {
                div { class: "filter-panel",
                    div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;",
                        span { style: "font-size:11px;font-weight:600;color:var(--accent);", "Router Runtime Filter" }
                        span { class: "hint", "Changes what the router outputs — not just the display." }
                    }
                    div { class: "hint", style: "margin-bottom:8px;",
                        "Modules appear as they emit log events. Select a level override per module, then click "
                        strong { "Apply" }
                        " — a confirmation dialog will appear before sending to the router."
                    }
                    if module_tree.cloned().is_empty() {
                        div { class: "hint", style: "padding:8px 0;", "No log entries yet — connect to a router first." }
                    } else {
                        table { style: "margin-bottom:10px;",
                            thead { tr { th { "Module" } th { "Override level" } } }
                            tbody {
                                {
                                    let tree = module_tree.cloned();
                                    rsx! {
                                        for group in tree.into_iter() {
                                            {
                                                let pfx = group.prefix.clone();
                                                let pfx2 = pfx.clone();
                                                let cur = module_overrides.read().get(&pfx).cloned().unwrap_or_default();
                                                rsx! {
                                                    tr { style: "background:var(--bg);",
                                                        td { class: "mono", style: "font-size:10px;font-weight:600;", "{pfx}" }
                                                        td {
                                                            select {
                                                                style: "font-size:11px;",
                                                                onchange: move |e| {
                                                                    let v = e.value();
                                                                    if v.is_empty() { module_overrides.write().remove(&pfx2); }
                                                                    else            { module_overrides.write().insert(pfx2.clone(), v); }
                                                                },
                                                                for (val, lbl) in LEVEL_OPTIONS.iter() {
                                                                    option { value: "{val}", selected: cur.as_str() == *val, "{lbl}" }
                                                                }
                                                            }
                                                        }
                                                    }
                                                    for sub in group.subs.into_iter() {
                                                        {
                                                            let short = sub.trim_start_matches(&group.prefix).trim_start_matches("::").to_string();
                                                            let sub2 = sub.clone();
                                                            let cur_s = module_overrides.read().get(&sub).cloned().unwrap_or_default();
                                                            rsx! {
                                                                tr {
                                                                    td { class: "mono", style: "font-size:10px;padding-left:18px;color:var(--text-muted);", "↳ {short}" }
                                                                    td {
                                                                        select {
                                                                            style: "font-size:11px;",
                                                                            onchange: move |e| {
                                                                                let v = e.value();
                                                                                if v.is_empty() { module_overrides.write().remove(&sub2); }
                                                                                else            { module_overrides.write().insert(sub2.clone(), v); }
                                                                            },
                                                                            for (val, lbl) in LEVEL_OPTIONS.iter() {
                                                                                option { value: "{val}", selected: cur_s.as_str() == *val, "{lbl}" }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    div { style: "display:flex;gap:6px;",
                        button {
                            class: "btn btn-primary btn-sm",
                            onclick: move |_| show_confirm.set(true),
                            "Apply to router…"
                        }
                        button {
                            class: "btn btn-secondary btn-sm",
                            onclick: move |_| module_overrides.write().clear(),
                            "Reset"
                        }
                    }
                }
            }

            // ── Log list (chronological, newest at bottom) ────────────────────
            div { style: "display:flex;flex-direction:column;flex:1;min-height:0;background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:4px 6px;overflow:hidden;",
                if entries.is_empty() {
                    div { class: "empty",
                        if total == 0 {
                            "No logs yet. Connect to a router or start one from the Overview tab."
                        } else {
                            "No entries match the current filters."
                        }
                    }
                } else {
                    div {
                        id: "{list_id}",
                        class: "log-list",
                        for entry in entries.iter().cloned() {
                            div { class: "log-entry",
                                if col_ts  { span { class: "log-ts",  "{entry.timestamp}" } }
                                if col_tid && let Some(ref tid) = entry.thread_id {
                                    span { class: "log-tid", "{tid}" }
                                }
                                if col_lvl {
                                    span {
                                        class: "log-lvl",
                                        style: "color:{entry.level.color()};background:{entry.level.bg()};",
                                        "{entry.level.as_str()}"
                                    }
                                }
                                if col_tgt { span { class: "log-target", title: "{entry.target}", "{entry.target}" } }
                                span { class: "log-msg", "{entry.message}" }
                            }
                        }
                    }
                }
            }
        } // end .log-pane

        // ── Confirmation dialog ───────────────────────────────────────────────
        if *show_confirm.read() {
            {
                let overrides = module_overrides.read().clone();
                let lvl_str   = threshold.read().as_str().to_lowercase();
                let mut parts: Vec<String> = vec![lvl_str.clone()];
                for (m, l) in &overrides {
                    if !l.is_empty() { parts.push(format!("{m}={l}")); }
                }
                let filter_preview = parts.join(",");
                rsx! {
                    div { class: "modal-backdrop",
                        div { class: "modal-box", style: "width:420px;",
                            div { style: "font-size:14px;font-weight:600;color:var(--text);", "Apply runtime filter?" }
                            div { class: "hint",
                                "This will change what the router "
                                strong { "outputs" }
                                " globally. All clients connected to this router will be affected."
                            }
                            div {
                                style: "background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:8px 10px;",
                                span { class: "mono", style: "font-size:12px;color:var(--accent);", "{filter_preview}" }
                            }
                            div { style: "display:flex;gap:8px;justify-content:flex-end;",
                                button {
                                    class: "btn btn-secondary btn-sm",
                                    onclick: move |_| show_confirm.set(false),
                                    "Cancel"
                                }
                                button {
                                    class: "btn btn-danger btn-sm",
                                    onclick: move |_| {
                                        *PENDING_LOG_FILTER.write() = Some(filter_preview.clone());
                                        show_confirm.set(false);
                                    },
                                    "Apply"
                                }
                            }
                        }
                    }
                }
            }
        }

        // ── Export modal ──────────────────────────────────────────────────────
        if *show_export.read() {
            {
                let fmt      = *export_fmt.read();
                let content  = fmt.render(&export_entries);
                let content2 = content.clone();
                let ext      = fmt.ext();
                rsx! {
                    div { class: "modal-backdrop",
                        div { class: "modal-box", style: "width:700px;max-width:92vw;",
                            // Header
                            div { style: "display:flex;justify-content:space-between;align-items:center;",
                                span { style: "font-size:14px;font-weight:600;color:var(--text);",
                                    "Export Logs  "
                                    span { class: "hint", "({export_entries.len()} entries)" }
                                }
                                button {
                                    class: "btn btn-secondary btn-sm",
                                    onclick: move |_| show_export.set(false), "✕"
                                }
                            }

                            // Options row
                            div { style: "display:flex;gap:16px;flex-wrap:wrap;align-items:flex-end;",
                                div { style: "display:flex;flex-direction:column;gap:4px;",
                                    label { class: "hint", "Format" }
                                    div { style: "display:flex;gap:4px;",
                                        for (f, lbl) in [(ExportFormat::PlainText, "Plain"), (ExportFormat::Json, "JSON"), (ExportFormat::Csv, "CSV")] {
                                            button {
                                                key: "{lbl}",
                                                class: if *export_fmt.read() == f { "col-toggle on" } else { "col-toggle" },
                                                onclick: move |_| export_fmt.set(f),
                                                "{lbl}"
                                            }
                                        }
                                    }
                                }
                                div { style: "display:flex;flex-direction:column;gap:4px;",
                                    label { class: "hint", "Min level" }
                                    select {
                                        style: "font-size:12px;",
                                        onchange: move |e| {
                                            if let Some(l) = LogLevel::parse(&e.value()) { export_lvl.set(l); }
                                        },
                                        option { value: "TRACE", selected: *export_lvl.read() == LogLevel::Trace, "TRACE" }
                                        option { value: "DEBUG", selected: *export_lvl.read() == LogLevel::Debug, "DEBUG" }
                                        option { value: "INFO",  selected: *export_lvl.read() == LogLevel::Info,  "INFO"  }
                                        option { value: "WARN",  selected: *export_lvl.read() == LogLevel::Warn,  "WARN"  }
                                        option { value: "ERROR", selected: *export_lvl.read() == LogLevel::Error, "ERROR" }
                                    }
                                }
                                div { style: "display:flex;flex-direction:column;gap:4px;",
                                    label { class: "hint", "Module" }
                                    select {
                                        style: "font-size:12px;",
                                        onchange: move |e| {
                                            let v = e.value();
                                            export_prefix.set(if v == "all" { None } else { Some(v) });
                                        },
                                        option { value: "all", selected: export_prefix.read().is_none(), "All" }
                                        {
                                            let tree = module_tree.cloned();
                                            let cur = export_prefix.read().clone();
                                            rsx! {
                                                for group in tree.into_iter() {
                                                    option {
                                                        key: "{group.prefix}",
                                                        value: "{group.prefix}",
                                                        selected: cur.as_deref() == Some(group.prefix.as_str()),
                                                        "{group.prefix}"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // Preview
                            textarea {
                                style: "flex:1;min-height:260px;background:var(--bg);border:1px solid var(--border);color:var(--text);font-family:'SF Mono',monospace;font-size:11px;padding:8px;border-radius:4px;resize:vertical;",
                                readonly: true,
                                value: "{content}",
                            }

                            // Save buttons
                            div { style: "display:flex;gap:8px;flex-wrap:wrap;",
                                button {
                                    class: "btn btn-primary",
                                    onclick: move |_| save_log_to_file(&content, ext),
                                    "Save to file…"
                                }
                                button {
                                    class: "btn btn-secondary",
                                    title: "Write directly to the system temp directory — useful for tailing or scripting",
                                    onclick: move |_| {
                                        if let Some(path) = save_log_to_tmp(&content2, ext) {
                                            tracing::info!(path = %path, "log exported to temp file");
                                        }
                                    },
                                    "Quick save to /tmp"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ── Pop-out window ────────────────────────────────────────────────────────────

#[component]
fn LogWindowApp(pane_id: usize) -> Element {
    rsx! {
        document::Style { "{LOG_WINDOW_CSS}" }
        LogPane { pane_id }
    }
}

// ── Logs container ────────────────────────────────────────────────────────────

#[component]
pub fn Logs() -> Element {
    // Use GlobalSignals so split layout survives tab switches.
    let mut div_drag    = use_signal(|| false);
    let mut next_pane_id = use_signal(|| 2usize); // pane 0 and 1 are always the split panes

    let split_mode  = SplitMode::from_u8(*LOG_SPLIT_MODE.read());
    let split_ratio = *LOG_SPLIT_RATIO.read();

    rsx! {
        // Drag overlay — captures mouse while divider is being dragged
        if *div_drag.read() {
            {
                let cursor = if split_mode == SplitMode::Horizontal { "col-resize" } else { "row-resize" };
                rsx! {
                    div {
                        style: "position:fixed;inset:0;z-index:100;cursor:{cursor};",
                        onmousemove: move |e| {
                            let c = e.client_coordinates();
                            let ratio = if SplitMode::from_u8(*LOG_SPLIT_MODE.read()) == SplitMode::Horizontal {
                                let avail = (dioxus::desktop::window().inner_size().width as f64 - 200.0).max(1.0);
                                (((c.x - 200.0).max(0.0) / avail * 100.0).round() as u32).clamp(20, 80)
                            } else {
                                let avail = (dioxus::desktop::window().inner_size().height as f64 - 44.0).max(1.0);
                                ((c.y - 44.0).max(0.0) / avail * 100.0).round() as u32
                            };
                            *LOG_SPLIT_RATIO.write() = ratio.clamp(20, 80);
                        },
                        onmouseup: move |_| div_drag.set(false),
                    }
                }
            }
        }

        // ── Top toolbar ───────────────────────────────────────────────────────
        div {
            style: "display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--surface);border-bottom:1px solid var(--border);flex-shrink:0;flex-wrap:wrap;",
            span { style: "font-size:13px;font-weight:600;color:var(--text);", "Router Logs" }

            // Split mode buttons
            div { style: "display:flex;gap:4px;margin-left:8px;",
                button {
                    class: if split_mode == SplitMode::Single { "btn btn-primary btn-sm" } else { "btn btn-secondary btn-sm" },
                    onclick: move |_| *LOG_SPLIT_MODE.write() = SplitMode::Single.to_u8(),
                    "Single"
                }
                button {
                    class: if split_mode == SplitMode::Horizontal { "btn btn-primary btn-sm" } else { "btn btn-secondary btn-sm" },
                    onclick: move |_| *LOG_SPLIT_MODE.write() = SplitMode::Horizontal.to_u8(),
                    "Side by Side"
                }
                button {
                    class: if split_mode == SplitMode::Vertical { "btn btn-primary btn-sm" } else { "btn btn-secondary btn-sm" },
                    onclick: move |_| *LOG_SPLIT_MODE.write() = SplitMode::Vertical.to_u8(),
                    "Stacked"
                }
            }

            if split_mode != SplitMode::Single {
                div { style: "display:flex;gap:4px;",
                    for preset in [30u32, 50, 70] {
                        button {
                            key: "{preset}",
                            class: if split_ratio == preset { "btn btn-primary btn-sm" } else { "btn btn-secondary btn-sm" },
                            onclick: move |_| *LOG_SPLIT_RATIO.write() = preset,
                            "{preset}/{100-preset}"
                        }
                    }
                }
            }

            div { style: "margin-left:auto;",
                button {
                    class: "btn btn-secondary btn-sm",
                    title: "Open log stream in a separate OS window",
                    onclick: move |_| {
                        let pid = *next_pane_id.read();
                        next_pane_id.set(pid + 1);
                        let dom = VirtualDom::new_with_props(LogWindowApp, LogWindowAppProps { pane_id: pid });
                        dioxus::desktop::window().new_window(dom, Config::default());
                    },
                    "↗ New Window"
                }
            }
        }

        // ── Pane area ─────────────────────────────────────────────────────────
        {
            let a = format!("{split_ratio}%");
            let b = format!("{}%", 100 - split_ratio);

            match split_mode {
                SplitMode::Single => rsx! {
                    div { style: "flex:1;min-height:0;display:flex;",
                        LogPane { pane_id: 0 }
                    }
                },
                SplitMode::Horizontal => rsx! {
                    div { style: "flex:1;min-height:0;display:flex;flex-direction:row;",
                        div { style: "width:{a};min-width:0;display:flex;flex-direction:column;",
                            LogPane { pane_id: 0 }
                        }
                        div {
                            style: "width:4px;background:var(--border);cursor:col-resize;flex-shrink:0;",
                            onmousedown: move |_| div_drag.set(true),
                        }
                        div { style: "width:{b};min-width:0;display:flex;flex-direction:column;",
                            LogPane { pane_id: 1 }
                        }
                    }
                },
                SplitMode::Vertical => rsx! {
                    div { style: "flex:1;min-height:0;display:flex;flex-direction:column;",
                        div { style: "height:{a};min-height:0;display:flex;flex-direction:column;",
                            LogPane { pane_id: 0 }
                        }
                        div {
                            style: "height:4px;background:var(--border);cursor:row-resize;flex-shrink:0;",
                            onmousedown: move |_| div_drag.set(true),
                        }
                        div { style: "height:{b};min-height:0;display:flex;flex-direction:column;",
                            LogPane { pane_id: 1 }
                        }
                    }
                },
            }
        }
    }
}

// ── File save helpers ─────────────────────────────────────────────────────────

fn save_log_to_file(content: &str, ext: &str) {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let ts   = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let path = format!("{home}/ndn-router-{ts}.{ext}");
    if let Err(e) = std::fs::write(&path, content) {
        tracing::error!(path = %path, error = %e, "failed to save log file");
    } else {
        tracing::info!(path = %path, "log file saved");
    }
}

/// Write to the system temp directory; returns the path on success.
/// This is convenient for scripting / external tail: `tail -f /tmp/ndn-logs-*.log`
fn save_log_to_tmp(content: &str, ext: &str) -> Option<String> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let path = std::env::temp_dir().join(format!("ndn-logs-{ts}.{ext}"));
    match std::fs::write(&path, content) {
        Ok(()) => Some(path.display().to_string()),
        Err(e) => {
            tracing::error!(path = %path.display(), error = %e, "failed to write temp log file");
            None
        }
    }
}
