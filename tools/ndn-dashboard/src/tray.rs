/// System-tray integration for ndn-dashboard.
///
/// The [`TrayIcon`] type is not `Send` (it wraps NSStatusItem on macOS),
/// so we store it in a `thread_local!`.  Dioxus desktop runs everything on
/// the main thread via a `current_thread` Tokio runtime, so this is safe:
/// `setup()` and `update_state()` are always called from the same thread.
use std::cell::RefCell;
use std::sync::OnceLock;

use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

// ── Thread-local storage for the (non-Send) TrayIcon ─────────────────────────

thread_local! {
    static TRAY: RefCell<Option<TrayIcon>> = const { RefCell::new(None) };
}

// ── Stored menu-item IDs (MenuId is Clone + Send + Sync) ─────────────────────

struct MenuIds {
    open:       tray_icon::menu::MenuId,
    start:      tray_icon::menu::MenuId,
    stop:       tray_icon::menu::MenuId,
    tools:      tray_icon::menu::MenuId,
    send_file:  tray_icon::menu::MenuId,
    quit:       tray_icon::menu::MenuId,
}

static MENU_IDS: OnceLock<MenuIds> = OnceLock::new();

// ── Public API ────────────────────────────────────────────────────────────────

/// Create the system-tray icon and menu.
///
/// Must be called from the main thread after the OS event loop has started.
/// Calling it a second time is a no-op.
pub fn setup() {
    if MENU_IDS.get().is_some() {
        return; // already initialised
    }

    let open_item      = MenuItem::new("Open Dashboard",    true, None);
    let start_item     = MenuItem::new("Start Router",      true, None);
    let stop_item      = MenuItem::new("Stop Router",       true, None);
    let tools_item     = MenuItem::new("File Transfer…",    true, None);
    let send_file_item = MenuItem::new("Send File…",        true, None);
    let quit_item      = MenuItem::new("Quit",              true, None);

    let _ = MENU_IDS.set(MenuIds {
        open:      open_item.id().clone(),
        start:     start_item.id().clone(),
        stop:      stop_item.id().clone(),
        tools:     tools_item.id().clone(),
        send_file: send_file_item.id().clone(),
        quit:      quit_item.id().clone(),
    });

    let menu = Menu::new();
    let _ = menu.append_items(&[
        &open_item,
        &PredefinedMenuItem::separator(),
        &start_item,
        &stop_item,
        &PredefinedMenuItem::separator(),
        &tools_item,
        &send_file_item,
        &PredefinedMenuItem::separator(),
        &quit_item,
    ]);

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("NDN Dashboard")
        .with_icon(make_circle(139, 148, 158)) // gray = disconnected
        .build()
        .expect("failed to create system tray icon");

    TRAY.with(|t| *t.borrow_mut() = Some(tray));
}

/// Commands dispatched from tray-menu events.
#[derive(Debug)]
pub enum TrayCmd {
    OpenDashboard,
    StartRouter,
    StopRouter,
    /// Navigate dashboard to the Tools → File Transfer tab.
    OpenTools,
    /// Navigate to File Transfer tab with the send panel focused.
    SendFile,
    Quit,
}

/// Poll for one pending tray-menu event.
///
/// Call this in a loop until it returns `None` to drain the queue.
pub fn poll_menu_event() -> Option<TrayCmd> {
    let ids = MENU_IDS.get()?;
    let ev = MenuEvent::receiver().try_recv().ok()?;
    if ev.id == ids.open      { return Some(TrayCmd::OpenDashboard); }
    if ev.id == ids.start     { return Some(TrayCmd::StartRouter);   }
    if ev.id == ids.stop      { return Some(TrayCmd::StopRouter);    }
    if ev.id == ids.tools     { return Some(TrayCmd::OpenTools);     }
    if ev.id == ids.send_file { return Some(TrayCmd::SendFile);      }
    if ev.id == ids.quit      { return Some(TrayCmd::Quit);          }
    None
}

/// Update the tray icon colour and tooltip to reflect current state.
pub fn update_state(connected: bool, router_running: bool) {
    let (r, g, b) = if connected {
        (63u8, 185, 80)    // green
    } else if router_running {
        (210u8, 153, 34)   // yellow
    } else {
        (139u8, 148, 158)  // gray
    };
    let tooltip = if connected {
        "NDN Dashboard — Connected"
    } else if router_running {
        "NDN Dashboard — Router running (not connected)"
    } else {
        "NDN Dashboard — Disconnected"
    };

    TRAY.with(|t| {
        if let Some(tray) = t.borrow().as_ref() {
            let _ = tray.set_icon(Some(make_circle(r, g, b)));
            let _ = tray.set_tooltip(Some(tooltip));
        }
    });
}

// ── Icon generation ───────────────────────────────────────────────────────────

/// Generate a solid-colour circle as a 22×22 RGBA icon.
fn make_circle(r: u8, g: u8, b: u8) -> Icon {
    const S: u32 = 22;
    let mut data = vec![0u8; (S * S * 4) as usize];
    let c   = S as f32 / 2.0;
    let rad = c - 1.5_f32;
    for y in 0..S {
        for x in 0..S {
            let dx = x as f32 - c + 0.5;
            let dy = y as f32 - c + 0.5;
            if dx.hypot(dy) <= rad {
                let i = ((y * S + x) * 4) as usize;
                data[i]     = r;
                data[i + 1] = g;
                data[i + 2] = b;
                data[i + 3] = 255;
            }
        }
    }
    Icon::from_rgba(data, S, S).expect("icon data is always valid")
}
