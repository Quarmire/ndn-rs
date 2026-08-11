//! Layer: spec — the `NDN_*` environment surface, classified.
//!
//! **The problem this solves is reproducibility, not tidiness** (#81). 129 distinct `NDN_*`
//! variables are read across the three repos, 70 of them from library source. Nothing recorded
//! which were set for a given run, so a measurement could not be reproduced from its own output —
//! and a *misspelled* variable was indistinguishable from an unset one, silently doing nothing while
//! the operator believed it had taken effect.
//!
//! The split the tracker asked for is [`Class`]: **operational config** genuinely selects behaviour
//! and belongs in a run's description; **debug-bisect** switches exist to disable one thing at a
//! time while hunting a hardware fault, and any of them being set during a measurement is a warning
//! sign, because they turn off parts of the system under test.
//!
//! ## Why this reads the environment, not the call sites
//!
//! The obvious implementation — route all 70 reads through a helper — would be a 70-site refactor
//! that is only as complete as its last conversion, and a missed site is exactly the invisible knob
//! this exists to eliminate. [`snapshot`] instead enumerates the *process environment* and matches
//! it against the table below, so it reports every `NDN_*` that is set whether or not its reader was
//! ever touched, and flags any it does not recognise.

use std::collections::BTreeMap;

/// What a variable is for — the split #81 asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    /// Selects behaviour a run means to have. Belongs in the run's description; safe in production.
    Config,
    /// Disables or forces one mechanism so a fault can be bisected. **Set during a measurement, it
    /// is a confounder** — it turns off part of the system under test. Reported prominently.
    DebugBisect,
    /// Set in the environment, matched by nothing here. Most likely a typo of a real one, which
    /// would otherwise fail silently — the failure mode this whole module exists to catch.
    Unrecognised,
}

/// One classified variable.
#[derive(Clone, Copy, Debug)]
pub struct Var {
    pub name: &'static str,
    pub class: Class,
    /// One line: what it does. Kept short enough to print in a run header.
    pub what: &'static str,
}

const fn cfg(name: &'static str, what: &'static str) -> Var {
    Var { name, class: Class::Config, what }
}
const fn dbg_(name: &'static str, what: &'static str) -> Var {
    Var { name, class: Class::DebugBisect, what }
}

/// **The classification table.** Every `NDN_*` read from library source across ndn-rs, ndn-ext and
/// ndn-radio-drivers, swept 2026-08-11.
///
/// The `NDN_RADIO_*` block is large because the Realtek bring-up was bisected register block by
/// register block — that is the documented driver-porting method, and each switch is one step of it.
/// They are legitimately debug, and legitimately *not* things a deployment should ever set.
pub const KNOWN: &[Var] = &[
    // ---- scheduler / MAC (the surface every on-air measurement is configured through) ----
    cfg("NDN_SCHED_SLOT", "slot schedule: <slots> (derive width) or <slots>:<slot_us>"),
    cfg("NDN_SCHED_HOP", "FHSS schedule: ch,ch,...:dwell_us"),
    cfg("NDN_SCHED_CLOCK", "clock source: wall | cv | hw — also sets the slot guard band"),
    cfg("NDN_SCHED_MASTER", "this node broadcasts the time beacon"),
    cfg("NDN_SCHED_NODE_ID", "id for the network-reference election (lowest wins)"),
    cfg("NDN_SCHED_GROUP_DEPTH", "name components hashed into a scheduling group"),
    cfg("NDN_SCHED_CLAIM", "enable claiming an idle slot (CCLF election)"),
    cfg("NDN_SCHED_LEASE", "max base slots one lease may hold (#93); 1 = the measured single-slot hold"),
    cfg("NDN_SCHED_RESERVE", "reserve every Nth slot as a latency lane (#93); 0 = none, the measured default"),
    dbg_("NDN_SCHED_CLAIM_UNKNOWN", "claim slots whose owner was never heard — DEFEATS #94's hidden-terminal guard"),
    // ---- face / link ----
    cfg("NDN_NAME", "face name prefix"),
    cfg("NDN_PORT", "unicast port"),
    cfg("NDN_MULTICAST_V4", "multicast group"),
    cfg("NDN_MULTICAST_PORT", "multicast port"),
    cfg("NDN_ETHERTYPE", "ethertype for the ether face"),
    cfg("NDN_ETHER_MCAST_MAC", "ether multicast destination"),
    cfg("NDN_PACKET_SIZE", "link MTU"),
    cfg("NDN_DEFAULT_SEGMENT_SIZE", "producer segment size"),
    cfg("NDN_SHM", "shared-memory face path"),
    cfg("NDN_BCST", "broadcast mode"),
    cfg("NDN_FLOG", "log file"),
    // ---- radio selection / rate / power (operational) ----
    cfg("NDN_USB_INDEX", "which USB radio to open when several share a host"),
    cfg("NDN_RADIO_TX_RATE", "TX rate code (4 = legacy 6M, the broadcast-safe choice)"),
    cfg("NDN_RADIO_TXPWR", "TX power index"),
    cfg("NDN_TX_PWR", "TX power (LoRa)"),
    cfg("NDN_RADIO_LDPC", "enable LDPC FEC"),
    cfg("NDN_RADIO_STBC", "enable space-time block coding"),
    cfg("NDN_RADIO_FIXEDRATE", "pin the rate rather than adapt"),
    cfg("NDN_RADIO_IBSS", "IBSS mode"),
    cfg("NDN_RADIO_STA", "station mode"),
    cfg("NDN_NAVUSEHDR", "honour the Duration/NAV field from the injected header (#96: not honoured by stock 802.11)"),
    cfg("NDN_LORA_CHANNEL", "LoRa channel — 78 (928 MHz) avoids the HaLow co-band collapse"),
    cfg("NDN_LORA_SF", "LoRa spreading factor"),
    cfg("NDN_LORA_BW", "LoRa bandwidth"),
    cfg("NDN_LORA_POWER", "LoRa TX power"),
    cfg("NDN_LORA_CR", "LoRa coding rate"),
    cfg("NDN_HALOW_CHANNEL", "HaLow S1G channel"),
    cfg("NDN_HALOW_BW", "HaLow bandwidth (1/2/4/8 MHz)"),
    cfg("NDN_HALOW_MCS", "HaLow MCS"),
    cfg("NDN_HALOW_POWER", "HaLow TX power"),
    cfg("NDN_CAD_ON", "LoRa carrier-activity-detect LBT (measured: hurts at N=2)"),
    cfg("NDN_NODE_ID", "node identity for reports"),
    // ---- debug-bisect: driver bring-up ----
    dbg_("NDN_NO_PUMP", "disable the shared RX pump — starves RX to free USB bandwidth for TX"),
    dbg_("NDN_ASYNC_PUMP", "switch the RX pump to async transfers"),
    dbg_("NDN_RX_PUMP_DEPTH", "in-flight RX transfer depth"),
    dbg_("NDN_RX_AGG_OFF", "disable RX aggregation"),
    dbg_("NDN_RX_AGG_DBG", "log RX aggregation"),
    dbg_("NDN_RX_META_DBG", "log RX metadata parsing"),
    dbg_("NDN_RXDMA_AGG", "RX DMA aggregation tuning"),
    dbg_("NDN_CCA_OFF", "disable clear-channel assessment — makes the radio a blaster"),
    dbg_("NDN_RADIO_PROBE", "probe and report chip identity only"),
    dbg_("NDN_RADIO_MINIMAL", "minimal bring-up — skip most init blocks"),
    dbg_("NDN_RADIO_SKIP_CAL", "skip IQ/RF calibration"),
    dbg_("NDN_RADIO_NO_RESET", "do not reset the MAC on open"),
    dbg_("NDN_RADIO_NO_EFEM", "skip external front-end module setup"),
    dbg_("NDN_RADIO_NO_RXCFG", "skip RX configuration"),
    dbg_("NDN_RADIO_NO_STA", "skip station-mode registers"),
    dbg_("NDN_RADIO_NO_STAREGS", "skip the station register block"),
    dbg_("NDN_RADIO_NO_TXEN", "do not enable TX"),
    dbg_("NDN_RADIO_STAREGS", "force the station register block"),
    dbg_("NDN_RADIO_FORCE_FW", "force a firmware download over a running MCU (wedges the chip)"),
    dbg_("NDN_RADIO_FORCE_8822E", "treat the part as an 8822E"),
    dbg_("NDN_RADIO_CLEAR_HALT", "clear USB endpoint halt"),
    dbg_("NDN_RADIO_EP", "override the USB endpoint"),
    dbg_("NDN_RADIO_EP_DEBUG", "log endpoint selection"),
    dbg_("NDN_RADIO_QSEL", "override the TX queue select"),
    dbg_("NDN_RADIO_HMEBOX_H2C", "host-to-chip mailbox debugging"),
    dbg_("NDN_RADIO_MCU_DEBUG", "log MCU interactions"),
    dbg_("NDN_RADIO_MCU_RESP_MS", "MCU response timeout"),
    dbg_("NDN_RADIO_KERNEL_PHYDM", "use the kernel's phydm behaviour"),
    dbg_("NDN_RADIO_LOG_WRITES", "log every register write"),
    dbg_("NDN_RADIO_RX_DEBUG", "log RX path"),
    dbg_("NDN_RADIO_BTC38", "Bluetooth-coexistence register 38"),
    dbg_("NDN_RADIO_BTG", "Bluetooth-coexistence grant"),
    dbg_("NDN_RADIO_WLG", "WLAN grant"),
    dbg_("NDN_DCNLA_NOCBSSID", "disable BSSID matching"),
    dbg_("NDN_TXPWR_DBG", "log TX power writes"),
    dbg_("NDN_TONE_1T", "single-tone TX test, one chain"),
    dbg_("NDN_TONE_GAIN", "single-tone test gain"),
    dbg_("NDN_FW_ILM_PATCH", "firmware ILM patching"),
    dbg_("NDN_FW_PGCNT", "firmware page count"),
    dbg_("NDN_SMOKE", "smoke-test mode"),
    dbg_("NDN_SKIP", "skip a bring-up stage"),
    dbg_("NDN_TAG", "tag frames for a bisect run"),
];

/// One `NDN_*` variable found set in the environment.
#[derive(Clone, Debug)]
pub struct Active {
    pub name: String,
    pub value: String,
    pub class: Class,
    pub what: &'static str,
}

/// **Every `NDN_*` currently set**, classified — the line a run should print about itself.
///
/// Reads the process environment rather than instrumenting call sites, so nothing set can escape it
/// and an unknown name is reported as [`Class::Unrecognised`] instead of failing silently.
pub fn snapshot() -> Vec<Active> {
    let table: BTreeMap<&str, &Var> = KNOWN.iter().map(|v| (v.name, v)).collect();
    let mut out: Vec<Active> = std::env::vars()
        .filter(|(k, _)| k.starts_with("NDN_"))
        .map(|(k, v)| match table.get(k.as_str()) {
            Some(known) => {
                Active { name: k, value: v, class: known.class, what: known.what }
            }
            None => Active {
                name: k,
                value: v,
                class: Class::Unrecognised,
                what: "not in the classification table — check for a typo, it may be doing nothing",
            },
        })
        .collect();
    // Debug switches first: they are the ones that invalidate a measurement.
    out.sort_by(|a, b| a.class.cmp(&b.class).then(a.name.cmp(&b.name)).reverse());
    out
}

/// A one-line-per-variable report for a run header, plus a warning when anything that could confound
/// a measurement is set. Empty string when no `NDN_*` is set at all.
pub fn describe() -> String {
    let active = snapshot();
    if active.is_empty() {
        return String::new();
    }
    let mut s = String::from("NDN_* environment:\n");
    for a in &active {
        let tag = match a.class {
            Class::Config => "config",
            Class::DebugBisect => "DEBUG",
            Class::Unrecognised => "UNRECOGNISED",
        };
        s.push_str(&format!("  [{tag}] {}={} — {}\n", a.name, a.value, a.what));
    }
    let bad = active.iter().filter(|a| a.class != Class::Config).count();
    if bad > 0 {
        s.push_str(&format!(
            "  !! {bad} debug/unrecognised variable(s) set. Debug switches disable parts of the \
             system under test, and an unrecognised name is doing nothing at all — neither belongs \
             in a run whose numbers you intend to trust.\n"
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Env is process-global; these tests mutate it, so they must not run concurrently. Without
    /// this they pass today only because their assertions happen not to overlap — a flaky test is
    /// worse than none.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// **A typo must be visible.** The failure this module exists for: `NDN_SCHED_CLAM=1` sets
    /// nothing, changes nothing, and looks exactly like a correctly-configured run — which is how a
    /// measurement gets reported under a configuration it never had.
    #[test]
    fn an_unrecognised_variable_is_reported_not_ignored() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: single-threaded test process; set/remove around the assertion.
        unsafe {
            std::env::set_var("NDN_SCHED_CLAM", "1");
            std::env::set_var("NDN_SCHED_SLOT", "8");
        }
        let snap = snapshot();
        let typo = snap.iter().find(|a| a.name == "NDN_SCHED_CLAM").expect("the typo is reported");
        assert_eq!(typo.class, Class::Unrecognised, "a name matching nothing must not pass as config");
        let real = snap.iter().find(|a| a.name == "NDN_SCHED_SLOT").expect("the real one too");
        assert_eq!(real.class, Class::Config);

        let text = describe();
        assert!(text.contains("UNRECOGNISED"), "and it must be visible in the run header:\n{text}");
        assert!(text.contains("!!"), "with the warning that the run is not what it claims");
        unsafe {
            std::env::remove_var("NDN_SCHED_CLAM");
            std::env::remove_var("NDN_SCHED_SLOT");
        }
    }

    /// A debug-bisect switch set during a measurement is a confounder, and must be called out
    /// rather than listed alongside ordinary config. `NDN_SCHED_CLAIM_UNKNOWN` is the concrete
    /// case: it defeats #94's hidden-terminal guard, and it produced a 4x throughput figure that
    /// took a two-day campaign to understand.
    #[test]
    fn a_debug_switch_is_flagged_as_a_confounder() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("NDN_SCHED_CLAIM_UNKNOWN", "1") };
        let text = describe();
        assert!(text.contains("[DEBUG]"), "debug switches must be labelled:\n{text}");
        assert!(text.contains("!!"), "and warned about:\n{text}");
        unsafe { std::env::remove_var("NDN_SCHED_CLAIM_UNKNOWN") };
    }

    /// The table is the split #81 asked for; guard against it silently emptying, and against a
    /// duplicate entry making one classification shadow another.
    #[test]
    fn the_table_is_populated_and_free_of_duplicates() {
        assert!(KNOWN.len() > 60, "the swept surface was ~70 library-read vars");
        let mut names: Vec<&str> = KNOWN.iter().map(|v| v.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "a duplicated name would shadow one classification");
        assert!(
            KNOWN.iter().any(|v| v.class == Class::Config)
                && KNOWN.iter().any(|v| v.class == Class::DebugBisect),
            "both halves of the split must be represented"
        );
    }
}
