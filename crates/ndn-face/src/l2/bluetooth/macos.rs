//! macOS BLE GATT server via CoreBluetooth (`CBPeripheralManager`).
//!
//! All CoreBluetooth calls and delegate callbacks run on a single GCD serial
//! queue created at [`bind`] time, so [`MacosShared`] is single-threaded from
//! CoreBluetooth's view. The tokio side talks to that queue via an unbounded
//! RX channel (delegate → tokio) and a bounded TX channel that dispatches each
//! send via `dispatch_async_f`.
//!
//! At most one `BleFace` per process: the shared state lives in a global
//! `AtomicUsize` and a second `bind` will panic.

#![allow(unsafe_op_in_unsafe_fn, non_snake_case, clippy::missing_safety_doc)]

use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use objc2::runtime::{AnyClass, AnyObject, ClassBuilder, Sel};
use objc2::{msg_send, sel};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use ndn_packet::fragment::FRAG_OVERHEAD;

use super::{
    BLE_CS_CHAR_UUID, BLE_FRAMING_CHAR_UUID, BLE_SC_CHAR_UUID, BLE_SERVICE_UUID, BleError,
    BleFraming, NdntsReassembler, PendingCentral, TxItem,
};

type DispatchQueue = *mut c_void;

unsafe extern "C" {
    fn dispatch_queue_create(label: *const i8, attr: *const c_void) -> DispatchQueue;
    fn dispatch_release(obj: *mut c_void);
    fn dispatch_async_f(
        queue: DispatchQueue,
        ctx: *mut c_void,
        f: unsafe extern "C" fn(*mut c_void),
    );
}

#[link(name = "CoreBluetooth", kind = "framework")]
unsafe extern "C" {
    static CBAdvertisementDataServiceUUIDsKey: *const AnyObject;
    static CBAdvertisementDataLocalNameKey: *const AnyObject;
}

/// Per-connected-central state, keyed by `CBCentral.identifier` in
/// [`MacosShared::centrals`].
struct CentralEntry {
    /// Retained `CBCentral *`; `maximumUpdateValueLength` and targeted notify
    /// (`onSubscribedCentrals:`) need it. Null until the central subscribes.
    central: *mut AnyObject,
    /// Inbound packets from this central → the per-central face.
    in_tx: mpsc::UnboundedSender<Bytes>,
    /// Latched on the first inbound write; the peripheral mirrors it on TX.
    framing: Option<BleFraming>,
    /// NDNts reassembly state (unused for the NDNLPv2 framing).
    reasm: NdntsReassembler,
    /// Fragments not yet accepted by CoreBluetooth (`updateValue` returned
    /// false); flushed on `peripheralManagerIsReadyToUpdateSubscribers:`.
    pending_tx: VecDeque<Bytes>,
}

struct MacosShared {
    /// Retained `CBPeripheralManager *`; touch only from `ble_queue`.
    manager: *mut AnyObject,
    /// Retained `CBMutableCharacteristic *` for the SC (server→client) notify.
    sc_char: *mut AnyObject,
    /// One entry per connected central, keyed by `CBCentral.identifier`.
    centrals: HashMap<String, CentralEntry>,
    /// Advertised local name.
    local_name: String,
    /// Announces a newly connected central to the listener's accept loop.
    new_central_tx: mpsc::UnboundedSender<PendingCentral>,
    /// Outbound endpoint cloned into each `PendingCentral` (face → TX pump).
    tx_sender: mpsc::UnboundedSender<TxItem>,
}

// SAFETY: accessed only from the serial `ble_queue` after setup completes.
unsafe impl Send for MacosShared {}

static MACOS_SHARED: AtomicUsize = AtomicUsize::new(0);

/// Panics if a `BleFace` is already active in this process.
fn install_shared(shared: Box<MacosShared>) -> *mut MacosShared {
    let raw = Box::into_raw(shared);
    let prev = MACOS_SHARED.compare_exchange(0, raw as usize, Ordering::AcqRel, Ordering::Acquire);
    assert!(
        prev.is_ok(),
        "only one BleFace per process is supported on macOS"
    );
    raw
}

/// # Safety
/// Must only be called from within the `ble_queue` serial GCD queue.
unsafe fn shared_ref<'a>() -> &'a mut MacosShared {
    let raw = MACOS_SHARED.load(Ordering::Acquire) as *mut MacosShared;
    debug_assert!(!raw.is_null(), "MacosShared accessed after BleFace dropped");
    &mut *raw
}

const CB_MANAGER_STATE_POWERED_ON: i64 = 5;

const CB_PROP_READ: usize = 0x02;
const CB_PROP_NOTIFY: usize = 0x10;
const CB_PROP_WRITE_NO_RESP: usize = 0x04;
const CB_PERM_READABLE: usize = 0x01;
const CB_PERM_WRITABLE: usize = 0x02;

pub struct BleServer {
    manager: *mut AnyObject,
    delegate: *mut AnyObject,
    ble_queue: DispatchQueue,
}

impl BleServer {
    /// CoreBluetooth doesn't expose the local adapter address; report a stable
    /// placeholder for the face's `local_uri`.
    pub fn local_addr(&self) -> &str {
        "local"
    }
}

// SAFETY: ObjC retain/release is thread-safe; we never deref outside ble_queue.
unsafe impl Send for BleServer {}
unsafe impl Sync for BleServer {}

impl Drop for BleServer {
    fn drop(&mut self) {
        let raw = MACOS_SHARED.swap(0, Ordering::AcqRel) as *mut MacosShared;
        if !raw.is_null() {
            drop(unsafe { Box::from_raw(raw) });
        }
        unsafe {
            if !self.manager.is_null() {
                let _: () = msg_send![self.manager, release];
            }
            if !self.delegate.is_null() {
                let _: () = msg_send![self.delegate, release];
            }
            dispatch_release(self.ble_queue);
        }
    }
}

fn delegate_class() -> &'static AnyClass {
    static CELL: std::sync::OnceLock<&'static AnyClass> = std::sync::OnceLock::new();
    CELL.get_or_init(|| {
        let superclass = AnyClass::get("NSObject").expect("NSObject class not found");
        let mut builder =
            ClassBuilder::new("NdnRsBleDelegate", superclass).expect("class already registered");

        unsafe {
            type Ptr = *mut AnyObject;
            builder.add_method(
                sel!(peripheralManagerDidUpdateState:),
                cb_did_update_state as unsafe extern "C" fn(Ptr, Sel, Ptr),
            );
            builder.add_method(
                sel!(peripheralManager:didAddService:error:),
                cb_did_add_service as unsafe extern "C" fn(Ptr, Sel, Ptr, Ptr, Ptr),
            );
            builder.add_method(
                sel!(peripheralManager:central:didSubscribeToCharacteristic:),
                cb_did_subscribe as unsafe extern "C" fn(Ptr, Sel, Ptr, Ptr, Ptr),
            );
            builder.add_method(
                sel!(peripheralManager:central:didUnsubscribeFromCharacteristic:),
                cb_did_unsubscribe as unsafe extern "C" fn(Ptr, Sel, Ptr, Ptr, Ptr),
            );
            builder.add_method(
                sel!(peripheralManager:didReceiveWriteRequests:),
                cb_did_receive_writes as unsafe extern "C" fn(Ptr, Sel, Ptr, Ptr),
            );
            builder.add_method(
                sel!(peripheralManagerIsReadyToUpdateSubscribers:),
                cb_ready_to_update as unsafe extern "C" fn(Ptr, Sel, Ptr),
            );
        }

        builder.register()
    })
}

unsafe extern "C" fn cb_did_update_state(
    _this: *mut AnyObject,
    _sel: Sel,
    manager: *mut AnyObject,
) {
    let state: i64 = msg_send![manager, state];
    debug!(target: "face.system", state, "BLE/macOS: peripheral manager state changed");
    if state != CB_MANAGER_STATE_POWERED_ON {
        return;
    }
    info!(target: "face.system", "BLE/macOS: adapter powered on — registering NDN GATT service");

    let svc = create_ndn_service();
    let _: () = msg_send![manager, addService: svc];
    let _: () = msg_send![svc, release];
}

unsafe extern "C" fn cb_did_add_service(
    _this: *mut AnyObject,
    _sel: Sel,
    manager: *mut AnyObject,
    _service: *mut AnyObject,
    error: *mut AnyObject,
) {
    if !error.is_null() {
        let desc: *mut AnyObject = msg_send![error, localizedDescription];
        warn!(target: "face.system", "BLE/macOS: addService error — {}", nsstring_to_rust(desc));
        return;
    }
    start_advertising(manager);
}

/// `CBCentral.identifier.UUIDString` — the per-central registry key.
unsafe fn central_identifier(central: *mut AnyObject) -> String {
    let nsuuid: *mut AnyObject = msg_send![central, identifier];
    let s: *mut AnyObject = msg_send![nsuuid, UUIDString];
    nsstring_to_rust(s)
}

/// Look up the entry for `key`, creating it (and announcing a new
/// `PendingCentral` to the listener) on first contact. Must run on `ble_queue`.
unsafe fn entry_for<'a>(shared: &'a mut MacosShared, key: &str) -> &'a mut CentralEntry {
    if !shared.centrals.contains_key(key) {
        let (in_tx, in_rx) = mpsc::unbounded_channel::<Bytes>();
        shared.centrals.insert(
            key.to_owned(),
            CentralEntry {
                central: std::ptr::null_mut(),
                in_tx,
                framing: None,
                reasm: NdntsReassembler::new(),
                pending_tx: VecDeque::new(),
            },
        );
        let _ = shared.new_central_tx.send(PendingCentral {
            key: key.to_owned(),
            peer_uri: format!("ble://{key}"),
            in_rx,
            tx: shared.tx_sender.clone(),
        });
        debug!(target: "face.system", %key, "BLE/macOS: new central");
    }
    shared.centrals.get_mut(key).unwrap()
}

unsafe extern "C" fn cb_did_subscribe(
    _this: *mut AnyObject,
    _sel: Sel,
    _manager: *mut AnyObject,
    central: *mut AnyObject,
    characteristic: *mut AnyObject,
) {
    let uuid = char_uuid_string(characteristic);
    if uuid.eq_ignore_ascii_case(BLE_SC_CHAR_UUID) {
        let key = central_identifier(central);
        let shared = shared_ref();
        let entry = entry_for(shared, &key);
        if entry.central != central {
            if !entry.central.is_null() {
                let _: () = msg_send![entry.central, release];
            }
            let _: () = msg_send![central, retain];
            entry.central = central;
        }
        let mtu: usize = msg_send![central, maximumUpdateValueLength];
        debug!(target: "face.system", %key, mtu, "BLE/macOS: SC subscribed");
    }
}

unsafe extern "C" fn cb_did_unsubscribe(
    _this: *mut AnyObject,
    _sel: Sel,
    _manager: *mut AnyObject,
    central: *mut AnyObject,
    characteristic: *mut AnyObject,
) {
    let uuid = char_uuid_string(characteristic);
    if uuid.eq_ignore_ascii_case(BLE_SC_CHAR_UUID) {
        let key = central_identifier(central);
        let shared = shared_ref();
        // Dropping the entry closes its `in_tx`, ending the face's `recv`.
        if let Some(entry) = shared.centrals.remove(&key)
            && !entry.central.is_null()
        {
            let _: () = msg_send![entry.central, release];
        }
        debug!(target: "face.system", %key, "BLE/macOS: SC unsubscribed (face closed)");
    }
}

/// Each write carries one LpPacket (whole or fragment); NDNLPv2 reassembly
/// happens in the pipeline's per-face ReassemblyBuffer.
unsafe extern "C" fn cb_did_receive_writes(
    _this: *mut AnyObject,
    _sel: Sel,
    _manager: *mut AnyObject,
    requests: *mut AnyObject,
) {
    let shared = shared_ref();
    let count: usize = msg_send![requests, count];
    for i in 0..count {
        let req: *mut AnyObject = msg_send![requests, objectAtIndex: i];
        let central: *mut AnyObject = msg_send![req, central];
        let ns_data: *mut AnyObject = msg_send![req, value];
        if central.is_null() || ns_data.is_null() {
            continue;
        }
        let bytes_ptr: *const u8 = msg_send![ns_data, bytes];
        let len: usize = msg_send![ns_data, length];
        if bytes_ptr.is_null() || len == 0 {
            continue;
        }
        let raw = std::slice::from_raw_parts(bytes_ptr, len);
        let key = central_identifier(central);
        let entry = entry_for(shared, &key);
        // Latch framing from the first inbound write, then mirror it on TX.
        let framing = *entry.framing.get_or_insert_with(|| BleFraming::detect(raw));
        match framing {
            // NDNLPv2: forward raw; the pipeline's ReassemblyBuffer handles it.
            BleFraming::Ndnlpv2 => {
                let _ = entry.in_tx.send(Bytes::copy_from_slice(raw));
            }
            // NDNts: reassemble 1-byte-header fragments into whole packets.
            BleFraming::Ndnts => {
                if let Some(pkt) = entry.reasm.feed(raw) {
                    let _ = entry.in_tx.send(pkt);
                }
            }
        }
    }
}

unsafe extern "C" fn cb_ready_to_update(
    _this: *mut AnyObject,
    _sel: Sel,
    _manager: *mut AnyObject,
) {
    debug!(target: "face.system", "BLE/macOS: TX queue ready; flushing buffered fragments");
    let shared = shared_ref();
    let keys: Vec<String> = shared.centrals.keys().cloned().collect();
    for key in keys {
        flush_central(shared, &key);
    }
}

/// Returns the service with retain count +1.
unsafe fn create_ndn_service() -> *mut AnyObject {
    let sc_char = create_char(BLE_SC_CHAR_UUID, CB_PROP_NOTIFY, 0, std::ptr::null_mut());
    let cs_char = create_char(
        BLE_CS_CHAR_UUID,
        CB_PROP_WRITE_NO_RESP,
        CB_PERM_WRITABLE,
        std::ptr::null_mut(),
    );
    // Capability characteristic: a static-value read. CoreBluetooth serves a
    // cached value (non-nil `value:` + read-only) without a read-request
    // callback. Value = our framing's capability byte (NDNLPv2).
    let cap_value = make_nsdata(&[BleFraming::Ndnlpv2.capability_byte()]);
    let framing_char = create_char(
        BLE_FRAMING_CHAR_UUID,
        CB_PROP_READ,
        CB_PERM_READABLE,
        cap_value,
    );
    let _: () = msg_send![cap_value, release];

    shared_ref().sc_char = sc_char;

    let svc_class = AnyClass::get("CBMutableService").expect("CBMutableService not found");
    let svc_uuid = make_cbuuid(BLE_SERVICE_UUID);
    let svc_alloc: *mut AnyObject = msg_send![svc_class, alloc];
    let svc: *mut AnyObject = msg_send![svc_alloc, initWithType: svc_uuid, primary: true as u8];
    let _: () = msg_send![svc_uuid, release];

    let arr_class = AnyClass::get("NSArray").expect("NSArray not found");
    let chars_ptrs: [*mut AnyObject; 3] = [sc_char, cs_char, framing_char];
    let chars: *mut AnyObject =
        msg_send![arr_class, arrayWithObjects: chars_ptrs.as_ptr(), count: 3usize];
    let _: () = msg_send![svc, setCharacteristics: chars];

    let _: () = msg_send![cs_char, release];
    let _: () = msg_send![framing_char, release];

    svc
}

/// Returns +1 retained pointer. `value` (may be null) becomes the cached
/// characteristic value for static reads.
unsafe fn create_char(
    uuid_str: &str,
    properties: usize,
    permissions: usize,
    value: *mut AnyObject,
) -> *mut AnyObject {
    let char_class =
        AnyClass::get("CBMutableCharacteristic").expect("CBMutableCharacteristic not found");
    let uuid = make_cbuuid(uuid_str);
    let alloc: *mut AnyObject = msg_send![char_class, alloc];
    let ch: *mut AnyObject = msg_send![
        alloc,
        initWithType: uuid,
        properties: properties,
        value: value,
        permissions: permissions
    ];
    let _: () = msg_send![uuid, release];
    ch
}

/// Returns +1 retained pointer.
unsafe fn make_cbuuid(uuid_str: &str) -> *mut AnyObject {
    let cbuuid_class = AnyClass::get("CBUUID").expect("CBUUID not found");
    let ns_str = make_nsstring(uuid_str);
    let uuid: *mut AnyObject = msg_send![cbuuid_class, UUIDWithString: ns_str];
    let _: () = msg_send![ns_str, release];
    let _: () = msg_send![uuid, retain];
    uuid
}

/// Returns +1 retained pointer.
unsafe fn make_nsstring(s: &str) -> *mut AnyObject {
    let cls = AnyClass::get("NSString").expect("NSString not found");
    let alloc: *mut AnyObject = msg_send![cls, alloc];
    // NSUTF8StringEncoding = 4
    msg_send![
        alloc,
        initWithBytes: s.as_ptr() as *const c_void,
        length: s.len(),
        encoding: 4usize
    ]
}

unsafe fn char_uuid_string(characteristic: *mut AnyObject) -> String {
    let uuid: *mut AnyObject = msg_send![characteristic, UUID];
    let uuid_str: *mut AnyObject = msg_send![uuid, UUIDString];
    nsstring_to_rust(uuid_str)
}

unsafe fn nsstring_to_rust(ns: *mut AnyObject) -> String {
    if ns.is_null() {
        return String::new();
    }
    let utf8: *const i8 = msg_send![ns, UTF8String];
    if utf8.is_null() {
        return String::new();
    }
    std::ffi::CStr::from_ptr(utf8)
        .to_string_lossy()
        .into_owned()
}

unsafe fn start_advertising(manager: *mut AnyObject) {
    let svc_uuid = make_cbuuid(BLE_SERVICE_UUID);
    let arr_class = AnyClass::get("NSArray").expect("NSArray not found");
    let svc_uuid_ptrs: [*mut AnyObject; 1] = [svc_uuid];
    let svc_uuid_array: *mut AnyObject =
        msg_send![arr_class, arrayWithObjects: svc_uuid_ptrs.as_ptr(), count: 1usize];

    let local_name = make_nsstring(&shared_ref().local_name);
    let keys: [*const AnyObject; 2] = [
        CBAdvertisementDataServiceUUIDsKey,
        CBAdvertisementDataLocalNameKey,
    ];
    let vals: [*mut AnyObject; 2] = [svc_uuid_array, local_name];
    let dict_class = AnyClass::get("NSDictionary").expect("NSDictionary not found");
    let adv_data: *mut AnyObject = msg_send![
        dict_class,
        dictionaryWithObjects: vals.as_ptr(),
        forKeys: keys.as_ptr(),
        count: 2usize
    ];

    let _: () = msg_send![manager, startAdvertising: adv_data];

    let _: () = msg_send![svc_uuid, release];
    let _: () = msg_send![local_name, release];
    info!(target: "face.system", "BLE/macOS: advertising started");
}

struct TxWork {
    shared_ptr: *mut MacosShared,
    key: String,
    pkt: Bytes,
    frag_seq: u64,
}
unsafe impl Send for TxWork {}

unsafe extern "C" fn do_tx_work(ctx: *mut c_void) {
    let work = Box::from_raw(ctx as *mut TxWork);
    let shared = &mut *work.shared_ptr;

    let (central, framing) = match shared.centrals.get(&work.key) {
        Some(e) if !e.central.is_null() => (e.central, e.framing.unwrap_or_default()),
        // Central gone or not yet subscribed — drop (no notify target).
        _ => return,
    };

    // `maximumUpdateValueLength` already excludes the 3-byte ATT header, so
    // it's the usable payload size directly. Lives on `CBCentral`, not the
    // manager — sending to the manager raises NSInvalidArgumentException.
    let ble_mtu: usize = msg_send![central, maximumUpdateValueLength];
    if ble_mtu <= FRAG_OVERHEAD {
        warn!(
            target: "face.system",
            ble_mtu,
            needed = FRAG_OVERHEAD + 1,
            "BLE/macOS: ATT MTU too small for NDNLPv2 fragmentation, dropping packet"
        );
        return;
    }

    let mut seq = work.frag_seq;
    let frags = framing.frame(&work.pkt, ble_mtu, &mut seq);
    if let Some(entry) = shared.centrals.get_mut(&work.key) {
        entry.pending_tx.extend(frags);
    }
    flush_central(shared, &work.key);
}

/// Send as many of a central's queued fragments as CoreBluetooth will accept.
/// On a full TX queue (`updateValue` returns false) the remainder stays queued
/// and is retried from [`cb_ready_to_update`].
unsafe fn flush_central(shared: &mut MacosShared, key: &str) {
    let manager = shared.manager;
    let sc_char = shared.sc_char;
    if manager.is_null() || sc_char.is_null() {
        return;
    }
    let Some(entry) = shared.centrals.get_mut(key) else {
        return;
    };
    if entry.central.is_null() {
        return;
    }
    let arr_class = AnyClass::get("NSArray").expect("NSArray not found");
    let central_ptrs: [*mut AnyObject; 1] = [entry.central];
    let centrals_arr: *mut AnyObject =
        msg_send![arr_class, arrayWithObjects: central_ptrs.as_ptr(), count: 1usize];

    while let Some(frag) = entry.pending_tx.front() {
        let ns_data = make_nsdata(frag);
        let ok: bool = msg_send![
            manager,
            updateValue: ns_data,
            forCharacteristic: sc_char,
            onSubscribedCentrals: centrals_arr
        ];
        let _: () = msg_send![ns_data, release];
        if ok {
            entry.pending_tx.pop_front();
        } else {
            break; // queue full — wait for the ready callback
        }
    }
}

/// Returns +1 retained pointer. Uses `alloc + initWithBytes:length:` rather
/// than the class-side `dataWithBytes:length:` convenience constructor, which
/// returns autoreleased — explicit `release` on an autoreleased pointer
/// over-releases and segfaults when the autorelease pool drains.
unsafe fn make_nsdata(bytes: &[u8]) -> *mut AnyObject {
    let cls = AnyClass::get("NSData").expect("NSData not found");
    let alloc: *mut AnyObject = msg_send![cls, alloc];
    msg_send![
        alloc,
        initWithBytes: bytes.as_ptr() as *const c_void,
        length: bytes.len()
    ]
}

pub async fn bind(
    adapter: Option<&str>,
    local_name: Option<&str>,
) -> Result<(Arc<BleServer>, mpsc::UnboundedReceiver<PendingCentral>), BleError> {
    if let Some(a) = adapter {
        debug!(target: "face.system", adapter = a, "BLE/macOS: adapter selection ignored (CoreBluetooth uses the system adapter)");
    }
    let local_name = local_name.unwrap_or("ndn-rs").to_owned();
    let (new_central_tx, new_central_rx) = mpsc::unbounded_channel::<PendingCentral>();
    let (tx_sender, mut tx_receiver) = mpsc::unbounded_channel::<TxItem>();

    let ble_queue: DispatchQueue =
        unsafe { dispatch_queue_create(c"ndn.ble.peripheral".as_ptr(), std::ptr::null()) };
    assert!(!ble_queue.is_null(), "failed to create BLE dispatch queue");

    let shared = Box::new(MacosShared {
        manager: std::ptr::null_mut(),
        sc_char: std::ptr::null_mut(),
        centrals: HashMap::new(),
        local_name,
        new_central_tx,
        tx_sender,
    });
    let shared_ptr = install_shared(shared);

    let (delegate, manager) = unsafe {
        let class = delegate_class();
        let delegate: *mut AnyObject = msg_send![class, new];

        let pm_class = AnyClass::get("CBPeripheralManager").expect("CBPeripheralManager not found");
        let pm_alloc: *mut AnyObject = msg_send![pm_class, alloc];
        let manager: *mut AnyObject = msg_send![
            pm_alloc,
            initWithDelegate: delegate,
            queue: ble_queue
        ];

        (*shared_ptr).manager = manager;

        (delegate, manager)
    };

    let server = Arc::new(BleServer {
        manager,
        delegate,
        ble_queue,
    });

    // Capture raw pointers as `usize` so the async block is `Send`. SAFETY:
    // deref happens only inside `do_tx_work` on the GCD queue.
    let queue_addr: usize = ble_queue as usize;
    let shared_addr: usize = shared_ptr as usize;
    tokio::spawn(async move {
        let mut frag_seq: u64 = 0;
        while let Some(item) = tx_receiver.recv().await {
            let queue = queue_addr as DispatchQueue;
            if queue.is_null() {
                break;
            }
            let sptr = shared_addr as *mut MacosShared;
            let seq = frag_seq;
            frag_seq = frag_seq.wrapping_add(1);
            let work = Box::new(TxWork {
                shared_ptr: sptr,
                key: item.key,
                pkt: item.pkt,
                frag_seq: seq,
            });
            unsafe {
                dispatch_async_f(queue, Box::into_raw(work) as *mut c_void, do_tx_work);
            }
        }
    });

    Ok((server, new_central_rx))
}
