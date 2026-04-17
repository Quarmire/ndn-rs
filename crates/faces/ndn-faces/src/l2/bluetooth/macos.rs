//! macOS BLE GATT server via CoreBluetooth (`CBPeripheralManager`).
//!
//! # Threading model
//!
//! CoreBluetooth requires all API calls to happen on a specific GCD serial
//! queue.  We create that queue at [`bind`] time and pass it to
//! `CBPeripheralManager`.  All delegate callbacks are invoked on the same
//! queue, keeping access to [`MacosShared`] single-threaded from
//! CoreBluetooth's perspective.
//!
//! The tokio world communicates with the CoreBluetooth queue via two channels:
//!
//! - **RX** (CoreBluetooth → tokio): delegate writes to an
//!   `UnboundedSender<Bytes>`; tokio receives with `UnboundedReceiver`.
//!   `UnboundedSender::send()` is synchronous, safe to call from a GCD thread.
//!
//! - **TX** (tokio → CoreBluetooth): a tokio task calls
//!   `dispatch_async_f(ble_queue, …)` for each outgoing packet; the dispatched
//!   closure calls `updateValue:forCharacteristic:onSubscribedCentrals:`.
//!
//! # Limitation
//!
//! At most **one `BleFace` per process**: the shared state is stored in a
//! process-wide `AtomicUsize`.  Creating a second `BleFace` while the first is
//! alive will panic at `bind` time.

// In Rust 2024, unsafe operations inside `unsafe fn` bodies still require an
// explicit `unsafe {}` block (unsafe_op_in_unsafe_fn deny-by-default).  This
// file is pure low-level FFI; suppressing the requirement here keeps the code
// readable without compromising safety (the # Safety docs on each function
// explain the actual invariants).
#![allow(unsafe_op_in_unsafe_fn, non_snake_case, clippy::missing_safety_doc)]

use std::ffi::c_void;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use objc2::runtime::{AnyClass, AnyObject, ClassBuilder, Sel};
use objc2::{msg_send, sel};
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, info, warn};

use ndn_packet::fragment::{FRAG_OVERHEAD, fragment_packet};
use ndn_packet::lp::{encode_lp_packet, is_lp_packet};

use super::{BLE_CS_CHAR_UUID, BLE_SC_CHAR_UUID, BLE_SERVICE_UUID, BleError, BleFace, CHAN_DEPTH};

/// ATT protocol overhead per write/notify (1-byte opcode + 2-byte handle).
const ATT_OVERHEAD: usize = 3;


// libdispatch is part of libSystem on macOS; no explicit link attribute needed.
type DispatchQueue = *mut c_void;

unsafe extern "C" {
    fn dispatch_queue_create(label: *const i8, attr: *const c_void) -> DispatchQueue;
    fn dispatch_release(obj: *mut c_void);
    fn dispatch_async_f(
        queue: DispatchQueue,
        ctx: *mut c_void,
        f: unsafe extern "C" fn(*mut c_void),
    );
    // CBAdvertisementData keys (extern NSString constants from CoreBluetooth.framework)
    static CBAdvertisementDataServiceUUIDsKey: *const AnyObject;
    static CBAdvertisementDataLocalNameKey: *const AnyObject;
}


struct MacosShared {
    /// Raw retained `CBPeripheralManager *` — only touch from `ble_queue`.
    manager: *mut AnyObject,
    /// Raw retained `CBMutableCharacteristic *` for the SC (server→client)
    /// notify characteristic.
    sc_char: *mut AnyObject,
    /// Whether a central is currently subscribed to the SC characteristic.
    subscribed: bool,
    /// Channel to send raw RX packets (LpPackets / LpPacket fragments) to
    /// the tokio side. The pipeline's `TlvDecodeStage` handles NDNLPv2
    /// reassembly via its per-face `ReassemblyBuffer` — no local assembler.
    rx_sender: mpsc::UnboundedSender<Bytes>,
}

// SAFETY: `MacosShared` is accessed exclusively from the serial `ble_queue`
// (plus the initial setup before CoreBluetooth is started).
unsafe impl Send for MacosShared {}

/// Process-wide singleton pointer to `Box<MacosShared>`.
/// Zero means no active BleFace; non-zero is the raw `*mut MacosShared`.
static MACOS_SHARED: AtomicUsize = AtomicUsize::new(0);

/// Store `Box<MacosShared>` in the global singleton, returning the raw pointer.
/// Panics if a BleFace is already active.
fn install_shared(shared: Box<MacosShared>) -> *mut MacosShared {
    let raw = Box::into_raw(shared);
    let prev = MACOS_SHARED.compare_exchange(0, raw as usize, Ordering::AcqRel, Ordering::Acquire);
    assert!(
        prev.is_ok(),
        "only one BleFace per process is supported on macOS"
    );
    raw
}

/// Retrieve a mutable reference to the shared state.
///
/// # Safety
/// Must only be called from within the `ble_queue` serial GCD queue.
unsafe fn shared_ref<'a>() -> &'a mut MacosShared {
    let raw = MACOS_SHARED.load(Ordering::Acquire) as *mut MacosShared;
    debug_assert!(!raw.is_null(), "MacosShared accessed after BleFace dropped");
    &mut *raw
}


/// `CBManagerStatePoweredOn` — the adapter is on and ready.
const CB_MANAGER_STATE_POWERED_ON: i64 = 5;

/// `CBCharacteristicPropertyNotify` (0x10).
const CB_PROP_NOTIFY: usize = 0x10;
/// `CBCharacteristicPropertyWriteWithoutResponse` (0x04).
const CB_PROP_WRITE_NO_RESP: usize = 0x04;
/// `CBAttributePermissionsWriteable` (0x02).
const CB_PERM_WRITABLE: usize = 0x02;


pub struct BleServer {
    /// Raw `CBPeripheralManager *` (retained +1).
    manager: *mut AnyObject,
    /// Raw retained delegate object; keeps delegate alive.
    delegate: *mut AnyObject,
    ble_queue: DispatchQueue,
}

// SAFETY: `BleServer` is dropped from the tokio thread, but all ObjC objects
// are reference-counted by the ObjC runtime which is thread-safe for
// retain/release.  We never dereference them outside the BLE queue.
unsafe impl Send for BleServer {}
unsafe impl Sync for BleServer {}

impl Drop for BleServer {
    fn drop(&mut self) {
        // Clear the global singleton and free the shared state.
        let raw = MACOS_SHARED.swap(0, Ordering::AcqRel) as *mut MacosShared;
        if !raw.is_null() {
            drop(unsafe { Box::from_raw(raw) });
        }
        // Release ObjC objects.
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
                sel!(peripheralManager:didAdd:error:),
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


/// Called when the Bluetooth adapter state changes.  We wait for PoweredOn,
/// then register the NDN GATT service.
unsafe extern "C" fn cb_did_update_state(
    _this: *mut AnyObject,
    _sel: Sel,
    manager: *mut AnyObject,
) {
    let state: i64 = msg_send![manager, state];
    debug!(state, "BLE/macOS: peripheral manager state changed");
    if state != CB_MANAGER_STATE_POWERED_ON {
        return;
    }
    info!("BLE/macOS: adapter powered on — registering NDN GATT service");

    let svc = create_ndn_service();
    let _: () = msg_send![manager, addService: svc];
    // Release — manager has retained the service.
    let _: () = msg_send![svc, release];
}

/// Called after `addService:` completes.  If successful, start advertising.
unsafe extern "C" fn cb_did_add_service(
    _this: *mut AnyObject,
    _sel: Sel,
    manager: *mut AnyObject,
    _service: *mut AnyObject,
    error: *mut AnyObject,
) {
    if !error.is_null() {
        let desc: *mut AnyObject = msg_send![error, localizedDescription];
        warn!("BLE/macOS: addService error — {:?}", desc);
        return;
    }
    start_advertising(manager);
}

/// A central subscribed to the SC (server→client) notify characteristic.
unsafe extern "C" fn cb_did_subscribe(
    _this: *mut AnyObject,
    _sel: Sel,
    _manager: *mut AnyObject,
    _central: *mut AnyObject,
    characteristic: *mut AnyObject,
) {
    let uuid = char_uuid_string(characteristic);
    if uuid.eq_ignore_ascii_case(BLE_SC_CHAR_UUID) {
        debug!("BLE/macOS: SC (server→client) subscribed");
        shared_ref().subscribed = true;
    }
}

/// A central unsubscribed from the SC (server→client) notify characteristic.
unsafe extern "C" fn cb_did_unsubscribe(
    _this: *mut AnyObject,
    _sel: Sel,
    _manager: *mut AnyObject,
    _central: *mut AnyObject,
    characteristic: *mut AnyObject,
) {
    let uuid = char_uuid_string(characteristic);
    if uuid.eq_ignore_ascii_case(BLE_SC_CHAR_UUID) {
        debug!("BLE/macOS: SC (server→client) unsubscribed");
        shared_ref().subscribed = false;
    }
}

/// Incoming Write Without Response on the CS (client→server) characteristic.
///
/// Each write carries exactly one LpPacket (whole or fragment); hand the raw
/// bytes up to the face recv channel and let the pipeline's `TlvDecodeStage`
/// handle NDNLPv2 reassembly via its per-face `ReassemblyBuffer`.
unsafe extern "C" fn cb_did_receive_writes(
    _this: *mut AnyObject,
    _sel: Sel,
    _manager: *mut AnyObject,
    requests: *mut AnyObject, // NSArray<CBATTRequest *>
) {
    let shared = shared_ref();
    let count: usize = msg_send![requests, count];
    for i in 0..count {
        let req: *mut AnyObject = msg_send![requests, objectAtIndex: i];
        let ns_data: *mut AnyObject = msg_send![req, value];
        if ns_data.is_null() {
            continue;
        }
        let bytes_ptr: *const u8 = msg_send![ns_data, bytes];
        let len: usize = msg_send![ns_data, length];
        if bytes_ptr.is_null() || len == 0 {
            continue;
        }
        let pkt = Bytes::copy_from_slice(std::slice::from_raw_parts(bytes_ptr, len));
        let _ = shared.rx_sender.send(pkt);
    }
}

/// CoreBluetooth calls this when the TX queue has space after a previous
/// `updateValue:` returned `false`.
unsafe extern "C" fn cb_ready_to_update(
    _this: *mut AnyObject,
    _sel: Sel,
    _manager: *mut AnyObject,
) {
    debug!("BLE/macOS: TX queue ready to accept more notifications");
    // TODO: drain any pending TX packets buffered during flow-control
}


/// Create the NDN GATT `CBMutableService` with its SC (notify) and CS (write)
/// characteristics. Returns a raw `CBMutableService *` with retain count +1
/// (caller must release).
unsafe fn create_ndn_service() -> *mut AnyObject {
    let sc_char = create_char(BLE_SC_CHAR_UUID, CB_PROP_NOTIFY, 0);
    let cs_char = create_char(BLE_CS_CHAR_UUID, CB_PROP_WRITE_NO_RESP, CB_PERM_WRITABLE);

    // Store the SC characteristic pointer in shared state for later use.
    // sc_char retain count is +1 from create_char; we keep that reference.
    shared_ref().sc_char = sc_char;

    let svc_class = AnyClass::get("CBMutableService").expect("CBMutableService not found");
    let svc_uuid = make_cbuuid(BLE_SERVICE_UUID);
    let svc_alloc: *mut AnyObject = msg_send![svc_class, alloc];
    let svc: *mut AnyObject = msg_send![svc_alloc, initWithType: svc_uuid, primary: true as u8];
    // Release the UUID (svc has retained it).
    let _: () = msg_send![svc_uuid, release];

    // characteristics = [sc_char, cs_char]
    let arr_class = AnyClass::get("NSArray").expect("NSArray not found");
    let chars_ptrs: [*mut AnyObject; 2] = [sc_char, cs_char];
    let chars: *mut AnyObject =
        msg_send![arr_class, arrayWithObjects: chars_ptrs.as_ptr(), count: 2usize];
    let _: () = msg_send![svc, setCharacteristics: chars];

    // Release temporary objects (NSArray has retained them).
    let _: () = msg_send![cs_char, release];
    // Keep sc_char alive via shared.sc_char (already retained once from create_char).

    svc // +1 retain; caller must release
}

/// Create a `CBMutableCharacteristic`.
/// Returns raw pointer with retain count +1 (caller must eventually release).
unsafe fn create_char(uuid_str: &str, properties: usize, permissions: usize) -> *mut AnyObject {
    let char_class =
        AnyClass::get("CBMutableCharacteristic").expect("CBMutableCharacteristic not found");
    let uuid = make_cbuuid(uuid_str);
    let alloc: *mut AnyObject = msg_send![char_class, alloc];
    let ch: *mut AnyObject = msg_send![
        alloc,
        initWithType: uuid,
        properties: properties,
        value: std::ptr::null_mut::<AnyObject>(),
        permissions: permissions
    ];
    let _: () = msg_send![uuid, release];
    ch // +1
}

/// Create a `CBUUID` from a UUID string.
/// Returns raw pointer with retain count +1 (caller must release).
unsafe fn make_cbuuid(uuid_str: &str) -> *mut AnyObject {
    let cbuuid_class = AnyClass::get("CBUUID").expect("CBUUID not found");
    let ns_str = make_nsstring(uuid_str);
    let uuid: *mut AnyObject = msg_send![cbuuid_class, UUIDWithString: ns_str];
    let _: () = msg_send![ns_str, release];
    // UUIDWithString: returns autoreleased; retain for our use.
    let _: () = msg_send![uuid, retain];
    uuid
}

/// Create an `NSString` from a Rust `&str`.
/// Returns raw pointer with retain count +1 (caller must release).
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

/// Return the `UUIDString` of a characteristic's UUID as a Rust `String`.
unsafe fn char_uuid_string(characteristic: *mut AnyObject) -> String {
    let uuid: *mut AnyObject = msg_send![characteristic, UUID];
    let uuid_str: *mut AnyObject = msg_send![uuid, UUIDString];
    nsstring_to_rust(uuid_str)
}

/// Convert an `NSString *` to a Rust `String`.
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

/// Build the advertising NSDictionary and call `startAdvertising:`.
unsafe fn start_advertising(manager: *mut AnyObject) {
    let svc_uuid = make_cbuuid(BLE_SERVICE_UUID);
    let arr_class = AnyClass::get("NSArray").expect("NSArray not found");
    let svc_uuid_ptrs: [*mut AnyObject; 1] = [svc_uuid];
    let svc_uuid_array: *mut AnyObject =
        msg_send![arr_class, arrayWithObjects: svc_uuid_ptrs.as_ptr(), count: 1usize];

    let local_name = make_nsstring("ndn-rs");
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

    // Cleanup temporaries.
    let _: () = msg_send![svc_uuid, release];
    let _: () = msg_send![local_name, release];
    info!("BLE/macOS: advertising started");
}


struct TxWork {
    shared_ptr: *mut MacosShared,
    pkt: Bytes,
    /// Monotonic base sequence to use if NDNLPv2 fragmentation is required.
    frag_seq: u64,
}
unsafe impl Send for TxWork {}

unsafe extern "C" fn do_tx_work(ctx: *mut c_void) {
    let work = Box::from_raw(ctx as *mut TxWork);
    let shared = &mut *work.shared_ptr;

    if !shared.subscribed || shared.manager.is_null() || shared.sc_char.is_null() {
        return;
    }

    let mtu: usize = msg_send![shared.manager, maximumUpdateValueLength];
    let ble_mtu = mtu.saturating_sub(ATT_OVERHEAD);

    if ble_mtu <= FRAG_OVERHEAD {
        warn!(
            ble_mtu,
            needed = FRAG_OVERHEAD + 1,
            "BLE/macOS: ATT MTU too small for NDNLPv2 fragmentation, dropping packet"
        );
        return;
    }

    // Build the on-wire LpPacket(s): passthrough if already framed, single
    // LpPacket envelope if it fits, NDNLPv2 fragments otherwise. Mirrors the
    // UDP / Ethernet / BLE/Linux send paths.
    let frags: Vec<Bytes> = if is_lp_packet(&work.pkt) {
        vec![work.pkt.clone()]
    } else if work.pkt.len() + 4 <= ble_mtu {
        vec![encode_lp_packet(&work.pkt)]
    } else {
        fragment_packet(&work.pkt, ble_mtu, work.frag_seq)
    };

    for frag in &frags {
        let ns_data = make_nsdata(frag);
        let ok: bool = msg_send![
            shared.manager,
            updateValue: ns_data,
            forCharacteristic: shared.sc_char,
            onSubscribedCentrals: std::ptr::null_mut::<AnyObject>()
        ];
        let _: () = msg_send![ns_data, release];
        if !ok {
            warn!("BLE/macOS: TX queue full — fragment dropped (flow-control not yet implemented)");
            break;
        }
    }
}

/// Create an `NSData` from a byte slice.  Returns +1 retained pointer.
unsafe fn make_nsdata(bytes: &[u8]) -> *mut AnyObject {
    let cls = AnyClass::get("NSData").expect("NSData not found");
    msg_send![
        cls,
        dataWithBytes: bytes.as_ptr() as *const c_void,
        length: bytes.len()
    ]
}


pub async fn bind(id: ndn_transport::FaceId) -> Result<BleFace, BleError> {
    // Channels.
    let (rx_sender, rx_receiver) = mpsc::unbounded_channel::<Bytes>();
    let (tx_sender, mut tx_receiver) = mpsc::channel::<Bytes>(CHAN_DEPTH);

    // Create the GCD serial queue for CoreBluetooth.
    let ble_queue: DispatchQueue =
        unsafe { dispatch_queue_create(c"ndn.ble.peripheral".as_ptr(), std::ptr::null()) };
    assert!(!ble_queue.is_null(), "failed to create BLE dispatch queue");

    // Box up the shared state and install in the global singleton.
    let shared = Box::new(MacosShared {
        manager: std::ptr::null_mut(),
        sc_char: std::ptr::null_mut(),
        subscribed: false,
        rx_sender,
    });
    let shared_ptr = install_shared(shared);

    // Instantiate the ObjC delegate and peripheral manager.
    let (delegate, manager) = unsafe {
        let class = delegate_class();
        let delegate: *mut AnyObject = msg_send![class, new]; // +1

        let pm_class = AnyClass::get("CBPeripheralManager").expect("CBPeripheralManager not found");
        let pm_alloc: *mut AnyObject = msg_send![pm_class, alloc];
        let manager: *mut AnyObject = msg_send![
            pm_alloc,
            initWithDelegate: delegate,
            queue: ble_queue
        ]; // +1

        // Store manager pointer in shared state.
        (*shared_ptr).manager = manager;

        (delegate, manager)
    };

    let server = Arc::new(BleServer {
        manager,
        delegate,
        ble_queue,
    });

    // TX bridge: tokio → GCD queue.
    // Capture raw pointers as `usize` so the async block is `Send`.
    // SAFETY: shared_ptr is only dereferenced inside `do_tx_work` on the GCD
    // queue; ble_queue is a thread-safe libdispatch queue handle.
    let queue_addr: usize = ble_queue as usize;
    let shared_addr: usize = shared_ptr as usize;
    tokio::spawn(async move {
        // Monotonic NDNLPv2 base sequence for fragment groups.
        let mut frag_seq: u64 = 0;
        while let Some(pkt) = tx_receiver.recv().await {
            let queue = queue_addr as DispatchQueue;
            if queue.is_null() {
                break;
            }
            let sptr = shared_addr as *mut MacosShared;
            let seq = frag_seq;
            frag_seq = frag_seq.wrapping_add(1);
            let work = Box::new(TxWork {
                shared_ptr: sptr,
                pkt,
                frag_seq: seq,
            });
            unsafe {
                dispatch_async_f(queue, Box::into_raw(work) as *mut c_void, do_tx_work);
            }
        }
    });

    let local_uri = "ble://local".to_owned();

    Ok(BleFace {
        id,
        local_uri,
        rx: Mutex::new(rx_receiver),
        tx: tx_sender,
        _server: server,
    })
}
