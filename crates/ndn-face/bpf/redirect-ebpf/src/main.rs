//! Minimal XDP redirect-to-XSK program. Every frame on the bound queue is
//! redirected into the `XSKS` map (keyed by RX queue index); if no socket is
//! registered for that queue it falls through to the normal stack (XDP_PASS).
//! This is the fixed, generic redirect program the userspace loader attaches.
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::XskMap,
    programs::XdpContext,
};

#[map]
static XSKS: XskMap = XskMap::with_max_entries(64, 0);

#[xdp]
pub fn redirect(ctx: XdpContext) -> u32 {
    // SAFETY: ctx.ctx points at a valid xdp_md for the duration of the call.
    let queue = unsafe { (*ctx.ctx).rx_queue_index };
    // redirect() returns XDP_REDIRECT when a socket is registered at `queue`,
    // else an error → fall through to the kernel stack.
    XSKS.redirect(queue, 0).unwrap_or(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
