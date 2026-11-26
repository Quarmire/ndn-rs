//! A counting allocator for tests: how many allocations a closure makes on the
//! calling thread.
//!
//! The one `#[global_allocator]` of the crate's test binary. It forwards to the
//! system allocator and counts only while a [`count_allocations`] call is on
//! the thread's stack, so other tests in the binary are unaffected. Use it for
//! the "no allocation per message" gates:
//!
//! ```ignore
//! let (value, allocations) = count_allocations(|| work());
//! ```

// `GlobalAlloc` is an unsafe trait and the workspace denies unsafe code; the
// allowance is scoped to this test-only module, which only forwards to `System`.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static COUNT: Cell<usize> = const { Cell::new(0) };
    static LIVE: Cell<i64> = const { Cell::new(0) };
}

struct Counting;

fn note(size: usize) {
    // `try_with`: the thread-local may be gone while a thread exits.
    let _ = ARMED.try_with(|armed| {
        if armed.get() {
            let _ = COUNT.try_with(|count| count.set(count.get() + 1));
            let _ = LIVE.try_with(|live| live.set(live.get() + size as i64));
        }
    });
}

fn note_free(size: usize) {
    let _ = ARMED.try_with(|armed| {
        if armed.get() {
            let _ = LIVE.try_with(|live| live.set(live.get() - size as i64));
        }
    });
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        note_free(layout.size());
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        note_free(layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// What `f` returned and how many times it allocated (`alloc`, `alloc_zeroed`
/// and `realloc`) on this thread.
pub(crate) fn count_allocations<T>(f: impl FnOnce() -> T) -> (T, usize) {
    COUNT.with(|count| count.set(0));
    ARMED.with(|armed| armed.set(true));
    let value = f();
    ARMED.with(|armed| armed.set(false));
    (value, COUNT.with(Cell::get))
}

/// What `f` returned and the octets of allocation it left live on this thread: what it
/// allocated less what it freed, both counted only while `f` runs. Build everything `f` frees
/// inside `f` (memory allocated before the call and freed in it would count as negative), and
/// keep what `f` returns alive across the call: the figure is what the returned value and the
/// state `f` touched still hold.
pub(crate) fn live_bytes<T>(f: impl FnOnce() -> T) -> (T, i64) {
    LIVE.with(|live| live.set(0));
    ARMED.with(|armed| armed.set(true));
    let value = f();
    ARMED.with(|armed| armed.set(false));
    (value, LIVE.with(Cell::get))
}
