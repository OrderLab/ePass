//! The ePass C ABI for userspace loaders: `epass_compile` and
//! `epass_output_free` from `epass-core` (see `epass-core/include/epass.h`),
//! plus [`epass_default_host`], a host over the system allocator.

use std::alloc::Layout;
use std::ffi::c_void;

pub use epass_core::ffi::*;

unsafe extern "C" fn sys_alloc(_ctx: *mut c_void, size: usize, align: usize) -> *mut c_void {
    match Layout::from_size_align(size, align) {
        // SAFETY: the core never asks for zero bytes (checked anyway).
        Ok(l) if l.size() != 0 => unsafe { std::alloc::alloc(l).cast() },
        _ => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn sys_free(_ctx: *mut c_void, ptr: *mut c_void, size: usize, align: usize) {
    if let (false, Ok(l)) = (ptr.is_null(), Layout::from_size_align(size, align)) {
        // SAFETY: `ptr` came from `sys_alloc` with this layout.
        unsafe { std::alloc::dealloc(ptr.cast(), l) };
    }
}

unsafe extern "C" fn sys_now_ns(_ctx: *mut c_void) -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

struct SyncHost(epass_host);
// SAFETY: the host holds no state (`ctx` is NULL) and its functions are
// thread-safe.
unsafe impl Sync for SyncHost {}

static DEFAULT_HOST: SyncHost = SyncHost(epass_host {
    ctx: std::ptr::null_mut(),
    alloc: Some(sys_alloc),
    free: Some(sys_free),
    log: None,
    now_ns: Some(sys_now_ns),
    should_yield: None,
});

/// A host over the system allocator that logs nothing (valid forever).
#[no_mangle]
pub extern "C" fn epass_default_host() -> *const epass_host {
    &DEFAULT_HOST.0
}
