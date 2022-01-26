// pkmallocator/src/lib.rs - PKRU-Safe
//
// Copyright 2018 Paul Kirth
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#![never_gate]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_attributes)]
#![feature(alloc)]
#![feature(allocator_api)]
#![feature(libc)]
#![feature(thread_local)]
#![feature(extern_types)]
#![crate_name = "pkmallocator"]
#![crate_type = "rlib"]

extern crate alloc;
extern crate errno;
extern crate libc;
extern crate mpk;
extern crate pkalloc;

use alloc::alloc::{AllocErr, GlobalAlloc, Layout};
use errno::{errno, set_errno, Errno};
use libc::c_void;
use libc::{free, mmap, munmap, posix_memalign, realloc, syscall};
use libc::{MAP_ANON, MAP_FAILED, MAP_FIXED, MAP_PRIVATE, PROT_NONE, PROT_READ, PROT_WRITE};
use std::cell::RefCell;
use std::mem::{self, ManuallyDrop};
use std::ops::{Deref, DerefMut};
use std::ptr;
use std::ptr::NonNull;

static mut LOCK: libc::pthread_mutex_t = libc::PTHREAD_MUTEX_INITIALIZER;

const MIN_ALIGN: usize = 16;

thread_local! {
    pub static LOCAL_IS_SAFE: RefCell<bool> = RefCell::new(true);
}

thread_local! {
    pub static LOCAL_PKEY_STACK: RefCell<Vec<u32>> = RefCell::new(vec![]);
}

pub struct untrusted_ty<T> {
    pub val: T,
}

#[global_allocator]
pub static ALLOC: PkAlloc = PkAlloc;

pub struct PkAlloc;

pub struct AllocGuard {
    was_safe: bool,
}

impl AllocGuard {
    #[inline]
    pub fn new() -> AllocGuard {
        let ag = AllocGuard {
            was_safe: PkAlloc::is_safe(),
        };
        PkAlloc::disable_safe_alloc();
        ag
    }
}

impl Drop for AllocGuard {
    #[inline]
    fn drop(&mut self) {
        if self.was_safe {
            PkAlloc::enable_safe_alloc();
        }
    }
}

#[macro_export]
macro_rules! untrusted {
    ($x:block) => {{
        let _guard = $crate::AllocGuard::new();
        $x
    }};
}

pub mod libc_compat {
    use super::*;

    #[inline]
    pub unsafe fn malloc(size: usize) -> *mut u8 {
        let layout = Layout::from_size_align_unchecked(size, MIN_ALIGN);
        if PkAlloc::is_safe() {
            PkAlloc::safe_allocate(layout)
        } else {
            PkAlloc::normal_allocate(layout)
        }
    }

    #[inline]
    pub unsafe fn realloc(ptr: *mut u8, new_size: usize) -> *mut u8 {
        if pkalloc::pk_is_safe_addr(ptr) {
            pkalloc::libc_compat::realloc(ptr as *mut _, new_size) as *mut u8
        } else {
            libc::realloc(ptr as *mut c_void, new_size) as *mut u8
        }
    }

    #[inline]
    pub unsafe fn free(ptr: *mut u8) {
        if pkalloc::pk_is_safe_addr(ptr) {
            pkalloc::libc_compat::free(ptr as *mut _)
        } else {
            libc::free(ptr as *mut c_void)
        }
    }

    #[inline]
    pub unsafe fn malloc_usable_size(ptr: *const u8) -> usize {
        pkalloc::pk_malloc_usable_size(ptr as *const _)
    }
}

impl PkAlloc {
    // TODO return the pkey value with a lazy static
    /// returns the pkey value
    #[inline]
    pub fn get_pkey() -> i32 {
        unsafe { pkalloc::pk_vma_pkey() }
    }

    /// Enables allocations from the safe region
    #[inline]
    pub fn enable_safe_alloc() {
        LOCAL_IS_SAFE.with(|f| {
            *f.borrow_mut() = true;
        });
    }

    /// Disables allocations from the safe region
    /// Can be extended to use TLS for each arena
    #[inline]
    pub fn disable_safe_alloc() {
        LOCAL_IS_SAFE.with(|f| {
            *f.borrow_mut() = false;
        });
    }

    /// returns the value of is safe -- can be extended for thread safty
    #[inline]
    pub fn is_safe() -> bool {
        LOCAL_IS_SAFE.with(|f| *f.borrow())
    }

    /// Returns a result containing a pointer in the safe region to the alloction or an AllocErr
    ///
    /// # Arguments
    ///
    /// # `layout` the layout for the memory request
    ///
    #[inline]
    unsafe fn safe_allocate(layout: Layout) -> *mut u8 {
        let mut err = ManuallyDrop::new(mem::uninitialized::<AllocErr>());
        pkalloc::pk_alloc(
            layout.size(),
            layout.align(),
            &mut *err as *mut AllocErr as *mut u8,
        ) as *mut u8
    }

    /// Returns a result containing a pointer in the `unsafe` region to the alloction or an AllocErr
    ///
    /// # Arguments
    ///
    /// # `layout` the Layout for the memory request
    ///
    #[inline]
    unsafe fn normal_allocate(layout: Layout) -> *mut u8 {
        libc::malloc(layout.size()) as *mut u8
    }
}

unsafe impl GlobalAlloc for PkAlloc {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if PkAlloc::is_safe() {
            PkAlloc::safe_allocate(layout)
        } else {
            PkAlloc::normal_allocate(layout)
        }
    }

    #[inline]
    unsafe fn untrusted_alloc(&self, layout: Layout) -> *mut u8 {
        PkAlloc::normal_allocate(layout)
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if PkAlloc::is_safe() {
            pkalloc::pk_alloc_zeroed(layout.size(), layout.align()) as *mut u8
        } else {
            if layout.align() <= MIN_ALIGN && layout.align() <= layout.size() {
                libc::calloc(layout.size(), 1) as *mut u8
            } else {
                let ptr = PkAlloc::normal_allocate(layout.clone());
                if !ptr.is_null() {
                    ptr::write_bytes(ptr as *mut u8, 0, layout.size());
                }
                ptr
            }
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) -> () {
        if pkalloc::pk_is_safe_addr(ptr) {
            pkalloc::pk_dealloc(ptr as *mut u8, layout.size(), layout.align())
        } else {
            free(ptr as *mut c_void)
        }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if pkalloc::pk_is_safe_addr(ptr) {
            pkalloc::pk_realloc(ptr, layout, new_size) as *mut u8
        } else {
            libc::realloc(ptr as *mut c_void, new_size) as *mut u8
        }
    }
}

#[no_mangle]
pub extern "C" fn __in_trusted_compartment() -> bool {
    let pkey = PkAlloc::get_pkey();
    let pkru_val = mpk::pkey_get(pkey).expect("failed to read pkey!");
    return pkru_val == 0x0;
}

extern "C" {
    fn inc_gate_count();
}

#[no_mangle]
pub extern "C" fn __untrusted_gate_enter() {
    //unsafe { inc_gate_count(); }
    //mpk::pkrusafe_enter();
}

#[no_mangle]
pub extern "C" fn __untrusted_gate_exit() {
    //unsafe { inc_gate_count(); }
    //mpk::pkrusafe_exit()
}

#[no_mangle]
pub extern "C" fn __mpk_disable_access() {
    //mpk::pkrusafe_exit()
}

#[no_mangle]
pub extern "C" fn __mpk_restore_access() {
    //mpk::pkrusafe_enter();
}
