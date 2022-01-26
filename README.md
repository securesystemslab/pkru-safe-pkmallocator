# pkmallocator

This crate provides a rust interface to a global allocator that partitions the heap between `trusted` and `untrusted` regions.

We define a trusted region to be any memory allocated soley for use by Rust, and the untrusted region to be used for any other libray or application not written in rust, or directly flagged as untrusted. 

The allocator uses a custom version of Jemalloc (for trusted allocations) and the system allocator(for untrusted allocations) to split the heap. Our custom Jemalloc (provided by crate pkalloc) maps a large region of memory during bootstrap (2^47 bits of address space), and protects this region with an Intel Memory Protection Key (MPK). This protected memory is served to Rust code by default, but can be disabled either through use of the `untrusted!{}` macro, or by directly interfacing with the allocator's public APIs.

The allocator's state (whether it is curently allocating from the trusted or untrused region) is maintained in a thread local variable, and directly mirrors the behavior of the PKRU register itself, i.e. that all child threads inherit its current value (the same as for the value of PKRU itself).

It should be noted that not all foreign APIs are protected automatically. This library is intended to be used with the mpk-protector crate to automate wrapping the Rust FFI for certain modules, and keeping their data separate.

The main goal of this project is to prevent bugs or a malicious actor in the untrusted module from inappropriatly accessing (i.e. reading and/or modifying) data managed by the trusted portion of the application, that is not related to the module itself.

Note that this will not prevent the untrusted module from manipulating the data it passes to the trusted module directly, or from executing potentially malicious code on the host, but rather this defense seeks to maintain the integrity of the trusted portion of the application from direct manipulation or disclosure by the untrused module.

## Usage 
### Code Example

```rust
#![feature(libc)]
#[macro_use]
extern crate pkmallocator; // import untrused!{} macro and allocator APIs
extern crate libc;
extern crate untrusted;  // the library interface we've protected using the mpk-protector plugin

use std::ffi::CString;
use untrusted::use_ptr;

#[test]
fn use_rust_ptr() {
    let msg;
    
    // Declare a region(a code block) that will only yeild untrusted allocations
    // If we did not allocate msg from the untrusted region, then its use in use_ptr
    // would cause a memory permission error (SEGV under Linux)
    untrusted!({
        msg = CString::new("Hello World!").unwrap(); // allocate some memory from the untrusted region
    }); 
    
    // after the enclosed block ends normal allocation resumes 
    // note that this nests correctly, and will simply restore the previous
    // allocation state, rather than just reinstate normal allocation
    
    let cmsg = msg.as_ptr(); // get a pointer to pass to C
    unsafe {
        let ptr = use_ptr(cmsg); // pass a pointer to the untrusted memory to C, 
        assert_ne!(cmsg, ptr);
        assert_eq!(*cmsg, *ptr);
        libc::free(ptr as *mut libc::c_void); 
    }
}

```

### Cargo.toml
```toml
[dependencies]
mpk_protector = { git = "https://github.com/securesystemslab/pkru-safe-mpk-protector.git" }
pkmallocator = { git = "https://github.com/securesystemslab/pkru-safe-pkmallocator.git" }
mpk = { git = "https://github.com/securesystemslab/pkru-safe-mpk-libc.git" }
```
