//! Conditional compilation

#[allow(unused_macros)] // might be redefined to expand to nothing
macro_rules! if_cfg_getresuid { { $($y:tt)* } => { $($y)* } }

// Sadly we can't use this in struct MockableLibcFunctions in lmockable.rs
#[cfg(any(target_os = "macos", target_os = "netbsd"))]
macro_rules! if_cfg_getresuid { { $($y:tt)* } => { } }
