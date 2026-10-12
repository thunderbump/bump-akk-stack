#![deny(unsafe_op_in_unsafe_fn)]

#[cxx::bridge(namespace = "eqemu_proof")]
mod ffi {
    extern "Rust" {
        fn answer(value: u32) -> u32;
    }
}

fn answer(value: u32) -> u32 {
    eqemu_rust_proof_core::answer(value)
}

// SAFETY: This unique versioned symbol accepts no pointers and exposes only a
// fixed-width scalar. The native qualification caller owns its invocation.
#[unsafe(no_mangle)]
pub extern "C" fn eqemu_rust_bridge_v1() -> u32 {
    answer(41)
}
