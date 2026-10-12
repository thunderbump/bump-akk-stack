#include "eqemu-rust-proof-bridge/src/lib.rs.h"
#include <cstdio>

extern "C" unsigned int eqemu_rust_bridge_v1();

int main() {
    if (eqemu_proof::answer(41) != 42 || eqemu_rust_bridge_v1() != 42) {
        return 1;
    }
    std::puts("EQEMU_RUST_BRIDGE_RESULT 42");
    return 0;
}
