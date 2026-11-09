#!/bin/bash
set -euxo pipefail
mkdir -p /candidate/results /candidate/source
exec > >(tee /candidate/results/build.log) 2>&1
tar xf /candidate/source.tar -C /candidate/source
cd /candidate/source
export PATH=/opt/eqemu-perl/bin:/root/.cargo/bin:$PATH
perl -V
cmake --version
# A missing toolchain is an explicit prerequisite failure, never a skipped Rust test.
command -v cargo
rustc --version
cargo test --locked --manifest-path rust/actors/Cargo.toml
cargo build --locked --release --manifest-path rust/actors/Cargo.toml
cmake -S . -B /candidate/build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DEQEMU_BUILD_TESTS=ON -DEQEMU_SANITIZERS=ON -DPERL_EXECUTABLE=/opt/eqemu-perl/bin/perl
cmake --build /candidate/build --parallel 2
/candidate/build/bin/tests
