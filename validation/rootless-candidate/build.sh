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
# vcpkg version baselines require Git objects, which source archives omit.
vcpkg_commit=$(cat /candidate/vcpkg-commit)
rm -rf submodules/vcpkg
git clone https://github.com/microsoft/vcpkg.git submodules/vcpkg
git -C submodules/vcpkg checkout "$vcpkg_commit"
perl_core=$(/opt/eqemu-perl/bin/perl -MConfig -e 'print "$Config{archlib}/CORE"')
perl_lib=$(/opt/eqemu-perl/bin/perl -MConfig -e 'print $Config{libperl}')
cmake -S . -B /candidate/build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DEQEMU_BUILD_TESTS=ON -DEQEMU_SANITIZERS=ON -DPERL_EXECUTABLE=/opt/eqemu-perl/bin/perl -DPERL_INCLUDE_PATH="$perl_core" -DPERL_LIBRARY="$perl_core/$perl_lib"
cmake --build /candidate/build --parallel 2
cmake --build /candidate/build --target tests_sanitizer_controls --parallel 2
/candidate/controls.sh
export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:symbolize=1
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
/candidate/build/bin/tests

python3 /candidate/smoke.py
