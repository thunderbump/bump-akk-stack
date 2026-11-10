#!/bin/bash
# Throwaway workload: compile, run, and verify one deliberate ASan failure.
set -euo pipefail
cd /tmp
cat > proof.cpp <<'CPP'
#include <cstdio>
int main(int argc, char**) {
    auto* value = new int(42);
    if (argc > 1) delete value;
    std::printf("answer=%d\n", *value);
    if (argc == 1) delete value;
}
CPP
g++ --version | head -1
g++ -g -O0 -fno-omit-frame-pointer -fsanitize=address,undefined proof.cpp -o proof
export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1
export ASAN_SYMBOLIZER_PATH=/usr/bin/addr2line
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
./proof
set +e
./proof deliberate-failure > asan.log 2>&1
failure=$?
set -e
test "$failure" -ne 0
grep 'heap-use-after-free' asan.log
grep 'proof.cpp:' asan.log
printf 'expected_failure_exit=%s\n' "$failure"
printf 'memory.max='; cat /sys/fs/cgroup/memory.max
printf 'pids.max='; cat /sys/fs/cgroup/pids.max
printf 'cpu.max='; cat /sys/fs/cgroup/cpu.max
printf 'PASS: ordinary execution and symbolized ASan failure\n'
