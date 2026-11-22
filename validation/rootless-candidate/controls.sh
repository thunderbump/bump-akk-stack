#!/bin/bash
# Deliberate failures qualify the detector; ordinary workloads keep fatal options.
set -euo pipefail
export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:symbolize=1
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
export ASAN_SYMBOLIZER_PATH=/usr/bin/addr2line
binary=/candidate/build/bin/tests_sanitizer_controls
for control in pass use-after-free out-of-bounds undefined leak; do
    log=/candidate/results/control-$control.log
    status=0
    timeout 30 "$binary" "$control" >"$log" 2>&1 || status=$?
    printf '%s %s\n' "$control" "$status" >> /candidate/results/controls.txt
    if [[ $control == pass ]]; then
        test "$status" = 0
    else
        test "$status" != 0 && test "$status" != 124
        case $control in
            use-after-free) expected=heap-use-after-free;;
            out-of-bounds) expected=heap-buffer-overflow;;
            undefined) expected='runtime error:';;
            leak) expected=LeakSanitizer;;
        esac
        grep -q "$expected" "$log"
        grep -Eq 'sanitizer_controls.cpp:[0-9]+' "$log"
    fi
done
