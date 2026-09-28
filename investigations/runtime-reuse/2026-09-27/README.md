# Startup scenario: cancellation and fresh repeat

Current work is central-t0e1.37. The fixed lifecycle command runs two fresh,
sequential workers using the same qualified build and public database fixture.
It adds no C++ compilation, host dependency, actor code or general test framework.

## Existing evidence

- Build-handoff-01 passed producer compilation and a fresh consumer, including
  79 utility functions and five producer runner controls. One qualified 4 GiB
  artifact remains under build-handoff-01 with its original reuse expiry.
- Runtime attempts 01/02 failed on listener/instance-log predicates. Their inputs
  and outcomes remain unchanged; source-backed corrections are regression-tested.
- Attempt 03 completed startup/registration/world-time exchange, a zone-owned
  world connection, 60.396 seconds of service/database health, protected schema
  and empty player/login state, normal service shutdown and owned cleanup.
- Attempt 04 stopped the zone after a healthy sample. The normal checker
  detected exactly `zone: unexpected exit 0`; diagnostics and cleanup completed.

Preserved results are under `receipts/attempt-01` through `attempt-04`. The full
private diagnostic contents stay on the host; their hashes are recorded.
The historical MariaDB warning remains unexplained and did not recur in these
recent runs. None of these diagnostic experiments grants deployment acceptance.

## Current two-step experiment

Attempt 05 runs the normal guest, with the earlier zone-exit injection disabled.
Its supervisor waits for host-recorded zone readiness, validates worker ownership,
writes `cancel-request.json`, then calls `systemctl stop --no-block` for its own
suite. SIGTERM interrupts the supervisor; the existing ExecStopPost cleanup stops
the worker, destroys owned VM resources and releases the lease. This exercises
suite cancellation, not just a guest-process stop. Guest terminal diagnostics
are not required after cancellation; retained host progress/serial evidence and
cancellation/cleanup receipts establish what happened.

The foreground lifecycle driver verifies pinned launcher copies, ownership,
actual resource absence, worker/suite cleanup without rescue, released reservation
and the exact `Supervisor interrupted` / `Controller interrupted` outcomes.
It refuses a completed guest result or a cancellation without the ready marker.
Only then may it start attempt 06, a fresh normal sixty-second diagnostic repeat.
It checks complete positive guest evidence and clean teardown before reporting
`lifecycle_checks_passed=true`. Both child suites keep their original non-pass
statuses; the driver reports `accepted=false`. Its success means only that these
two lifecycle checks completed.

The driver is a fixed foreground script, with 256 MiB address-space and 60 CPU-second
limits. It waits at most 3,300 seconds per child. Existing child suite/worker/guest
limits and admission/reserve checks remain unchanged. Workers do not overlap.
Ctrl-C, SIGTERM or terminal hangup stops the active child and prevents the next
one from launching. SIGKILL cannot run the driver's cleanup handler; child suites
still have their independent lifetime and cleanup controls. Keep the terminal
open for the normal run, expected to take roughly ten minutes, not its upper bound.

## Prepare and launch

Preparation refuses existing attempts and outputs. Never regenerate launched
inputs. The one preparation command creates fresh 05/06 identities and the driver:

```sh
python3 investigations/runtime-reuse/2026-09-27/prepare_lifecycle.py
timeout 60s python3 -m unittest discover -s investigations/runtime-reuse/2026-09-27 -v
python3 ~/.local/state/eqemu-vm-proof/offline-runtime-reuse-05.py --check
python3 ~/.local/state/eqemu-vm-proof/offline-runtime-reuse-06.py --check
sudo python3 ~/.local/state/eqemu-vm-proof/offline-runtime-lifecycle-01.py
```

The lifecycle result is
`/var/lib/eqemu-vm-proof/runtime-lifecycle-01/result.json`.
Individual results/progress remain in `runtime-reuse-05` and `runtime-reuse-06`
beside that directory, each with `suite-result.json`, `suite-cleanup.json` and
`consumer/evidence/`. In another terminal, the active child can also be stopped
with `sudo systemctl stop eqemu-vm-runtime-reuse-05-suite.service` or the equivalent
06 command. The driver will reject an unintended outcome and halt.

Twenty-seven local checks cover the existing service/diagnostic behavior plus the
suite-stop target, exact cancellation evidence, incomplete cleanup rejection,
the barrier preventing repeat after a failed check, and complete repeat evidence.
Both generated controller input/XML/AppArmor checks pass. No VM was started by
preparation or these tests. Prepared hashes are in `receipts/preparation-05.json`,
`preparation-06.json` and `lifecycle-preparation-01.json`.

## Data and retention

Guests use sealed public fixtures, not production/NAS data or credentials. The
host never mounts guest filesystems or runs acquired candidate executables.
Artifact consumption is read-only; each child removes its own copy and VM disk.
The original build-handoff-01 artifact/custody stay unchanged. Reuse expires on
October 4, 2026 at 11:15:28 Pacific; expiry refuses reuse but does not delete it.
After all consumers are quiescent and the build is no longer needed, its existing
explicit discard command remains:

```sh
sudo python3 /var/lib/eqemu-vm-proof/build-handoff-01/suite.py --discard-artifact
```

Do not discard merely to inspect results. Whole-AFK integration and actor behavior
remain separate investigations; completing this pair does not close them.
