# Diagnostic service replay using the retained build

Central-t0e1.37 remains open. Build-handoff-01 passed producer compilation,
79 actual utility functions, all five runner controls, a fresh consumer without
compilation, and owned cleanup in 37.04 minutes. Preserved receipts are under
`../../build-handoff/2026-09-27/receipts/attempt-01`.

The current experiment deliberately stops the zone after startup and one healthy
sample. The unchanged health checker must fail even when that exit code is zero.
It uses the qualified retained artifact and does not compile EQEmu. Attempt 03
already supplies the successful diagnostic comparison, detailed below.

This remains diagnostic-only. Worker and suite outcomes stay non-pass; an
operator checks the intended failure and cleanup separately. There is no new
control-result classifier or actor implementation. Successful failure detection
does not promote the candidate to accepted runtime validation.

## First result and listener correction

Attempt 01 stopped after 6.30 minutes at the world listener check. Reuse and all
79 utility functions passed, as did runtime packages, public database imports
and shared data. World reported listening on port 9000 and stayed alive, but
the readiness predicate required 127.0.0.1. The server's IPv4 TCP implementation
binds 0.0.0.0. The retry accepts either wildcard or loopback in LISTEN state on
port 9000; authenticated zone registration and world-time exchange remain the
later readiness checks. It rejects wrong ports, unrelated addresses and
non-listening states.

World and MariaDB exited zero during failure cleanup, without forced termination.
Bounded diagnostics exported completely; the earlier Aborted connection warning
did not recur in the retained database tail. This does not explain that earlier
warning or prove zone behavior: no zone was started. Worker/suite cleanup passed
without rescue, released ownership and removed the disposable disk/copy. The
controller pool had memory-limit pressure but no OOM. Receipts are preserved in
`receipts/attempt-01`; diagnostic contents remain private at the original host
path, with their digest recorded. The failed outcome is unchanged.

The current commands target fresh attempt 04. Original attempt 01 preparation,
launcher and retained receipts are not regenerated. `receipts/preparation.json`
remains the first attempt's identity; `receipts/preparation-04.json` identifies
the new preparation. No new C++ build or host dependency is required.

## Second result and MVP retry

Attempt 02 reached static poknowledge boot, instance 0, world registration and
world-time exchange, then timed out waiting for a different instance log phrase.
It never reached the sixty-second health check. All 79 utility functions passed;
zone, world and database exited zero during cleanup, with no forced kills.
Diagnostic export and owned cleanup completed. The earlier MariaDB warning did
not recur, but remains unexplained. Receipts are under `receipts/attempt-02`.

Attempt 03 changes one scenario predicate to recognize the actual boot-completion
record. `startup-lines.json` holds four selected readiness lines from attempt 02,
without credentials or player data. The existing readiness regression failed
against the old predicate and passes with the correction; one additional check
rejects an incorrect instance ID. No new runtime gate, abstraction, dependency
or resource allowance is introduced. Original attempt 01/02 inputs and results
remain unchanged. The retained artifact is reused without compilation.

## Successful diagnostic and deliberate exit control

Attempt 03 completed all diagnostic checks in 5.23 minutes: 79 actual utility
functions, startup/registration/time exchange, owned world connection, 60.396
seconds of health observations, protected schema/empty player state and clean
service shutdown. Diagnostic export and owned cleanup completed. Aborted client
and connection counters stayed zero before shared data, after it, at readiness,
before shutdown and after shutdown. The earlier warning remains historically
unexplained. Receipts are preserved in `receipts/attempt-03`.

Attempt 04 takes the same path until one successful health/DB sample. Its fixed
guest setting then records `health-before-control`, requests SIGTERM for the
owned zone, waits at most fifteen seconds and records `control-zone-exit`.
The normal health checker should report `zone: unexpected exit 0`. The control
never raises a substitute scenario failure. Existing cleanup records the zone's
early exit, closes remaining services and tears down owned VM resources.

For this control to supply useful failure evidence, inspect all of:

- Normal ready evidence and a successful health sample before the stop.
- The stop request and actual zero exit, followed by first failure
  `zone: unexpected exit 0`, with no completed positive scenario.
- Complete bounded diagnostics. The zone's expected early-exit cleanup note
  may appear among later errors; unrelated errors require investigation.
- Normal remaining-service shutdown, complete worker/suite cleanup without
  rescue, released ownership and unchanged artifact/input hashes.

`suite_passed=false`, `diagnostic_complete=false` and `accepted=false` are
expected. A timeout, unrelated error or cleanup failure is not a successful
control. No actor code is needed. Repeat/cancellation evidence and general AFK
integration remain separate work; do not close the broader investigation.

## One guest scenario

The fresh offline VM consumes its own read-only artifact copy. It checks the
prior manifest, binaries, package state, system libraries and loader behavior,
and reruns actual utility tests. It then installs the sealed runtime packages,
checks that libraries/binaries remain unchanged and imports the public fixture.
No production or NAS data or credentials are inputs.

The guest adapter checks shared data, world/zone registration for poknowledge
202:0, world-time exchange, a zone-owned world connection, sixty seconds of
service and database health, normal world/zone shutdown, and unchanged protected
schema plus empty player/login state. Readiness phrases remain local to this
source-version adapter. There is no whole-database data-checksum gate or fixed
sample-count invariant. The collector never kills a service because a log line
contains a warning or the word Aborted.

Database connection counters and eqemu connection IDs are sampled around shared
data generation, readiness and shutdown. Query text is excluded. Service exits,
signals, forced termination and the first failure are recorded. Log tails have
32 KiB per-stream limits, at most eight streams and 512 KiB encoded diagnostic
frames within the existing 1 MiB serial budget. Export scrubs generated guest
secrets and control characters. Host output paths are fixed; no guest path can
select where host evidence is written. `diagnostics.jsonl` and `serial.log` are
root:bump mode 0640. Treat retained evidence as private diagnostic material.

The workload gets 1,800 seconds after ready. The host collector allows 2,040,
leaving time for guest shutdown and a separate fifteen-second diagnostic grace,
including two seconds reserved for the terminal frame. Worker and suite caps
remain 2,700 and 3,000 seconds. Existing memory, CPU, disk, admission and reserve
limits are unchanged. Guest service shutdown can force termination, which must
remain visible as a failure. Independent host cleanup is the outer safeguard.

## Preparation and operator commands

Preparation reads pinned previous inputs and archived fixture helpers as data.
It excludes the archived warning scanner, old scenario and data checksums.
Source hashes, artifact identity, worker, launcher and seed are recorded in
`receipts/preparation-04.json`. Preparation refuses existing attempt/output paths.
No VM starts during preparation or local checks.

```sh
python3 investigations/runtime-reuse/2026-09-27/prepare.py
timeout 60s python3 -m unittest discover -s investigations/runtime-reuse/2026-09-27 -v
python3 ~/.local/state/eqemu-vm-proof/offline-runtime-reuse-04.py --check
sudo python3 ~/.local/state/eqemu-vm-proof/offline-runtime-reuse-04.py
```

The twenty local checks exercise synthetic processes, actual warning capture,
early exits, forced shutdown, descendants, output limits, failed event export,
cleanup retry, deadline allowance, readiness/connection failure, redaction and
bounded protocol rejection. They do not establish real service behavior.

Progress and retained evidence are under
`/var/lib/eqemu-vm-proof/runtime-reuse-04/consumer/evidence/`:
`report.json`, `diagnostics.jsonl`, `serial.log`, and `cleanup.json`.
The attempt root contains `suite-result.json` and `suite-cleanup.json`.

```sh
sudo systemctl stop eqemu-vm-runtime-reuse-04-suite.service
```

Cancellation retains a non-pass outcome and runs owned cleanup. Do not
regenerate a launched attempt. The original qualified artifact and custody
remain read-only inputs owned by build-handoff-01; this replay removes only its
own copy and VM resources. Original reuse expiry is October 4, 2026 at 11:15:28
Pacific. Expiry refuses reuse but does not automatically delete the artifact.

After all consumers are quiescent and the retained build is no longer needed:

```sh
sudo python3 /var/lib/eqemu-vm-proof/build-handoff-01/suite.py --discard-artifact
```

Do not discard it merely to inspect results. No new artifact registry, cache,
scheduled eviction, gameplay implementation or AFK interface is added here.
