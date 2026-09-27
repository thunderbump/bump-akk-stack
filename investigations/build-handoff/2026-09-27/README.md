# Real build export and fresh consumer

Prepared under central-t0e1.37 after corrected-build-01 passed the full build,
79 utility tests, all five runner controls, ELF measurements and owned cleanup
in 33.16 minutes. Those receipts are preserved under
`../../corrected-build/2026-09-26/receipts/attempt-01`.

This fixed experiment rebuilds candidate
`1c561d442638b3da8d20e93ac105f98a227d37f2`, retaining the actual runner controls
before server compilation. The previous measurement run deliberately deleted
its binaries, so one new build is necessary. It exports exactly world, zone,
shared_memory and tests, unstripped, as flat regular files on a fully allocated
4 GiB raw ext4 disk. They measured about 800 MiB. Eight measured package-provided
libraries add about 10 MiB but are verified in place, not exported or overwritten.
Unexpected build-tree dependencies or missing embedded debug information fail.

The manifest records file hashes/lengths, system library identities, package
state, tool observations, effective build configuration and binary identities.
The build identity binds the corrected build recipe, candidate overlay, base
image, input media and format. The handoff recipe has a separate identity.
The bounded manifest digest is observed over the nonce-bound serial protocol.
The host handles opaque bytes only, seals after producer shutdown and promotes
custody only after successful producer cleanup. It never mounts the artifact,
inspects ELF files or executes acquired code.

The consumer boots from the same clean base with the same offline package media.
It installs packages, requires the same package-state digest, verifies the
manifest and system library hashes, and copies the four binaries to their
original absolute build paths in its own writable root. It refuses artifact
device writes, unmounts the read-only disk, resolves dependencies, invokes the
guest loader's `--verify` for each executable, and reruns the actual utility
suite without compiling EQEmu. The host compares the consumer observations with
the producer's accepted evidence. This proves only this build handoff if it
passes; world/zone startup, dlopen/Perl/Lua module use, database interactions,
gameplay and whole-AFK isolation are still unproven.

## Bounds and retention

Existing limits remain 4 GiB guest RAM, 6 GiB QEMU, two CPUs, one compile job,
32 GiB raw root per active worker and a 4 GiB artifact disk/copy. Workers run
sequentially. Each controller is capped at 960 MiB; the supervisor has 64 MiB,
with a shared 1 GiB cap and no swap. Admission/reserve thresholds remain
180/100 GiB free disk and 15/8 GiB available RAM. The producer worker has 17,400
seconds, consumer 2,700, and the suite retains its existing total 18,000-second
limit. The supervisor's 17,700-second execution budget is shared across cases.
These are upper bounds, not an expected five-hour running time.

A completely successful suite retains one root-owned 4 GiB artifact under this
attempt's `retained/` directory. All VM roots, staging copies and worker resources
are removed. Reuse expires seven days after retention; custody refuses expired
or discarded output. There is no scheduled eviction. Use the explicit discard
command below when the artifact is superseded or no longer needed. Failed,
cancelled, rescued or controller-budget-failed suites do not qualify retention.
Missing output on a successful path fails cleanup. Unidentified or changed files
are retained for investigation instead of being deleted speculatively.

Discard requires inactive suite/workers, absent worker resources, the released
producer's identity and matching artifact bytes. It removes only this owned
file/directory, revokes custody and writes an additional receipt without changing
the original suite outcome. The root-owned copied launcher is required so later
source edits cannot silently change the operation.

## Prepare and run

The preparer reads the previous pinned cloud-init seed as data with `isoinfo`,
checks its seed/worker identities and the pinned successful handoff suite, then
creates fresh identities. It starts no VM and refuses existing preparation or
attempt paths. The prior corrected-build receipt hashes are checked at launch.
No production/database/NAS input is used; no dependency installation occurs on
the host.

```sh
python3 investigations/build-handoff/2026-09-27/prepare.py
python3 ~/.local/state/eqemu-vm-proof/offline-build-handoff-01.py --check
timeout 60s python3 -m unittest discover -s investigations/build-handoff/2026-09-27 -v
sudo python3 ~/.local/state/eqemu-vm-proof/offline-build-handoff-01.py
```

Thirteen local checks cover manifest/output/environment rejection, fresh-consumer
completion, corrupted-copy cleanup, failed/missing retention, expiry and explicit
discard, including refusal of changed bytes and live resources. Both missing-store
regressions failed against the initial generated suite and pass after the fix.
The existing twenty artifact/diagnostic helper checks also pass. Static
syntax/input/libvirt XML/AppArmor checks pass. These are preparation results,
not evidence that the new VM handoff has run.

Progress and result paths:

- `/var/lib/eqemu-vm-proof/build-handoff-01/producer/evidence/report.json`
- `/var/lib/eqemu-vm-proof/build-handoff-01/consumer/evidence/report.json`
- `/var/lib/eqemu-vm-proof/build-handoff-01/suite-result.json`

```sh
sudo systemctl stop eqemu-vm-build-handoff-01-suite.service
sudo python3 /var/lib/eqemu-vm-proof/build-handoff-01/suite.py --discard-artifact
```

The first command cancels a running suite. The second is for a quiescent attempt
when its retained build should be discarded. Do not run it merely to inspect
results. No scheduled cleanup or broader artifact registry is introduced here.
