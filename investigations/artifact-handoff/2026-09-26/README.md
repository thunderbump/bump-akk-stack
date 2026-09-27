# Synthetic artifact handoff preparation

This experiment belongs to central-t0e1.37. It prepares two sequential offline VMs using the reviewed runtime-proof-03 controller as a fixed template. It does not compile EQEmu, start game services, or access deployment databases or backup mounts.

Run helper checks from the repository root:

```sh
timeout 60s python3 -m unittest discover -s investigations/artifact-handoff/2026-09-26 -v
```

`prepare.py` creates immutable local inputs and a launcher beneath the existing `~/.local/state/eqemu-vm-proof` cache. It needs `cloud-localds` and the already acquired base image. It starts no VM and refuses to overwrite an existing preparation or attempt. The launcher accepts `--check` without sudo. Its default action requires sudo and starts the systemd suite.

The producer formats a fully allocated 4 GiB raw disk inside its VM and writes a small known file and inventory. After shutdown and cleanup, the host hashes the opaque disk and marks it eligible. The consumer receives a separate read-only copy, verifies and copies the payload inside its VM, and attempts a write to prove the device is read-only. Both guests exercise invalid inventory and diagnostic controls. The suite removes the retained disk after both workers stop, preserving evidence and custody records.

`artifact.py` handles byte copying, hashing, and guest inventory checks. `diagnostics.py` accepts utility completion only with a successful exit and positive matching completion counts. Its diagnostic tail redacts complete configured secret values before export and bounds the exported UTF-8 bytes. It is not a general secret detector. These helpers are not yet integrated into the EQEmu service scenario.

The proof inherits worker admission, ownership checks, controller/QEMU memory limits, disk reservations, and cleanup from the archived runtime worker. Preparation checks are not proof that VM handoff or cleanup succeeds. A failed run retains its outcome even if later rescue cleanup succeeds.

The first handoff is exploratory. Producer/export cancellation and failed-publication controls remain mandatory before handoff qualification or an expensive build.

At initial preparation, the pending work was: executing this proof, compiling and running the separate C++ runner controls, measuring the real executable/library closure, sealing an actual build, integrating service diagnostics, and rerunning the world/zone success and failure scenarios. No general artifact cache, automatic retry policy, or retention service is introduced here.

## Attempt 02 correction

Attempt 01 passed the producer and hit the consumer controller memory limit before VM startup. Kernel accounting attributes most memory to dirty file-cache pages. `copy_blob` now flushes and syncs each 16 MiB window, then advises releasing the completed source/destination cache ranges. `copy_probe.py` runs a synthetic 4 GiB copy in an unprivileged systemd service under the same 960 MiB cap. The preserved before/after receipts show 960 MiB versus about 44 MiB copy peaks; the unchanged byte digest passed both runs. The old probe reproduced memory-limit pressure, not an OOM kill. The original VM attempt supplies the OOM evidence.

Cleanup records controller-budget errors separately from resource removal and still keeps the suite failed. Attempt 02 has fresh identities. Before launch it verifies the immutable failed-attempt receipts and absence of its workers/resources, then removes only the exactly identified old controller slice file. It adds a reconciliation receipt without modifying the failed result. Sudo is still needed for that operation and the VM launch.

`preparation.json` remains attempt 01's receipt. The new generated receipt is `preparation-02.json`. The original local inputs, launch script and failed-attempt receipts remain unchanged. A successful host copy probe did not establish a successful VM consumer at preparation time. Attempt 02 subsequently passed, as recorded below.

## Fixed failure controls

Attempt 02 passed both guests and complete cleanup in 341.87 seconds. Its immutable receipts are under `receipts/attempt-02/`. The full controller pool recorded memory-limit pressure but no OOM; the separate copy-phase measurement does not describe peak memory of the entire run.

`prepare_controls.py` prepares attempt 03 from the hash-pinned successful controller, with two sequential producer cases. `cancel` waits for an authenticated export-start checkpoint while the guest output filesystem is mounted, then stops the owned worker controller. `publish` allows a normal producer completion and injects an I/O exception at custody finalization. This fixed test adapter is embedded only in the publication control's worker. It is not a production or gameplay failure switch.

The ordinary publication path now applies private file mode before the atomic custody rename and records finalization exceptions as publication failure. A pending record remains ineligible. The control suite requires the intended cause, a rejected workload, actual consumer-custody refusal and successful owned cleanup. Unknown crashes, unexpected success, incomplete cleanup or an eligible artifact do not satisfy the negative controls. The final suite may pass because both expected failures were handled correctly; the underlying worker outcomes must remain non-pass.

At preparation time these controls had not executed; their later success is recorded below. They test cancellation during producer export and failure of final custody promotion, not power-loss durability, every filesystem error, consumer-copy cancellation or whole-AFK cancellation. The other artifact-content controls and eventual real candidate build remain separate qualification requirements.

## Transfer rejection coverage

Attempt 03 subsequently passed both fixed controls and cleanup in 329.62 seconds. The exact results are preserved under `receipts/attempt-03/`; both worker outcomes remain failed as intended. No eligible artifact remained, consumer custody admission refused both cases, and cleanup needed no rescue.

The remaining byte and flat-inventory checks run against small synthetic files through the existing helpers. `test_transfer_rejections.py` covers same-size mutation, truncation, actual symlinks/FIFOs, a timeout after copying starts, expired empty transfers, deadlines crossed during final flush, wrong identity and reduced file-count/byte limits. Existing tests cover duplicates, traversal, declared special types and exact payload verification. These are not new VM scenarios.

The audit found that an expired empty transfer or late final flush could return success. Deadline checks now cover entry and completion, including synchronization. They reject late completion; they do not make a blocking filesystem syscall preemptible. The worker service deadline remains the outer bound. Twenty helper tests pass. A fresh 4 GiB copy probe also passed under the same memory cap, recorded in `receipts/copy-deadline-fixed.json`.

This closes the identified synthetic transfer-helper gaps before preparing the corrected candidate build. It does not prove malformed guest filesystem handling, power-loss durability, or a real executable/library package. The synthetic identity exercises exact identity rejection; real source/toolchain/build-profile identities, loader/symbol closure, nested payload handling if needed, and utility completion must be established with the real candidate before it can be promoted. The completed VM inputs are immutable and still contain their original helper versions; the deadline correction is tested locally and will enter the next fresh worker.

Run the helper suite with the documented outer timeout when automating it. This also bounds a future regression that accidentally makes a FIFO open block.
