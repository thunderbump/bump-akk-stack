# Synthetic artifact handoff preparation

This experiment belongs to central-t0e1.37. It prepares two sequential offline VMs using the reviewed runtime-proof-03 controller as a fixed template. It does not compile EQEmu, start game services, or access deployment databases or backup mounts.

Run helper checks from the repository root:

```sh
python3 -m unittest discover -s investigations/artifact-handoff/2026-09-26 -v
```

`prepare.py` creates immutable local inputs and a launcher beneath the existing `~/.local/state/eqemu-vm-proof` cache. It needs `cloud-localds` and the already acquired base image. It starts no VM and refuses to overwrite an existing preparation or attempt. The launcher accepts `--check` without sudo. Its default action requires sudo and starts the systemd suite.

The producer formats a fully allocated 4 GiB raw disk inside its VM and writes a small known file and inventory. After shutdown and cleanup, the host hashes the opaque disk and marks it eligible. The consumer receives a separate read-only copy, verifies and copies the payload inside its VM, and attempts a write to prove the device is read-only. Both guests exercise invalid inventory and diagnostic controls. The suite removes the retained disk after both workers stop, preserving evidence and custody records.

`artifact.py` handles byte copying, hashing, and guest inventory checks. `diagnostics.py` accepts utility completion only with a successful exit and positive matching completion counts. Its diagnostic tail redacts complete configured secret values before export and bounds the exported UTF-8 bytes. It is not a general secret detector. These helpers are not yet integrated into the EQEmu service scenario.

The proof inherits worker admission, ownership checks, controller/QEMU memory limits, disk reservations, and cleanup from the archived runtime worker. Preparation checks are not proof that VM handoff or cleanup succeeds. A failed run retains its outcome even if later rescue cleanup succeeds.

The first handoff is exploratory. Producer/export cancellation and failed-publication controls remain mandatory before handoff qualification or an expensive build.

Still pending: executing this proof, compiling and running the separate C++ runner controls, measuring the real executable/library closure, sealing an actual build, integrating service diagnostics, and rerunning the world/zone success and failure scenarios. No general artifact cache, automatic retry policy, or retention service is introduced here.

## Attempt 02 correction

Attempt 01 passed the producer and hit the consumer controller memory limit before VM startup. Kernel accounting attributes most memory to dirty file-cache pages. `copy_blob` now flushes and syncs each 16 MiB window, then advises releasing the completed source/destination cache ranges. `copy_probe.py` runs a synthetic 4 GiB copy in an unprivileged systemd service under the same 960 MiB cap. The preserved before/after receipts show 960 MiB versus about 44 MiB copy peaks; the unchanged byte digest passed both runs. The old probe reproduced memory-limit pressure, not an OOM kill. The original VM attempt supplies the OOM evidence.

Cleanup records controller-budget errors separately from resource removal and still keeps the suite failed. Attempt 02 has fresh identities. Before launch it verifies the immutable failed-attempt receipts and absence of its workers/resources, then removes only the exactly identified old controller slice file. It adds a reconciliation receipt without modifying the failed result. Sudo is still needed for that operation and the VM launch.

`preparation.json` remains attempt 01's receipt. The new generated receipt is `preparation-02.json`. The original local inputs, launch script and failed-attempt receipts remain unchanged. A successful host copy probe does not establish a successful VM consumer; that remains the fresh experiment's question.
