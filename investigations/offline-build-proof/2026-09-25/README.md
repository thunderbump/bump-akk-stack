# Offline EQEmu build attempt preparation

Fixed experiment workload and supervisor for the verified 2026-09-25 input bundle. Status: prepared, not executed in a VM. No production data or host package installation is part of this run.

The guest verifies all inputs, uses its real dpkg status to resolve only acquired package versions, installs offline, verifies the pinned vcpkg solver plan, runs a nonzero-exit control, configures/builds with one job and runs upstream utility tests. It exports bounded untrusted progress/results. Host admission, QEMU confinement, no-NIC policy and cleanup are inherited from the synthetic lifetime proof. Seven relevant inherited function ASTs were checked unchanged.

Limits remain 4 GiB guest RAM, 6 GiB QEMU host cap, 32 GiB guest disk, two vCPUs and a shared 1 GiB controller pool. Guest preflight gets 30 minutes, compilation/tests share four hours, worker lifetime is 17,400 seconds including boot/preparation, and supervisor lifetime is 18,000 seconds. The host serial ceiling remains 1 MiB with 16 KiB frames, fresh nonce and strict bounded JSON. Per-command guest output is capped at 64 MiB. No host guest-filesystem mount is used.

Fifteen local tests and schema/policy/input-hash checks pass. Local controls execute only small known shell/Python commands, never acquired code. Tests cover failure propagation, command timeout, log overflow, missing/tampered media, frame limits/order/nonce, incomplete success and cleanup after release. Runtime package resolution, build resource fit and actual workload success remain unproven.

Files use fixed operator-owned experiment paths and are not a general AFK adapter. The generated seed ISO stays outside Git; its identity is in generated-manifest.json. A retained attempt is never overwritten. Cancel the supervisor service to trigger owned worker teardown. A successful attempt still needs a separate fresh repeat before claiming repeatability.
