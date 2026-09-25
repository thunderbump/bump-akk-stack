# Offline VM proof source archive

This directory preserves the local synthetic investigation sources used through September 25, 2026. It is reference material for the operations documentation, not an installable worker, supported command interface, or AFK integration. No default Compose behavior changes.

The authoritative overview and module documentation live in the [operations UI](http://localhost:8081/projects/bump-akk-stack/documentation/test-isolation.html). Acceptance evidence and limitations are described there. The recovery/concurrency suite passed on September 25 from 11:44:30 to 12:00:04 PDT.

Sources are copied byte-for-byte. `archive-manifest.json` records their hashes. Generated per-case workers are intentionally retained because those exact variants ran. Paths and root-only internal modes refer to the original host experiment. Do not run these archived scripts as an installation or rerun recipe. Prior retained run state and omitted media are required by their checks.

The archive excludes VM images, ISO media, database backups and credentials. Small JSON receipts describe synthetic fixtures. The recovery worker report copies omit verbose QEMU and guest-report fields; the manifest gives each original report's hash and omitted keys. Top-level suite receipts remain byte-identical. The preserved source does not establish immunity from hypervisor/kernel vulnerabilities, host reboot recovery, or correctness of arbitrary guest-reported gameplay results.
