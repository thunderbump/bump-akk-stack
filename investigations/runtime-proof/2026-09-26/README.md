# Fresh-build runtime proof, attempt 01

Prepared 2026-09-26; no VM has run. This extends the preserved offline build proof with a same-guest runtime adapter. It reuses fixed build and runtime input media. Generated seed bytes remain local; generated-manifest.json records their identity.

The initial execution builds the server and runs utility tests, then installs the fixed runtime package closure in the guest. It initializes an owned MariaDB database and boots shared_memory/world/static poknowledge with one required water map withheld from a writable copy. It requires all other readiness and a continuing world connection, records that startup acceptance is false, and checks graceful shutdown/state. It stops the database and deletes that case's owned data directory. The positive case uses a newly initialized database, fresh SQL import and a separate runtime tree with the complete maps, followed by at least 60 seconds and seven health samples.

Input/media hashes, actual guest package selection, schema/version, empty player/login groups, required content, all table checksums, binary identity, process identity/connection, map/quest/time readiness, service exits and bounded logs are checked. The guest rejects changes outside the explicit startup-state table set. The host treats all guest facts as untrusted and independently checks confinement, host reserves, lifecycle, immutable media and exact-owned cleanup.

A missing legacy plugin.pl hook is the sole explicit optional Perl-file exception; the real pinned plugin directories and modules are required. SQL, quest and fatal process errors still fail, including errors during shutdown. Source console category labels are truncated to ten characters, which the error matcher accounts for. Direct guest path strings used by shared_memory and opcode loaders retain trailing slashes.

## Limits and controls

Retains 4 GiB guest/6 GiB QEMU/2 vCPU/one compiler job/32 GiB disk, controller 1 GiB, offline devices, no host shares, 180 GiB admission disk and 100 GiB reserve. Four-hour shared build/runtime deadline, runtime sub-limit 30 minutes, controller/worker external deadlines unchanged. Serial 1 MiB, frames 16 KiB, frame count 1,500; stage-name allowance 100 for fixed import/snapshot steps. Services each drain at most 64 MiB console output; log/shared-memory and DB growth checks enforce the prepared 8 GiB additional guest disk budget. Guest and host OOM counters gate success.

17 new runtime controls and 16 retained build controls passed, along with fixed input hashes, libvirt XML schema and AppArmor parser checks. Tests execute only trusted synthetic local processes and mocked evidence; no downloaded scripts, packages, SQL, quests or game binaries run on the host.

## Remaining proof

Operator sudo is required to launch. This first attempt does not itself prove real guest installation/import/startup. Runtime cancellation and a fresh successful repeat are separate follow-up attempts after first-run evidence. No actor, player, bot, production migration or general AFK execution is enabled. The investigation remains open.

Authoritative operating instructions and findings live in operations-webui. These scripts are a fixed investigation kit, not a production installer or a general validation interface.
