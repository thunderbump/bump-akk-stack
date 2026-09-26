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

## Attempt 02: offline APT cache correction

Attempt 01 finished in 33.12 minutes. Build and upstream tests passed, but runtime
package simulation exited 100 before installation, SQL import or server startup.
Its suite outcome remains failed and all owned cleanup completed without rescue.
Selected immutable receipts are in `runtime-proof-inputs-02/attempt01-evidence/`.

A real APT simulation using an isolated copy of the pinned indexes, status and
packages reproduced the exact failure. Renaming only six MariaDB package cache
files to include their escaped `1:` version epoch made the same simulation pass
with exactly 15 new packages, no upgrades and no removals. Ubuntu pool filenames
and APT archive cache filenames are different. The sealed media stays unchanged.

`guest-runtime.py` now stages verified packages under the full package/version/arch
cache name, including `%3a` for colons. `test-runtime-packages.py` exercises that
same function against real `apt-get -s --no-download`; original pool names and a
missing archive fail, while corrected staging passes. No acquired code, package
installation, SQL or game binary executes on the host. Its failing-before and
passing-after logs are retained. The 33 existing controls also pass.

The new generator and launcher use separate attempt 02 identities and require
the exact failed attempt 01 result plus completed cleanup. `--check` passes input
hashes, XML and AppArmor syntax without starting a VM. Preparation receipts record
34 local tests. Guest runtime installation and startup remain unproven. Runtime
cancellation and a fresh successful repeat remain required after initial success.

Operator command, after reviewing the local prepared files:

```sh
sudo python3 ~/.local/state/eqemu-vm-proof/offline-runtime-proof-02.py
```

This needs the operator's sudo password. Progress/final evidence goes under
`/var/lib/eqemu-vm-proof/runtime-proof-02/`. Cancel the owned run with
`sudo systemctl stop eqemu-vm-runtime-02-suite.service`. Never reuse retained state.

## Attempt 03: distinguish payloads from mutex files

Attempt 02 passed build/tests, offline package installation/audit, Perl probes and
all five database imports. The shared_memory program exited 0, then the guest
validator reported "Shared memory missing/empty". World/zone startup was not reached.
The failed outcome and complete cleanup are preserved under
`runtime-proof-inputs-03/attempt02-evidence/`.

Pinned EQEmu 4aceae18b94ffaafc08e2b17bc41cd72c77f795d creates zero-byte
`items.lock` and `spells.lock` through common/ipc_mutex.cpp beside the payloads.
The old validator incorrectly demanded every file in that directory be nonempty.
Synthetic filesystem tests reproduce that rejection even with valid nonempty
items/spells. The actual failed guest listing was not retained, so the next real
guest run must confirm the source-backed diagnosis. No upstream code ran on host.

The guest now permits those two known mutex files while requiring regular,
non-symlink, nonempty items/spells payloads. Unknown entries fail. Only payload
sizes/hashes enter the unchanged host protocol. Failure diagnostics include a
bounded inventory of names and sizes. Five regressions pass, alongside all 34
prior controls. Static media/XML/AppArmor checks pass. The launcher verifies
attempt 02's exact failed outcome and cleanup before creating fresh attempt 03.
Sealed inputs, earlier attempt files, limits and isolation are unchanged.

Prepared, not executed. Operator sudo password is required:

```sh
sudo python3 ~/.local/state/eqemu-vm-proof/offline-runtime-proof-03.py
```

Progress/final evidence: `/var/lib/eqemu-vm-proof/runtime-proof-03/`.
Cancel: `sudo systemctl stop eqemu-vm-runtime-03-suite.service`.
Runtime cases, runtime cancellation and a fresh successful repeat remain open.
