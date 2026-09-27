# Corrected candidate build and output measurements

This fixed experiment prepares a new offline VM build of EQEmu candidate
`1c561d442638b3da8d20e93ac105f98a227d37f2`. It changes four test files from the
sealed baseline `4aceae18b94ffaafc08e2b17bc41cd72c77f795d`. Original file hashes
are checked before applying the overlay inside the guest. Packages, source
archive, submodules and downloads reuse the identified build-inputs-v3 media.

The archived templates are the earlier successful build04 guest/transport/suite
recipes. Their original utility-success claim is insufficient; preparation
replaces that path with numeric completion validation and real runner controls.
The worker comes from the archived runtime03 isolation controller, with its
runtime media and scenario protocol removed. Recipe, overlay, seed, worker,
package/tool observations, effective configuration and executable identities
remain separately recorded. Templates are frozen reference inputs, not standalone
commands for this experiment.

Order: offline package/input preflight; candidate overlay; configure
RelWithDebInfo; explicitly build the shared runner-control target; require pass,
failed assertion, empty suite, setup exception and body exception outcomes; build
all configured upstream targets; require the real utility suite to complete;
measure world, zone, shared_memory and tests plus loader-resolved libraries.
Missing, partial or contradictory completion cannot pass. Rejected completion
retains the stage, error and sanitized output tail within the existing bounded
failure channel. Expected failures must exit 1 with the precise control counts;
a crash or arbitrary nonzero exit does not satisfy them.

Guest-only `ldd` and `readelf` record dependency paths, NEEDED, RPATH/RUNPATH,
interpreter, build IDs, file hashes and embedded debug-info presence. Measurements
include the complete unstripped binaries and unique resolved libraries. The
summary reports whether that measured set fits 3 GiB; a larger set is a useful
measurement, not an experiment failure. This is not a full runtime closure:
dlopen, Perl/Lua modules, fixtures, maps and fresh-consumer execution remain open.
No artifact is exported, retained or promoted. All guest disks and build outputs
are removed during owned cleanup; bounded host observations and diagnostics remain.

No deployment/database/NAS input is used. No candidate C++, acquired package,
ELF inspection or guest filesystem mount runs on the host. The existing limits
remain: 4 GiB guest RAM, 6 GiB QEMU limit, two CPUs, one compile job, 32 GiB raw
root, 960 MiB worker controller, 64 MiB supervisor within their 1 GiB shared cap.
Guest preflight gets 1800 seconds and build phase 14400; worker lifetime 17400 and
suite lifetime 18000 seconds. Admission requires 180 GiB free and 15 GiB available
RAM; running reserve is 100 GiB/8 GiB. Cleanup preserves failed outcomes and
continues exact-owned slice removal even when controller-budget evidence fails.

Prepare once, before launch:

```sh
python3 investigations/corrected-build/2026-09-26/prepare.py
python3 ~/.local/state/eqemu-vm-proof/offline-corrected-build-01.py --check
timeout 60s python3 -m unittest discover -s investigations/corrected-build/2026-09-26 -v
```

The preparer refuses existing output or an existing root attempt. Preparation
checks candidate diff scope, generated domain length, syntax and input identity.
The twelve local checks cover process exits/timeouts, bad/duplicate/incomplete
completion, exact negative outcomes, bounded retained failure output, protocol
identity and legacy success rejection. They do not compile or run C++.

Launch requires an interactive sudo password on this host:

```sh
sudo python3 ~/.local/state/eqemu-vm-proof/offline-corrected-build-01.py
```

Progress: `/var/lib/eqemu-vm-proof/corrected-build-01/build/evidence/report.json`.
Final result: `/var/lib/eqemu-vm-proof/corrected-build-01/suite-result.json`.
Cancel with `sudo systemctl stop eqemu-vm-corrected-build-01-suite.service`.
Keep central-t0e1.37 open after preparation and after a successful measurement:
artifact reuse and world/zone startup are still separate evidence to obtain.
