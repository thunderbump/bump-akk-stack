# Rootless candidate validation

Run `validation/rootless-candidate/run /absolute/Server FULL_40_CHARACTER_HEAD [IMAGE_DIGEST]`.
Requires Docker rootless prerequisites, systemd user service support, and network access.
Uses only the explicit proof socket; never selects a Docker context. Serializes with
prior proof runs. The supplied checkout must be clean and at the selected commit.
Archives the selected source and verifies and includes each initialized pinned submodule. Use a separate clean clone when the working checkout has edits.

Defaults to upstream `eqemulator/eqemu-server:v16`, resolves and records its digest.
Repeat with that digest for image identity reproducibility. A derived Dockerfile installs Debian build dependencies and the exact Rust channel
from the selected source rust-toolchain.toml. The base digest, derived image ID,
submodule commits and image build log are retained. Public dependency downloads require network access.
Uses the image's `/opt/eqemu-perl` to preserve Perl ABI. No production mounts,
published ports, host network, DB credentials, or deployment entrypoint are used.

The two-hour candidate process runs under 7 GiB memory including swap, two CPUs,
512 PIDs; daemon service has 8 GiB/two CPUs. Artifacts remain under
`~/.local/state/eqemu-rootless-proof/run-*`: source archive, commit, image digest,
Docker inspection, logs and process exit. Cleanup removes the named container and
stops the owned transient daemon, retaining the image cache. Cleanup errors are
best effort and do not constitute a verified cleanup receipt.

Stages: locked Rust tests and release build, CMake full build with utility tests and
C++ ASan/UBSan, native utility suite. Rust and Cargo CXX are uninstrumented.
Native controls and a fresh public-fixture smoke follow the build. Rust/CXX instrumentation remains out of scope.
Set `ROOTLESS_SMOKE_FIXTURE` to the approved public runtime payload directory, with its sibling `runtime-bundle-manifest.json`.

## Observed run, 2026-11-09

Source d58d1fa4c at its full recorded HEAD, upstream v16 digest
`sha256:b6f46ebc00f8da8f103197cf2252be8173317b85fbc42716c994ad33d5da39f7`.
Actual rootless run exported evidence to
`/home/bump/.local/state/eqemu-rootless-proof/run-Ap1B59jH` and exited 1 at
`command -v cargo`. Perl 5.32.1 and CMake 3.25.1 were available.
No candidate compilation or tests completed. Next step is an additive image layer
with the selected source's pinned Rust toolchain, then rerun this command.

## Completed proof, 2026-11-09

Source `d58d1fa4cb5ce656984d6ebaaeb78c8b70b06c85`, Rust 1.99.0,
base digest as above. Evidence:
`/home/bump/.local/state/eqemu-rootless-proof/run-YHO3WgBs`.
Locked Rust suites passed 9 + 34 + 1 tests and release build passed.
All 427 C++ build steps completed with native ASan/UBSan enabled; utility
receipt finalized 95 selected/started/completed, zero failures, process exit 0.
Perl headers and library both resolve inside `/opt/eqemu-perl` 5.32.1.
An earlier run exposed mixed system Perl linkage; explicit include/library paths
fix it. vcpkg needs Git baseline history, so the container clones its public
repository and checks out the exact archived submodule commit before configuring.

No sanitizer positive/negative controls were run, so this proves a successful
instrumented native utility run, not qualified sanitizer detection. Rust/CXX
instrumentation and fresh DB/world/zone scenarios remain untested. Dependency
package resolution and rustup bootstrap are network inputs, not hermetic pins.

Repeat:
```
validation/rootless-candidate/run /absolute/clean/Server d58d1fa4cb5ce656984d6ebaaeb78c8b70b06c85 eqemulator/eqemu-server@sha256:b6f46ebc00f8da8f103197cf2252be8173317b85fbc42716c994ad33d5da39f7
```

## Control checks (not yet qualified)

`controls.sh` runs the existing native control executable after compilation,
requires the normal case to exit zero, and checks each deliberate failure for
its expected sanitizer report and a symbolized sanitizer_controls.cpp line.
Ordinary utility execution retains fatal ASan/UBSan options. This addition has
not completed actual qualification. Attempt `run-LK4vFVPI` was interrupted during
dependency rebuilding; it establishes no control or smoke result. DB/world/zone
smoke remains unimplemented.

## Increment evidence, 2026-11-09

Current source: `d58d1fa4cb5ce656984d6ebaaeb78c8b70b06c85`.
Run `run-2UBddwhh` retained under `~/.local/state/eqemu-rootless-proof`.
Derived image `sha256:f0ebf5277b3917c48a8d1c4caef00023af1fd99dce64a28bda12385cab13af2f`.
Rust 44 tests/release and native 427 steps passed. Original controls receipt:
pass 0, UAF/OOB/UB/leak 1, expected diagnostics and source lines checked.
Native utility finalized 95/95, zero failures. Smoke preparation first hit a Python
archive API compatibility error, corrected to GNU tar against verified public inputs.

The retained local diagnostic snapshot was resumed to investigate smoke without
rebuilding dependencies. Its repeated leak control crashed with 139 without a report;
that repetition is NOT a qualifying control run. The original control logs remain
separate. The manual resume command continued to utility/smoke despite that control
failure; it is diagnostic evidence, not an end-to-end passing runner receipt.
Utility again finalized 95/95. Fresh MariaDB imports completed. `shared_memory`
connected to the scratch DB, then LeakSanitizer reported 1424 bytes in three
allocations through Database/SharedDatabase constructors and exited 1.
World/zone readiness was not reached. Candidate source fixes are outside this
Stack increment. No sanitizer suppression was added. Full smoke remains unqualified.
`resume.log`, `resume-container.json`, and `resume-results/smoke.json` retain the
failure and clean MariaDB exit 0. Owned containers were removed and daemon verified
inactive. Images remain as diagnostic cache.

Prior interrupted `run-LK4vFVPI` inspection/results were recovered and its exact
container removed. Actual derived image was `sha256:28a874bae9aca52ab6c168039cc002fa24ee4689cf0a74d3fa032f5d507e09cb`;
`08b482...` was its container ID. Recovered state was stopped, exit 255,
OOMKilled false. This does not establish the reason for daemon shutdown.

Repeat the full corrected runner:
```
ROOTLESS_SMOKE_FIXTURE="$HOME/.local/state/eqemu-vm-proof/runtime-qeynos2-inputs-20261025/payload" validation/rootless-candidate/run "$HOME/.local/state/eqemu-rootless-proof/source-proof" d58d1fa4cb5ce656984d6ebaaeb78c8b70b06c85 eqemulator/eqemu-server@sha256:b6f46ebc00f8da8f103197cf2252be8173317b85fbc42716c994ad33d5da39f7
```
