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
No sanitizer controls or DB/world/zone smoke are claimed. Fresh test DB smoke and
cross-language sanitizer coverage remain later increments after build prerequisites.

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
