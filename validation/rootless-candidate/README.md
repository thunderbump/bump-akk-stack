# Rootless candidate validation

Run `validation/rootless-candidate/run /absolute/Server FULL_40_CHARACTER_HEAD [IMAGE_DIGEST]`.
Requires Docker rootless prerequisites, systemd user service support, and network access.
Uses only the explicit proof socket; never selects a Docker context. Serializes with
prior proof runs. The supplied checkout must be clean and at the selected commit.
Git archive exports tracked files only; missing submodules fail the build.

Defaults to upstream `eqemulator/eqemu-server:v16`, resolves and records its digest.
Repeat with that digest for image identity reproducibility. Debian package and Rust
dependency provisioning are deliberately not guessed. The upstream image must have
the exact source Rust toolchain installed; otherwise the log is a prerequisite blocker.
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
