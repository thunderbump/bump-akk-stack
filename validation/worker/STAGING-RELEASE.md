# Fixed e35 staging build/export

This is source/package preparation for one fixed operation, not an admitted or
qualified build route. It does not release the disposable environment HOLD.
There is no installation operator in this package.

The selection is `fixed-e35-staging-build-export-v1`. It accepts only Server
`e35d4513c44e5eacac796a36fd68cd30acb7706a`, tree
`f288d612781a4ceb9d8595f4d36d797c863080b1`, and the exact sealed ISO declared in
`staging-release-v1.json`. No caller command, environment, image, target or
export-file operand exists. Existing ordinary/profile selections and limits
remain unchanged.

## Source and prospective installed closure

The source baseline is merged Stack `7d2559d93476872425bf0dc386d56deef2a7ad0a`.
The installed baseline is the separately admitted 19-file integration release,
runtime SHA256 `37ceb3371e34e92917cb51609aba244d86191857f029bb71cc5f8b3603fa40f8`,
historical implementation identity `9960d78d7758721c13347a9d243790cd6ac10796574e05db8d153bbd5e25e61f`.

`prepare_staging_release.py` checks the public baseline against the retained v6
readback and prepares a three-line dispatch hook in those installed runtime
bytes. It updates that release's existing inventory and adds six fixed helpers
plus a root-admission policy. Seventeen original files remain byte-identical.
It does not promote the repository's larger worker implementation or PR34.
Baseline bytes are supplied as rollback review data, not an executable rollback.
All original operators, backups, histories and uncertain execution outcomes stay
independent. No installed code, config or ownership is changed by preparation.

The fixed operation refuses until a separately reviewed root-owned
`staging-release-policy.json` binds the exact ordinary config and complete
prospective file inventory. Existing sanitizer/profiling selections cannot use
it. Later admission must verify the exact dependency closure and confinement.
Changing worker bytes changes identity; old ordinary/formatter/AFK recipe pins
are historical. This new frontend records its own digest and claims no AFK reuse
or ordinary validation qualification.

The installed maintenance broker also monitors the current worker bytes. A
later admission must coherently reconcile its existing integrity baseline and
any head/pending state, or it will correctly report installed drift. This
package does not read private broker state, edit that baseline, change broker
code or provide an admission bypass. Current public config and kernel facts
must be checked again at the separately authorized admission boundary.

## Guest operation

The guest verifies all 16 files in the sealed media before starting Docker.
Docker 29.9.3 runs only inside this VM, with private data/socket/state paths.
Its explicit classic `overlay2` configuration disables the containerd
snapshotter, bridge, firewall manipulation and userland proxy. No VFS/fuse
fallback exists. Actual cgroup-v2, OverlayFS, ext4 and Docker driver/backing-fs
checks precede image import. The OCI graph, platform/config identity and imported
diff IDs must match the pinned builder.

The builder's historical entrypoint is overridden. It receives read-only source,
native dependencies, toolchain/vendor and helper mounts; build, Cargo home/target
and output directories are fresh and guest-local. Network is disabled, root
filesystem read-only, capabilities dropped, and no Docker socket is mounted into
the build container. Rust format/metadata/clippy/tests/doctests and a parallel-1
RelWithDebInfo build produce world, zone, shared_memory, eqlaunch, ucs and
queryserv. Two small native source utility controls and the zone Rust bridge
symbol are checked. No ordinary 26-case, ABC, database or staging workload runs.

New outputs must match the sealed runtime library bytes, Perl Config/XS hashes,
ELF architecture/interpreter, needed-library closure, symbol versions and strong
dynamic symbols. No libc, Perl or other shared library is shipped. A new needed
library/version, unresolved symbol, output-size or resource problem is NONPASS.

## Separate release transfer and receipts

The fixed release is exactly 28 regular files, six ELFs plus metadata/logs, with
per-file limits, 690 MiB payload and 691 MiB tar caps. No links, sparse files,
special files, extra names or arbitrary PAX paths are accepted. MANIFEST,
SHA256SUMS, source/tree/run, input manifest and Cargo.lock must agree.

Release bytes use one dedicated guest virtio port and owned host Unix endpoint.
They never consume the integration/profile channel budgets or console log.
Frames are at most 20,000 bytes, carry at most 12,288 raw bytes per chunk, and the
wire cap is 1 GiB. Host capture completes before guest-disk teardown. The client
transfer follows owned VM cleanup. Both sinks keep incomplete bytes as
`release.tar.partial`; only a complete validated archive receives a final name.
The client fsyncs and verifies it before its exact run/digest ACK. Byte completion
and deployability are distinct in `client-receipt.json`.

Build/check exits, container/native/engine cleanup, host VM/scratch cleanup,
guest capture and durable client ACK are separate observations. Missing evidence
stays unknown or not-run. Failed build logs from the four fixed log names are
encoded into the existing bounded serial log before teardown. Failure/partial
receipts remain under the owned job/output directories. Export failure cannot
promote the build, and no recovery, re-export or retry API is added. Interrupted
ExecStopPost can retain an active marker requiring explicit disposition; there
is no automatic repair.

## Preparation commands only

From a clean committed checkout, prepare the finite review package:

```sh
/usr/bin/python3 -I validation/worker/prepare_staging_release.py \
  --media /home/bump/.local/state/eqemu-cdau-staging-deploy/20261106-docker-29.9.3-engine-v1/staging-build-inputs.iso \
  --output /absolute/new-private-review-package
```

Prepare a request without connecting to the worker:

```sh
/usr/bin/python3 -I scripts/build-staging-release \
  --media /home/bump/.local/state/eqemu-cdau-staging-deploy/20261106-docker-29.9.3-engine-v1/staging-build-inputs.iso \
  --prepare-only /absolute/new-request.json
```

After separate admission, HOLD disposition and exact once-run authorization, the
same CLI supports `--once /absolute/new-once.json --output /absolute/new-output`
instead of `--prepare-only`. Do not precreate output. The O_EXCL mode-0600 once
intent is fsynced before the sole connection; uncertain submission is not retried.
This foreground CLI has no automatic job, scheduler or callback behavior.

## Unqualified prerequisites

The retained signed package inventory names kernel/modules 6.8.0-139-generic,
but exact boot config, OverlayFS/virtio-console module bytes and backing
filesystem evidence are unavailable. Package names do not prove support. The
actual guest checks are mandatory and an unsupported setup refuses without an
extra kernel package or host privilege change. Engine authentication is the
selected official HTTPS acquisition plus local hash pin, not a publisher
signature.

The overlay2 peak model is 38,501,677,901 bytes including its 8 GiB reserve, not a
fit result. The guest requires at least that much free space before import.
The 48 GiB guest disk, 4 GiB guest RAM, 6 GiB host cap, swap0, 2 CPUs and host
pids64 remain unchanged and unqualified. The inner build container uses 3 GiB
and pids64 without promising headroom. Kernel/cgroup/namespace/seccomp/AppArmor,
engine cold-start/cleanup, new QEMU virtio-port confinement and real transport
throughput remain runtime gates. No live readiness probe or execution has
established them. A later admission/review must stop on an objective package or
confinement gap rather than widen this route.
