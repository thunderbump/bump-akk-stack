# Rust input and component proof commands

This directory provides the tiny safe-core/CXX fixture and bounded proof tools.
It does not launch containers or VMs, install a host validator, or prove actor
behavior. Run workloads only in the reviewed isolated execution scope.

Acquire the five official Rust 1.99.0 components as opaque checked bytes:

```sh
python3 -B validation/rust/prepare_inputs.py acquire --output /new/components
```

In an isolated trusted Cargo environment, generate the fixture's lockfile and
vendor closure with `cargo vendor --locked`. Keep the printed Cargo source
configuration, replacing its directory value with the literal `"@VENDOR@"`.
Archive the contents of the vendor directory, without its enclosing directory,
as an uncompressed tar. This repository's fixture contains the identified
lockfile; no host Cargo execution is required by preparation.

```sh
python3 -B validation/rust/prepare_inputs.py bundle \
  --components /retained/components --vendor /retained/vendor.tar \
  --config /retained/vendor-config.toml --output /new/bundle
python3 -B validation/rust/prepare_proof.py \
  --source validation/rust/fixture --bundle /new/bundle/rust-inputs.tar \
  --output /new/proof-inputs
```

Review the preparation receipt and helper identities before execution. In an
isolated producer with Python 3.12+, GCC/binutils and an executable writable
work directory, make the guest-only marker available inside the isolated
filesystem at `/opt/eqemu-proof/BUILD_GUEST_ONLY`. Mount source/helper/bundle
inputs read-only. The producer's prefix, Cargo cache, target directory and logs
stay within its fresh owned output directory.

```sh
python3 -B /stack/validation/rust/proof.py \
  --source /inputs/fixture --bundle /inputs/rust-inputs.tar --output /work/positive
```

Repeat with a separate output and `--control format`, `lint`, `test`, `doctest`,
`unsafe` or `link`. The runner changes only its disposable fixture copy before
taking the control's identity. Each result records its exact contract, named
observations, source custody and bounded diagnostics. It has a 1200-second
global command deadline; Rust stages allow 300 seconds each, native link 60
seconds and the final native call 10 seconds. No control can return success.
The outer execution owner must also bound resources, interruption and teardown.

After a positive producer, copy only the native executable and its measured
loader closure into a fresh consumer without Rust/Cargo. Verify their hashes
and require exactly `EQEMU_RUST_BRIDGE_RESULT 42`. That is component evidence;
the maintained VM/worker proof and final actor zone integration remain distinct.

To prepare a maintained Rust-capable package, pass `--rust-contract` to
`validation/prepare.py`. The reviewed JSON contract names the exact workspace,
package/features/test selection, dependency Git blobs and sealed bundle path in
the existing public input store. See `rust.contract` for its fixed schema. The
default package remains ordinary C++ validation. New Cargo/lock/toolchain
declarations require a supported closure/package update; source code changes
without dependency changes retain the same contract.

For enabled profiles the final zone must contain the scalar versioned native
symbol `eqemu_rust_bridge_v1`. The worker requires its exact linked zone hash to
match the normal executable inventory. The marker does not establish gameplay
behavior. It prevents a core-only or stale-binary result from being reported as
the enabled native-link stage.
