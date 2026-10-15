# Direct validator upgrade

Prepare the replacement native/actor/debugger package with
`validation/prepare.py --with-actor --rust-contract /reviewed/current-contract.json`.
Use the exact installed Rust contract. No host Rust tool installation or execution
is needed. Freeze the reviewed package into two fixed operator programs:

```sh
python3 -B validation/upgrade/prepare.py --package /prepared/package --output /new/upgrade
```

Preparation executes no root command or VM. Review its declaration, program and
wrapper hashes. This revision upgrades only installed manifest
`bef324e52c445c8d77ff7ac6ffe2b142b3f0f0ffd6adf60f17c16aa000b6ed21`.
The ordinary repair requires a byte-identical profile, including the existing
Rust selection. Do not add `--activate-rust`: that separate first-activation mode
requires a dormant old release and cannot rebind this enabled contract. Repair
does not qualify Rust; the exact-zone native-link fixture remains required.
`reviewed-check.sh` performs read-only root preflight;
`reviewed-apply.sh` performs the direct upgrade. Both use the checked-byte,
private root staging bootstrap. The declaration pins the current installed
release, replacement manifest and successful Rust provisioning proof.

The root operation holds `request.lock`, discovers every retained run with an
eight-run bound, verifies sealed current/prior readers, checks live suite/worker
absence and holds any remaining empty controller cgroup while rechecking it.
It preserves empty slice debt. Unknown, populated, frozen or descendant groups
refuse. AFK services must be idle and submitter uploads empty.

Admission closes before new release or pointer mutation. The replacement is
copied from the same verified bytes, checked in its root-owned release directory,
and tested against preserved run receipts before wrappers switch. The normal
submitter's identity must name the new manifest before admission reopens.

Input media, policy, AFK configuration and retained receipts remain unchanged.
No job, game, VM, archive operation or old-release deletion occurs. A bounded
durable audit records progress and failure. A failed owned attempt stays disabled;
repeat the same reviewed apply program to finish forward. There is no rollback
or automatic old-release failover interface.
