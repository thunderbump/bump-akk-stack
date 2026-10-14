# Direct validator upgrade

Prepare the native/actor/debugger package with `validation/prepare.py --with-actor`
without a Rust contract for a dormant upgrade. To activate the pinned actor
workspace, also pass `--rust-contract /reviewed/contract.json`. No host Rust
tool installation or execution is needed.

Freeze the reviewed package into two fixed operator programs:

```sh
python3 -B validation/upgrade/prepare.py --package /prepared/package --output /new/upgrade
```

Preparation executes no root command or VM. Review its declaration, program and
wrapper hashes. This revision upgrades only installed manifest
`810730e94fe14f123c36ab9ad26bfc4543a4f23918b3bef48fc0e1f76f9feb24`.
Without `--activate-rust`, the profile must remain byte-identical, including its existing Rust selection.
For an enabled package, add `--activate-rust` to the preparer. The operator then
freezes its exact profile hash and permits only the declared Rust bundle and
dependency blobs over the unchanged native profile. Activation does not qualify
Rust: the subsequent source card must link the static bridge into the final zone
and pass the enabled fixture. The exact-zone native-link check remains required.
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
