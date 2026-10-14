# Direct validator upgrade

Prepare the native/actor/debugger package with `validation/prepare.py --with-actor`
and no Rust contract. This keeps Rust execution dormant until the actor workspace
and locked dependency contract exist. No host Rust tool installation is needed.

Freeze the reviewed package into two fixed operator programs:

```sh
python3 -B validation/upgrade/prepare.py --package /prepared/package --output /new/upgrade
```

Preparation executes no root command or VM. Review its declaration, program and
wrapper hashes. This revision upgrades only installed manifest
`13ab61457e2174e8004fd9ce2b5a524b5631c9aa0b75b61b836ed9fa843cef87`,
retaining its native/actor/debugger profile and dormant Rust contract.
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
