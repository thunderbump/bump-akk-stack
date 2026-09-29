# Current-candidate build/unit adapter

`eqemu-validate --source <clean-EQEmu-checkout>` submits one offline build and fresh-consumer utility check. The default source is the working directory, so AFK can use the command settings in `afk-build-unit.json` with the EQEmu workspace. The same installed command is called by `scripts/validate`; `--diagnostic` retains the existing startup replay.

This profile covers compilation and utility tests. It does not qualify runtime scenarios or deployment. Implementation and review remain separate and unsandboxed.

Prepare a reviewed installer with `python3 -B validation/prepare.py --output <new-directory>`. It reuses the pinned local proof templates and requires the existing diagnostic submitter group. Installation starts no VM and changes no diagnostic-runner entry point. Run the prepared `install.py` once with sudo; its output identifies the installed `disable.py` for rollback. The installer refuses existing destinations. Disabling revokes admission and stops exact-owned runs, preserving receipts.

A run uses the prior 180 GiB admission / 100 GiB emergency disk reserve, 32 GiB guest root, 4 GiB transfer artifact, one compile job and 18,000-second supervisor. It discards its own transfer artifact after the fresh consumer. Source uploads and generated media are bounded; at eight retained runs, admission refuses pending an administrator retention review. No production or NAS data is used.

Use `AFK_CHECKOUT=<afk-main-checkout> python3 -B -m unittest discover -s tests/validation -v` for command tests including the real AFK Validator. Installation and a real candidate run are separate qualification steps; synthetic success is not proof of VM execution.

Authoritative operational status and run evidence live in the [EQEmu project documentation](http://localhost:8081/projects/bump-eqemu/documentation/project-status.html).
