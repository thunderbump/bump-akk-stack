# Current-candidate build/unit command

`eqemu-validate --source <clean-EQEmu-checkout>` submits one offline producer build and fresh-consumer utility check. The default source is the working directory, so the current AFK PR fixture can select `/usr/local/bin/eqemu-validate` directly. Candidate tests and runner controls belong in the candidate PR. Source, staged files and initialized supported submodules must be clean.

The command returns `0` after all selected checks and owned cleanup pass, `1` after an evidenced candidate compile/test failure and cleanup, and `2` for refusal, infrastructure failure, uncertain evidence or incomplete cleanup. Interruption remains non-pass. Submitted and final JSON log events include the candidate revision, run identity, build identity, selected coverage and cleanup result. Upload refusal and cleanup errors retain a final event.

Prepare a reviewed installation package with explicit retained public dependencies:

```sh
python3 -B validation/prepare.py \
  --input-store <absolute-public-input-store> \
  --websocketpp <clean-pinned-websocketpp-checkout> \
  --output <new-directory-outside-inputs-and-source>
```

The input store layout and fixed dependency identities are in `profile.json`. Preparation checks each dependency's byte count and SHA-256, verifies websocketpp's pinned commit/tree and clean bytes/index, and verifies `recipe-manifest.json` before importing maintained helper code. It copies the checked-in cloud-init payloads and worker/suite templates from `recipes/`; no historical workstation or proof directory is required. Recipe edits require updating the corresponding fixed manifest digest during the same reviewed PR. Changes in the dependency closure require a supported profile update.

The recipes originate from the [prepared package receipt](https://github.com/thunderbump/bump-akk-stack/blob/f631f689b857629bdf17ce506a6166a0bbaa4005/validation/receipts/preparation.json), whose package manifest identity is `b193e5db558ff5346177941ca531b4ab26228f9aad7bbc7942ab33cd3311498a`. Maintained templates remove the prior proof prerequisite and use explicit runtime input locations. Recipe generation binds the current candidate and build identity, then discards the owned transfer artifact after the consumer finishes. Historical receipts and standalone AFK settings are excluded from this package.

Run the prepared `install.py` once with sudo after administrator review and separate host activation authorization. Preparation starts no VM. Installation retains the existing `eqemu-test` submitter group and fixed no-argument helper policy. It refuses existing destinations. Its output names `disable.py` for rollback; disabling revokes admission and stops exact-owned runs while preserving receipts.

Each request verifies the current user's existing NSS membership in `eqemu-test`. If the process inherited stale supplementary groups, only the fixed no-argument sudo helper runs through `sg eqemu-test`; its JSON input remains on stdin. Nonmembers refuse without a prompt or membership/policy change.

Admission can inspect retained terminal receipts from the exact prior package manifest `b193e5db558ff5346177941ca531b4ab26228f9aad7bbc7942ab33cd3311498a`. The administrator-owned prior release must remain installed with all original files and profile seals intact. The helper verifies candidate/build identity, sealed generated recipes, saved completion and live resource absence without rewriting receipts, removing media or stopping old units. Active, unknown or unverifiable prior releases block admission. Public status and cancel remain bound to the current release.

The fixed profile retains a 180 GiB admission / 100 GiB emergency reserve, 32 GiB guest root, 4 GiB transfer artifact, one compile job and 18,000-second supervisor. Eight retained runs block admission pending exact-owned archival. Source uploads and generated media are bounded. No saved-world or NAS data is involved.

Run the cheap package and foreground-command checks without an AFK checkout:

```sh
python3 -B -m unittest discover -s tests/validation -v
```

These checks exercise subprocess exits, interruption/cancellation, identity refusal, cleanup failure, recipe/input tampering and static preparation. VM qualification and host installation remain separate. AFK fixture policy belongs in its current PR configuration after the caller accepts `termination_grace_seconds` and `repairable_exit_codes`; the suggested build-unit profile uses `20400`, `780` and `[1]` respectively. No standalone Validator/Coordinator integration is supported here.
