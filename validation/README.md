# Current-candidate build/unit command

`eqemu-validate --source <clean-EQEmu-checkout>` submits one offline producer build and fresh-consumer utility check. The default source is the working directory, so the current AFK PR fixture can select `/usr/local/bin/eqemu-validate` directly. Candidate tests and controls belong in the candidate PR. The producer builds and executes `tests_reporting_controls` and all six `tests_runner_controls` modes, including `teardown-exception`, alongside the unchanged ordinary utility suite. It measures and exports both control executables with the existing four server/utility binaries. The fresh consumer verifies all six sealed binaries and their loader closure, then executes the controls and utilities without compilation. Missing control completion, an unexpected exit or an omitted observation cannot pass. Each control execution retains its 30-second deadline and 1 MiB log bound. Source, staged files and initialized supported submodules must be clean.

The command returns `0` after all selected checks and owned cleanup pass, `1` after an evidenced candidate compile/test failure and cleanup, and `2` for refusal, infrastructure failure, uncertain evidence or incomplete cleanup. Interruption remains non-pass. Submitted and final JSON log events include the candidate revision, run identity, build identity, selected coverage and cleanup result. Upload refusal and cleanup errors retain a final event.

`eqemu-validate --identity` is a normal-user, read-only probe. It prints exactly one JSON object with `schema_version:1` and an opaque `identity` string, currently `sha256:<manifest digest>`. It verifies the administrator-owned release path, complete sealed runtime/recipe file set, profile and declared dependency/input contract. It starts no VM, performs no source preparation, invokes no privileged helper and writes no jobs or receipts. Uncertain ownership, malformed declarations or changed package bytes refuse with exit `2` and no success JSON. Identity output stays below 4096 bytes and its identity string below 256 bytes. Large public dependency bytes retain their preparation/admission checks rather than being rehashed by this cheap probe. A newly installed package changes the identity, so callers cannot reuse earlier validation evidence across a validator update.

Prepare a reviewed installation package with explicit retained public dependencies:

```sh
python3 -B validation/prepare.py \
  --input-store <absolute-public-input-store> \
  --websocketpp <clean-pinned-websocketpp-checkout> \
  --output <new-directory-outside-inputs-and-source>
```

The input store layout and fixed dependency identities are in `profile.json`. Preparation checks each dependency's byte count and SHA-256, verifies websocketpp's pinned commit/tree and clean bytes/index, and verifies `recipe-manifest.json` before importing maintained helper code. It copies the checked-in cloud-init payloads and worker/suite templates from `recipes/`; no historical workstation or proof directory is required. Recipe edits require updating the corresponding fixed manifest digest during the same reviewed PR. Changes in the dependency closure require a supported profile update.

Transferred source inventories remain capped at 10,000 files. Initialized pinned submodule inventories use a separate 20,000-file cleanliness budget because the approved vcpkg checkout contains 13,083 files; these local inventories are not transferred or included in the source manifest. Both retain the 256 MiB source-byte bound, 16 MiB index bound and raw-byte/index/HEAD/untracked refusal checks. The source manifest remains capped at 1 MiB.

The recipes originate from the [prepared package receipt](https://github.com/thunderbump/bump-akk-stack/blob/f631f689b857629bdf17ce506a6166a0bbaa4005/validation/receipts/preparation.json), whose package manifest identity is `b193e5db558ff5346177941ca531b4ab26228f9aad7bbc7942ab33cd3311498a`. Maintained templates remove the prior proof prerequisite and use explicit runtime input locations. Recipe generation binds the current candidate and build identity, then discards the owned transfer artifact after the consumer finishes. Historical receipts and standalone AFK settings are excluded from this package.

Run the prepared `install.py` once with sudo after administrator review and separate host activation authorization. Preparation starts no VM. Installation retains the existing `eqemu-test` submitter group and fixed no-argument helper policy. It refuses existing destinations. Its output names `disable.py` for rollback; disabling revokes admission and stops exact-owned runs while preserving receipts.

Each request verifies the current user's existing NSS membership in `eqemu-test`. If the process inherited stale supplementary groups, only the fixed no-argument sudo helper runs through `sg eqemu-test`; its JSON input remains on stdin. Nonmembers refuse without a prompt or membership/policy change.

Admission can inspect retained terminal receipts from exactly three prior package manifests: `b193e5db558ff5346177941ca531b4ab26228f9aad7bbc7942ab33cd3311498a` `fc320a5152c47403f85332c35f14cf61482a3b1b95d52d68ea557382aeaa8c97`, and `a1eec9b33bbca1ba1d3c4b8911a1827ca1b1dd4d2ef72657699a0569201ba83a`. The administrator-owned prior release must remain installed with all original files and profile seals intact. The helper verifies candidate/build identity, sealed generated recipes, saved completion and live resource absence without rewriting receipts, removing media or stopping old units. Active, unknown or unverifiable prior releases block admission. Public status and cancel remain bound to the current release.

The fixed profile retains a 180 GiB admission / 100 GiB emergency reserve, 32 GiB guest root, 4 GiB transfer artifact, one compile job and 18,000-second supervisor. Eight retained runs block admission pending exact-owned archival. Source uploads and generated media are bounded. No saved-world or NAS data is involved.

Run the cheap package and foreground-command checks without an AFK checkout:

```sh
python3 -B -m unittest discover -s tests/validation -v
```

These checks exercise subprocess exits, interruption/cancellation, identity refusal, cleanup failure, recipe/input tampering and static preparation. VM qualification and host installation remain separate. AFK fixture policy belongs in its current PR configuration after the caller accepts `termination_grace_seconds` and `repairable_exit_codes`; the suggested build-unit profile uses `20400`, `780` and `[1]` respectively. No standalone Validator/Coordinator integration is supported here.

## Actor lifecycle profile

The default remains `build-unit-v1`. `eqemu-validate --profile actor-lifecycle-v1` selects the fixed public Plane of Knowledge fixture plus candidate `zone tests:actor-lifecycle`. It compiles once in the producer, then verifies and uses the six transferred executables in the fresh offline consumer. Utilities and reporting/runner controls still run in both guests. The consumer installs the pinned runtime package closure, verifies that no transferred executable or measured library changed, imports five public SQL members in fixed order, removes ambient `poknowledge` spawns, disables the zone controller and external sinks, generates shared items/spells and runs the native scenario. It starts only its owned disposable database and zone command. No world, login, UCS or queryserv process starts.

Prepare the actor-capable package with the existing command plus `--with-actor`. Ordinary preparation does not require runtime media. Actor preparation checks the exact ISO byte count and SHA-256 from `runtime-fixture.json`, reads its sealed payload manifest, and hashes all 47 opaque payload members. The manifest itself makes 48 verified files. No SQL, package or quest code executes during preparation. Missing or changed runtime inputs refuse. The guest checks the same fixed input identities again before use.

Actor selection changes the source input/profile and build identity; unit-only evidence cannot satisfy actor coverage. The installed identity probe seals the actor helpers and declarations too. The recipe remains one fixed scenario, with no arbitrary zone, command forwarding or scenario language.

The runtime allocation is 1800 seconds, including package installation, import, shared data, execution and diagnostics. Ordinary zone execution is capped at 300 seconds. The actor consumer has a 3900-second work deadline within the unchanged 18000-second supervisor and 19000-second foreground work ceiling. The helper reserves the full runtime allocation before starting it and checks the remaining zone allocation before launch. These are limits awaiting real qualification, not measured performance. An 8 GiB runtime growth cap, 8 GiB free floor, bounded DB/shared/log allocations and existing host resource/cleanup gates apply.

### Native command contract for EQEmu `.7.1`

The scenario implementation belongs to EQEmu. This adapter requires one final stdout line, emitted only after native shutdown, beginning with `EQEMU_ACTOR_RESULT ` and followed by a JSON object with exactly these fields:

```json
{
  "version": 1,
  "scenario": "actor-lifecycle-v1",
  "control": null,
  "status": "passed",
  "completed_cases": ["create-duplicate", "name-collision", "native-processing", "retire-recreate", "external-removal-id-reuse", "save-fresh-zone"],
  "cycles": 3,
  "ticks": 1,
  "id_reuse": true,
  "save_restore": true,
  "native_cleanup": true,
  "elapsed_seconds": {"boot": 1.0, "processing": 1.0, "shutdown": 1.0}
}
```

A native-clean completion is refused if the wrapper observes a live descendant after leader exit. The wrapper still kills that exact owned group, but forced rescue cannot establish ordinary actor success or a repairable assertion. A bounded 3000-byte scrubbed native diagnostic tail is exported with the actor observation and failed assertion error so it survives guest-disk teardown. Credentials split across output reads are redacted before persistence.

Counts and times are actual observations. A positive exit `0` requires every fixed named case, three cycles, positive native ticks, actual ID reuse/save-restore and complete native cleanup. Ordinary evidenced assertions use status `assertion-failed`, exit `1`, completed-case/count observations up to failure and `native_cleanup:true`. Refusal or orderly cancellation uses `refused` or `cancelled` and exit `2`. Incomplete native shutdown, missing/duplicate/malformed completion, unknown nonzero or signal, missing maps/CLI/stage, timeout/OOM and incomplete host/DB cleanup stay infrastructure non-pass `2`. The foreground process itself preserves signal exits.

`--force-failure-after-create` is the fixed assertion control and reports `control:"assertion"`. `--wait-for-cancellation-after-create` reports `control:"cancel"`; after actual creation it emits `EQEMU_ACTOR_PHASE {"version":1,"phase":"actor-created"}` as a separate line and flushes it. JSON field order/spacing do not matter. The guest forwards that phase immediately to the worker, host status and foreground `actor-created` event. The caller can then signal the foreground process. Waiting is bounded to 60 seconds in native code; absence of a phase is refusal. The flags are mutually exclusive and unknown arguments must refuse. The adapter accepts no ordinary positive result for a control invocation.

### One-build qualification controls

Qualification is separately authorized host work in `.4.2`. One explicit positive actor invocation with `--retain-artifact` may retain exactly one verified artifact for at most one day. Native and host worker cleanup must still complete; the final receipt separately identifies intentionally retained artifact custody. Regular PR validation discards its artifact.

Run controls against that exact clean source checkout with `--profile actor-lifecycle-v1 --reuse-artifact <positive-run-id> --qualification-control assertion`, `missing-map` or `cancel`. Each starts a fresh consumer only, using the existing sealed artifact. Reuse requires the same submitter, candidate/tree/source-input manifest, actor profile, current installed package/build identity and successful positive cleanup. Expired, changed, unknown or unit-only evidence refuses before run-directory creation. Controls never return pass. Missing-map removes only the disposable base map before the required-map gate and cannot launch the actor. Cancellation exposes the live creation phase before caller interruption. Controls own only their copies and preserve the original custody bytes and receipts.

Release the original with `eqemu-validate --release-artifact <positive-run-id>`. This exact-owner operation starts no jobs and verifies quiescent/absent workers, original custody and artifact bytes. Active or uncertain control consumers block release. Expired artifacts remain owned and inspectable until this explicit release; no unrelated resource is pruned. The one-artifact and eight-run limits remain fixed. A positive run plus three fresh control runs needs four available receipt slots; `.4.2` must establish that headroom through separately reviewed exact-owned archival.

Cheap source tests and static preparation establish this adapter's wiring. They do not establish that the future native command boots without world or passes actor assertions. Actual runtime qualification remains `.4.2` after `.7.1` supplies the command.
