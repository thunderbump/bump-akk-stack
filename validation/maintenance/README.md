# central-ng41 fixed maintenance broker

Source/package preparation only. No root service has been installed or qualified.
The authoritative walkthrough belongs in Operations under
`bump-akk-stack/documentation/central-ng41-validator-maintenance.md`.

`maintenance.py` contains the fixed protocol, source-object verifier and two-file
transaction. `service.py` is the systemd connected-socket entry point. It imports
only protected broker code and stdlib, never installed worker or candidate code.
`client.py` is unprivileged. `install.py` runs only once from a separately reviewed
normal root terminal, after the package/installer hashes have been checked.

Capabilities: health, status, diagnose, fixture-data read, source-binding publish,
and explicit bounded binding rollback. No archive, delete, retention clear,
maintenance retry, arbitrary program, file path or Python capability exists.
The unresolved 02fee state and its guards are outside this feature.

Prepare from clean committed source:

```
scripts/prepare-validator-maintenance --output /absolute/fresh-package --submitter bump
```

This prints the complete root install/uninstall argv and SHA256s as data. It does
not call systemd or run an installer. Installation enables only the new broker
socket. Source publication preserves the ordinary socket's observed state, so it
does not activate the held inactive worker socket. It never launches a workload.

Run harmless source tests:

```
python3 -B -m unittest discover -s tests/worker -p test_maintenance.py -v
```

One test uses a real Unix socket and a NoNewPrivs=1 child under the current UID.
Temporary transaction tests simulate privileged metadata. Neither qualifies
actual root/systemd, mount namespaces, worker execution or candidate results.
