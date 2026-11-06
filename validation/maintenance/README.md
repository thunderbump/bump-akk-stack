# central-ng41 fixed maintenance broker

This directory contains the service source and package preparation tools. Brian
installed the reviewed `f62ce81` package on his validator host. Its authenticated
root-service health, status, and same-mount diagnostics passed installed read-only
qualification. Privileged source-binding publication and rollback remain unrun,
and installation does not qualify candidate workloads. Other hosts still require
their own installation and qualification.

The [authoritative Operations walkthrough on the LAN](http://192.168.1.230:8081/projects/bump-akk-stack/documentation/central-ng41-validator-maintenance.html)
records the installation evidence, commands, and remaining qualification limits.

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
Temporary transaction tests simulate privileged metadata. These host tests alone
do not qualify actual root/systemd, mount namespaces, privileged transactions,
worker execution, or candidate results. The installed read-only checks above are
separate evidence.
