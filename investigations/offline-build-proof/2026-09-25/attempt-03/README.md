# Attempt 03 preparation

Attempt 02 failed while linking the upstream test executable: system `-lz` was missing. Configuration passed, but utility tests did not run. Its complete failure and cleanup receipts are retained in `../receipts/attempt-02/`.

This retry adds only Ubuntu zlib1g-dev 1:1.3.dfsg-3.1ubuntu2.2 amd64 to the media and updates package provenance. The base manifest already records the matching zlib runtime and libc6-dev. The acquired archive is authenticated through retained signed Ubuntu indexes. APT cache naming includes the encoded version epoch. No acquired code or maintainer scripts ran on the host.

The new guest probe compiles and runs a tiny program using system `-lz` immediately after package installation. Required guest evidence includes that probe. Server source, port versions, isolation/resource limits and build options are unchanged. Sixteen local tests, static input/policy/schema checks and an isolated APT simulation passed. The simulation uses manifest-derived status plus the signed zlib runtime stanza; actual guest package resolution remains required. Seven worker lifecycle/isolation function ASTs match attempt 02.

Run after reviewing these exact inputs:

```sh
sudo python3 -I ~/.local/state/eqemu-vm-proof/offline-build-proof-v3.py
```

Owned output root: `/var/lib/eqemu-vm-proof/build-proof-03`.
Cancel: `sudo systemctl stop eqemu-vm-build-03-suite.service`.

Prepared, not yet executed. Full build, upstream test execution, cleanup and a fresh repeat are still required. No production or NAS data is used.
