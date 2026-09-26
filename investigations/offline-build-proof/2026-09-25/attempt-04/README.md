# Fresh repeat of successful attempt 03

Prepared 2026-09-26. Attempt 03 passed offline package installation, dependency configuration, server compilation, upstream utility tests and host cleanup in 33.1 minutes. Full receipts are in `../receipts/attempt-03/`.

Attempt 04 uses the exact same base, seed ISO, build input ISO, guest program, host protocol, build flags and resource limits. The fresh base produces empty dependency/compiler caches. Only host resource identity and owned output paths change. Seed metadata retains its original instance ID; each attempt starts from a fresh pristine base, so cloud-init state is not reused. The preparation manifest records byte equality. No additional package acquisition or input ISO copy was needed.

The launcher requires the exact successful prior suite receipt, completed cleanup, no rescue, no active lease and absent prior scratch data. Sixteen local tests and static policy/schema/input checks passed. Review the checked launcher, then run:

```sh
sudo python3 -I ~/.local/state/eqemu-vm-proof/offline-build-proof-v4.py
```

Progress: `/var/lib/eqemu-vm-proof/build-proof-04/build/evidence/report.json`.
Result: `/var/lib/eqemu-vm-proof/build-proof-04/suite-result.json`.
Cancel: `sudo systemctl stop eqemu-vm-build-04-suite.service`.

Prepared, not yet executed. Repeat acceptance requires matching input/tool/configuration identities, passing build and tests, and successful host cleanup with no rescue. Compare timing, memory, guest disk and binary hashes. This is operational repeatability; bit-for-bit binary reproducibility is not presumed. World/zone startup with these new binaries and general AFK integration remain separate investigations. No production or NAS input is used.
