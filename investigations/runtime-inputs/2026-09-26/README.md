# Public runtime input preparation, 2026-09-26

This archive records input preparation for the first fresh-build world/zone proof. No acquired script, package, SQL or game binary was executed on the host. No production or NAS data was used.

The full input media stays in the private local proof directory. Its SHA256 is `5fa2a4822e03ee7693c566e8670ddab5ee35c7a5d25d4671ac57c53ddf82c767`, size 171,806,720 bytes. All 48 payloads, including the manifest, were read independently from the ISO and hash/size checked. The media requires the previously proven v3 build ISO, identified in the manifest.

Preparation scripts describe the one-shot steps used against the retained build-input metadata. They are investigation artifacts, not a production installer or generic acquisition tool. Exact directory ownership and caps are in admission.json. Do not execute SQL, packages, quests or game binaries on the host. A future launcher must verify sealed identities before guest installation and enforce the existing offline VM policy.

## Evidence and limits

- PEQ archive dated 2026-08-22, fetched over HTTPS from the official portal, pinned by captured SHA256. No independent publisher signature/checksum was found. SQL data was inspected without import.
- Core/custom versions match 9328/0. Bot version is 0, with no bot tables and Bots:Enabled=false. This is only the bots-disabled fixture. Three buyer tables repeat with identical empty definitions; 224 CREATE statements define 221 distinct tables.
- Full pinned quest archive verified against all 7,975 Git blob identities. Legacy text bytes are retained; ASCII dependency tokens were scanned without interpreter execution. Selected map files also match upstream Git blob identities.
- Fifteen additional packages, 18,955,506 compressed bytes and 198,671,360 declared installed bytes. Ubuntu signature/index/package hash verification passed. Static solver used base manifest placeholders plus exact build package control metadata, with zero upgrades/removals. Real guest preflight and installation remain mandatory.
- Eight source-matched opcode/config data files are included. runtime-input-contract.json records intended generated paths, credentials policy, fixture order and resource caps. It is not a runnable server configuration or launcher.
- SQL syntax, schema semantics, interpreter loads, actual memory/disk expansion, runtime startup and cleanup have not been tested here. The source MariaDB dump header is 10.11.18; the selected Noble client/server is 10.11.14. Keep its sandbox directive and prove import with the pinned MariaDB client in the guest.

No archive payloads, package binaries, live configuration, credentials, guest filesystem or production data are committed here. Authoritative plan and worklog live in operations-webui.
