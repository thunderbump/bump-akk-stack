# Offline EQEmu build input preparation, 2026-09-25

Historical experiment source and compact receipts. These scripts prepare data for an offline VM. They are not a general acquisition service or AFK adapter. They use fixed local experiment paths and must not be treated as portable production commands.

No acquired source, vcpkg executable, package maintainer script or port recipe ran on the host. Source enumeration is static, not a vcpkg solver result. Ubuntu resolution used manifest-derived installed-package placeholders, not the guest's complete dpkg status. Actual guest resolution, installation, configure/build and tests remain pending.

The sealed ISO contains 151 verified files including its manifest, totals 467,603,456 bytes, and has SHA256 `8c296a41d6a23d33985a4d820cab1727738155d1d2ad10e2583775597455cb9b`. Binary inputs and full Ubuntu indexes stay outside Git. The manifest records their identities. All ISO payloads were read back through isoinfo and compared against expected size and SHA256.

Preparation ran in named transient user services with 1 GiB memory, no swap, two CPU equivalents, 64 tasks and bounded time/file size. The acquisition script also checks its 2 GiB task cap and 180 GiB host free-space threshold. These are bounded trusted acquisition operations, not a proven sandbox for candidate execution.

Only a temporary independent clone made to verify the vcpkg bundle was deleted. Historical caches, production deployments and NAS data were untouched. Canonical findings and the proposed guest execution protocol live in operations-webui.
