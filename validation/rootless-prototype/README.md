# Minimal rootless Docker proof

Run `validation/rootless-prototype/run` after host rootless Docker prerequisites
are installed. This original opt-in proof compiles a tiny C++ program, checks
normal execution and one deliberate symbolized ASan failure, and exports evidence
to `~/.local/state/eqemu-rootless-proof/run-*`. It uses the explicit proof socket
and shares its lock/cache with the larger candidate runner. No default Docker
context or live deployment selection changes.

This is a small historical smoke proof, not full sanitizer or EQEmu qualification.
The expanded experiment is documented in `../rootless-candidate/README.md`.
