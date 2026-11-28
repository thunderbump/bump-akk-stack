"""Host side of the headless Qeynos2 journey.

Owns input identity, a disposable rootless Docker daemon started for one
command, the one container it runs, result assembly and cleanup. Candidate
binaries run only inside that container (no network, private loopback).
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fixture as F  # noqa: E402

REPO = HERE.parent.parent
HARNESS_FILES = ("guest.py", "fixture.py", "servertrace.py", "checks.py", "observer.py", "census.py")
DEFAULT_STATE_ROOT = Path.home() / ".local/state/eqemu-rust-journey"
DEFAULT_IMAGE = "sha256:630e294d6568c1b5f253f2967c5704b52ee3d0e5f73db0ba2ab01de77e71e873"
RESULT_SCHEMA = "qeynos2-journey-result/v1"
LABEL = "eqemu-rust-journey=1"
UNIT_PREFIX = "eqemu-rust-journey-"

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_ENVIRONMENT = 3
EXIT_CLEANUP = 4

GUEST_TIMEOUT = 900
DAEMON_START_TIMEOUT = 60
DAEMON_RUNTIME_MAX = 3600
BUILD_TIMEOUT = 1800
CONTAINER_LIMITS = ["--memory", "2g", "--memory-swap", "2g", "--cpus", "1", "--pids-limit", "256"]


class UsageError(Exception):
    pass


class EnvironmentFailure(Exception):
    pass


def utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def stamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def file_identity(path: Path) -> dict:
    return {"path": str(path), "sha256": sha256(path), "bytes": path.stat().st_size}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True).stdout.strip()


def harness_identity() -> dict:
    out = {"files": {name: sha256(HERE / name) for name in HARNESS_FILES}}
    out["files"]["host.py"] = sha256(HERE / "host.py")
    try:
        out["commit"] = git(REPO, "rev-parse", "HEAD")
        rel = str(HERE.relative_to(REPO))
        out["dirty"] = bool(git(REPO, "status", "--porcelain", "--", rel, "scripts/qeynos2-journey"))
    except (subprocess.CalledProcessError, FileNotFoundError, ValueError):
        out["commit"] = None
        out["dirty"] = None
    return out


def outside_repo(path: Path) -> Path:
    path = path.expanduser().resolve()
    if path == REPO or REPO in path.parents:
        raise UsageError(f"{path} is inside the source tree; keep run artifacts under ~/.local/state")
    return path


def write_json(path: Path, data) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str) + "\n")
    os.replace(tmp, path)


@contextlib.contextmanager
def harness_lock(state_root: Path):
    """Serialize commands that share the harness Docker data root."""
    state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle = (state_root / "lock").open("a")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        raise EnvironmentFailure(f"another journey command holds {state_root / 'lock'}")
    try:
        yield
    finally:
        fcntl.flock(handle, fcntl.LOCK_UN)
        handle.close()


class Daemon:
    """One rootless dockerd in a transient user systemd unit.

    The unit has ``RuntimeMaxSec`` so a daemon outlives a killed host process
    by at most an hour. ``stop`` is idempotent, never raises and reports what
    it verified. ``started`` is set before ``systemd-run`` so an interruption
    while the unit is being created still leads to a stop attempt.
    """

    def __init__(self, state_root: Path, run_id: str):
        uid = os.getuid()
        self.unit = f"{UNIT_PREFIX}{run_id}.service"
        runtime = Path(f"/run/user/{uid}")
        self.data_root = state_root / "docker-data"
        self.exec_root = runtime / f"{UNIT_PREFIX}{run_id}-exec"
        self.rootlesskit_dir = runtime / f"{UNIT_PREFIX}{run_id}-rootlesskit"
        self.pidfile = runtime / f"{UNIT_PREFIX}{run_id}.pid"
        self.socket = runtime / f"{UNIT_PREFIX}{run_id}.sock"
        self.started = False
        self.record = {"unit": self.unit, "socket": str(self.socket), "data_root": str(self.data_root)}

    def docker(self, *args, timeout=120, check=True, **kw) -> subprocess.CompletedProcess:
        process = subprocess.run(["docker", "--host", f"unix://{self.socket}", *args], capture_output=True,
                                 text=True, timeout=timeout, **kw)
        if check and process.returncode != 0:
            raise EnvironmentFailure(f"docker {args[0]} failed: {process.stderr.strip()[-500:]}")
        return process

    def start(self) -> None:
        active = subprocess.run(["systemctl", "--user", "list-units", "--plain", "--no-legend",
                                 "--state=active,activating,deactivating,reloading",
                                 f"{UNIT_PREFIX}*"], capture_output=True, text=True).stdout.strip()
        if active:
            raise EnvironmentFailure(f"journey daemon unit already active: {active}")
        self.data_root.mkdir(mode=0o700, exist_ok=True)
        argv = [
            "systemd-run", "--user", "--quiet", f"--unit={self.unit}", "--collect",
            "--property=Delegate=yes", "--property=MemoryMax=4G", "--property=TasksMax=1024",
            f"--property=RuntimeMaxSec={DAEMON_RUNTIME_MAX}", "--property=TimeoutStopSec=60",
            f"--setenv=DOCKERD_ROOTLESS_ROOTLESSKIT_STATE_DIR={self.rootlesskit_dir}",
            "/usr/bin/dockerd-rootless.sh", f"--data-root={self.data_root}", f"--exec-root={self.exec_root}",
            f"--pidfile={self.pidfile}", f"--host=unix://{self.socket}", "--storage-driver=overlay2",
            "--feature=containerd-snapshotter=false", "--bridge=none", "--iptables=false", "--ip6tables=false",
            "--ip-forward=false", "--ip-masq=false", "--userland-proxy=false",
        ]
        self.record["argv"] = argv
        self.started = True
        process = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        if process.returncode != 0:
            raise EnvironmentFailure(f"systemd-run failed: {process.stderr.strip()}")
        deadline = time.monotonic() + DAEMON_START_TIMEOUT
        while True:
            if self.socket.exists():
                info = self.docker("info", "--format", "{{json .}}", check=False)
                if info.returncode == 0:
                    data = json.loads(info.stdout)
                    if "name=rootless" not in data.get("SecurityOptions", []):
                        raise EnvironmentFailure("daemon is not rootless")
                    self.record["engine"] = {k: data.get(k) for k in
                                             ("ServerVersion", "Driver", "DockerRootDir", "CgroupVersion")}
                    break
            if time.monotonic() > deadline:
                raise EnvironmentFailure(f"daemon socket not ready after {DAEMON_START_TIMEOUT}s")
            time.sleep(0.25)
        leftovers = self.docker("ps", "-aq", "--filter", f"label={LABEL}").stdout.split()
        if leftovers:
            self.docker("rm", "-f", *leftovers)
            self.record["removed_stale_containers"] = leftovers
        others = self.docker("ps", "-aq").stdout.split()
        if others:
            raise EnvironmentFailure(f"harness data root holds unexpected containers: {others}")

    def stop(self) -> dict:
        out = {"unit": self.unit, "started": self.started}
        if not self.started:
            out["complete"] = True
            return out
        try:
            stop = subprocess.run(["systemctl", "--user", "stop", self.unit], capture_output=True, text=True,
                                  timeout=120)
            out["stop_returncode"] = stop.returncode
            show = subprocess.run(["systemctl", "--user", "show", self.unit, "-p", "ActiveState", "--value"],
                                  capture_output=True, text=True, timeout=30)
            state = show.stdout.strip()
            out["active_state_after"] = state
            subprocess.run(["systemctl", "--user", "reset-failed", self.unit], capture_output=True, timeout=30)
            for path in (self.exec_root, self.rootlesskit_dir):
                if path.exists():
                    shutil.rmtree(path, ignore_errors=True)
            out["socket_absent"] = not self.socket.exists()
            out["exec_root_absent"] = not self.exec_root.exists()
            out["rootlesskit_dir_absent"] = not self.rootlesskit_dir.exists()
            out["complete"] = (show.returncode == 0 and state in ("inactive", "failed")
                               and out["socket_absent"] and out["rootlesskit_dir_absent"])
        except Exception as error:  # cleanup must not raise
            out["error"] = f"{type(error).__name__}: {error}"
            out["complete"] = False
        self.started = not out["complete"]
        return out


class Container:
    def __init__(self, daemon: Daemon, name: str):
        self.daemon = daemon
        self.name = name
        self.created = False
        self.argv = None

    def create(self, image: str, mounts: list[tuple[Path, str, bool]], argv: list[str], workdir="/") -> None:
        args = ["create", "--name", self.name, "--label", LABEL, "--pull", "never", "--network", "none",
                *CONTAINER_LIMITS, "--user", "0", "--cap-drop", "ALL", "--cap-add", "NET_RAW",
                "--security-opt", "no-new-privileges", "--read-only", "--tmpfs", "/tmp:rw,nosuid,size=256m",
                "--workdir", workdir]
        for src, dst, readonly in mounts:
            args += ["--mount", f"type=bind,src={src},dst={dst}" + (",readonly" if readonly else "")]
        args += ["--entrypoint", argv[0], image, *argv[1:]]
        self.argv = args
        # Mark before creating: an interruption after Docker accepts the
        # request must still lead to removal by this unique name.
        self.created = True
        self.daemon.docker(*args)

    def run(self, log: Path, timeout: int) -> dict:
        timed_out = False
        with log.open("wb") as handle:
            process = subprocess.Popen(["docker", "--host", f"unix://{self.daemon.socket}", "start", "-a", self.name],
                                       stdout=handle, stderr=subprocess.STDOUT)
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                self.daemon.docker("stop", "-t", "30", self.name, check=False, timeout=60)
                process.wait(timeout=60)
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
        state = json.loads(self.daemon.docker("inspect", "--format", "{{json .State}}", self.name).stdout)
        return {"exit": state.get("ExitCode"), "oom_killed": state.get("OOMKilled"), "timed_out": timed_out,
                "status": state.get("Status")}

    def remove(self) -> dict:
        """Remove by name and verify; never raises."""
        if not self.created:
            return {"complete": True, "created": False}
        out = {"created": True}
        try:
            self.daemon.docker("rm", "-f", self.name, check=False, timeout=90)
            listing = self.daemon.docker("ps", "-aq", "--filter", f"name=^{self.name}$", check=False, timeout=30)
            out["verify_returncode"] = listing.returncode
            remaining = listing.stdout.split()
            out["complete"] = listing.returncode == 0 and not remaining
        except Exception as error:
            out["error"] = f"{type(error).__name__}: {error}"
            out["complete"] = False
        self.created = not out["complete"]
        return out


def stage_inputs(args, run_dir: Path) -> dict:
    inputs = run_dir / "inputs"
    inputs.mkdir(mode=0o700)
    identity = {}
    for role, given in (("server", args.server), ("client", args.client)):
        source = Path(given).expanduser().resolve()
        if not source.is_file():
            raise UsageError(f"--{role} {given} is not a file")
        target = inputs / role
        shutil.copyfile(source, target)
        target.chmod(0o500)
        record = file_identity(source)
        copied = sha256(target)
        if copied != record["sha256"]:
            raise UsageError(f"--{role} changed while copying")
        revision = getattr(args, f"{role}_revision")
        record["revision"] = revision
        if role == "client":
            record["validation_pin"] = F.VALIDATION_CLIENTS.get(record["sha256"])
        identity[role] = record
    maps = Path(args.maps).expanduser().resolve()
    if not maps.is_dir():
        raise UsageError(f"--maps {args.maps} is not a directory")
    (inputs / "maps").mkdir(mode=0o700)
    files = {}
    for name, pinned in F.PINNED_MAPS.items():
        source = maps / name
        if not source.is_file():
            raise UsageError(f"--maps lacks {name}")
        shutil.copyfile(source, inputs / "maps" / name)
        digest = sha256(inputs / "maps" / name)
        files[name] = {"sha256": digest, "bytes": source.stat().st_size, "pinned": digest == pinned}
    identity["maps"] = {"dir": str(maps), "files": files}
    unpinned = [n for n, f in files.items() if not f["pinned"]]
    if unpinned and not args.allow_unpinned_maps:
        raise UsageError(f"maps differ from the pinned fixture: {unpinned} (pass --allow-unpinned-maps to run anyway)")
    harness = run_dir / "harness"
    harness.mkdir(mode=0o700)
    for name in HARNESS_FILES:
        shutil.copyfile(HERE / name, harness / name)
        (harness / name).chmod(0o400)
    return identity


def fixture_identity() -> dict:
    return {
        "mode": F.SERVER_MODE, "character": F.CHARACTER, "zone_id": F.ZONE_ID, "zone": F.ZONE_NAME,
        "seed_xyz": list(F.SEED_XYZ), "seed_heading": F.SEED_HEADING, "rat_spawn_id": F.RAT_SPAWN_ID,
        "rat_npc_type": F.RAT_NPC_TYPE, "move": F.MOVE, "pinned_maps": F.PINNED_MAPS,
    }


GUEST_JSON_LIMIT = 16 * 1024 * 1024


def read_guest_json(path: Path) -> dict | None:
    """Read a guest-written JSON file only if it is a bounded regular file."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_size > GUEST_JSON_LIMIT:
        raise EnvironmentFailure(f"{path.name} is not a regular file of at most {GUEST_JSON_LIMIT} bytes")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise EnvironmentFailure(f"{path.name} is not a JSON object")
    return data


def milestone_table(guest_rows: list[dict] | None, pre: dict, cleanup_ok: bool | None,
                    variant: str = "routine") -> list[dict]:
    table = []
    for name in F.HOST_PRE:
        table.append(pre.get(name, {"name": name, "status": "not_run"}))
    rows = {m["name"]: m for m in (guest_rows or []) if isinstance(m, dict) and "name" in m}
    for name in F.VARIANTS[variant]["milestones"]:
        table.append(rows.get(name, {"name": name, "status": "not_run"}))
    if cleanup_ok is None:
        table.append({"name": "cleanup", "status": "not_run"})
    else:
        table.append({"name": "cleanup", "status": "pass" if cleanup_ok else "fail"})
    return table


def container_consistent(run: dict, guest: dict) -> str | None:
    """Why the container's ending contradicts the guest report, or None."""
    if run.get("oom_killed") or run.get("timed_out"):
        return f"container OOM-killed or timed out: {run}"
    expected = 0 if guest.get("status") == "PASS" else 1
    if run.get("exit") != expected:
        return f"container exit {run.get('exit')} disagrees with guest status {guest.get('status')}"
    return None


class Interrupted(Exception):
    pass


SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
_received: list[int] = []


def install_signal_handlers():
    """Turn the first signal into ``Interrupted``; later ones are only recorded."""
    def handler(signum, frame):
        _received.append(signum)
        if len(_received) == 1:
            raise Interrupted(f"received signal {signum}")
    for sig in SIGNALS:
        signal.signal(sig, handler)


@contextlib.contextmanager
def signals_deferred():
    """Cleanup runs to completion: signals arriving now are recorded, not raised."""
    previous = {sig: signal.getsignal(sig) for sig in SIGNALS}
    for sig in SIGNALS:
        signal.signal(sig, lambda signum, frame: _received.append(signum))
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def command_run(args) -> int:
    state_root = Path(args.state_root).expanduser().resolve()
    run_id = stamp() + "-" + secrets.token_hex(3)
    output_root = outside_repo(Path(args.output_root) if args.output_root else state_root / "runs")
    output_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    started = time.monotonic()
    result = {
        "schema": RESULT_SCHEMA, "run_id": run_id, "label": args.label, "status": "FAIL",
        "exit_code": None, "first_failed_milestone": None, "failure": None, "started_utc": utc(),
        "harness": harness_identity(), "fixture": fixture_identity(), "image": args.image,
        "variant": args.variant, "server_mode": F.VARIANTS[args.variant]["server_mode"],
        "census": args.census,
    }
    pre: dict = {}
    state = {"run_dir": None, "daemon": None, "container": None}
    guest = None
    guest_rows = None
    cleanup: dict = {}
    host_error = None  # (milestone, type, message, exit code)

    def clean():
        """Idempotent: keeps the first complete record of each step, retries incomplete ones."""
        with signals_deferred():
            for key, owner, act in (("container", state["container"], lambda c: c.remove()),
                                    ("daemon", state["daemon"], lambda d: d.stop())):
                if owner is not None and not cleanup.get(key, {}).get("complete"):
                    cleanup[key] = act(owner)

    install_signal_handlers()
    try:
        at = time.monotonic()
        try:
            server = Path(args.server).expanduser()
            short = sha256(server)[:8] if server.is_file() else "missing"
            run_dir = output_root / f"{run_id}-server-{short}"
            run_dir.mkdir(mode=0o700)
            state["run_dir"] = run_dir
            result["artifacts"] = {"dir": str(run_dir)}
            result["identity"] = stage_inputs(args, run_dir)
            if result["harness"].get("dirty"):
                result["harness"]["warning"] = "harness files differ from the recorded commit"
            pre["inputs"] = {"name": "inputs", "status": "pass", "seconds": round(time.monotonic() - at, 3)}
        except (UsageError, OSError) as error:
            pre["inputs"] = {"name": "inputs", "status": "fail"}
            host_error = ("inputs", type(error).__name__, str(error), EXIT_USAGE)
        if host_error is None:
            at = time.monotonic()
            out = run_dir / "output"
            try:
                with harness_lock(state_root):
                    try:
                        state["daemon"] = daemon = Daemon(state_root, run_id)
                        daemon.start()
                        if daemon.docker("image", "inspect", args.image, check=False).returncode != 0:
                            raise EnvironmentFailure(f"image {args.image} missing; run 'prepare-image' first")
                        out.mkdir(mode=0o700)
                        state["container"] = container = Container(daemon, f"eqemu-rust-journey-{run_id}")
                        container.create(args.image, [
                            (run_dir / "harness", "/journey", True),
                            (run_dir / "inputs", "/inputs", True),
                            (out, "/output", False),
                        ], ["python3", "-B", "-s", "-E", "/journey/census.py" if args.census else "/journey/guest.py", "--output", "/output",
                            "--server", "/inputs/server", "--client", "/inputs/client", "--maps", "/inputs/maps",
                            "--variant", args.variant])
                        result["environment"] = {"daemon": daemon.record, "container_argv": container.argv}
                        pre["environment"] = {"name": "environment", "status": "pass",
                                              "seconds": round(time.monotonic() - at, 3)}
                        run = container.run(run_dir / "guest.log", GUEST_TIMEOUT)
                        result["container"] = run
                        guest = read_guest_json(out / "guest-result.json")
                        if guest is None:
                            progress = read_guest_json(out / "progress.json")
                            raise EnvironmentFailure(
                                f"guest wrote no result (container {run}); see guest.log"
                                + ("" if progress else "; no progress either"))
                        guest_rows = guest.get("milestones")
                        problem = container_consistent(run, guest)
                        if problem:
                            raise EnvironmentFailure(problem)
                    finally:
                        clean()
            except Exception as error:  # every host-side failure is an environment failure
                host_error = (None, type(error).__name__, str(error), EXIT_ENVIRONMENT)
    except Interrupted as error:
        host_error = (None, "Interrupted", str(error), EXIT_ENVIRONMENT)
    finally:
        try:
            clean()
        except Exception as error:  # never lose the result
            cleanup["error"] = f"{type(error).__name__}: {error}"
        run_dir = state["run_dir"]
        if host_error and host_error[0] is None:
            # Name the milestone that was running when the host-side failure hit.
            if "inputs" not in pre:
                pre["inputs"] = {"name": "inputs", "status": "fail"}
            elif "environment" not in pre:
                pre["environment"] = {"name": "environment", "status": "fail"}
            elif guest is None:
                progress = None
                with contextlib.suppress(Exception):
                    progress = read_guest_json(run_dir / "output" / "progress.json")
                guest_rows = [dict(m) for m in (progress or {}).get("milestones", [])]
                running = [m for m in guest_rows if m.get("status") == "running"]
                if running:
                    running[0]["status"] = "fail"
                    running[0]["note"] = "guest ended during this milestone"
                else:
                    pre["environment"] = dict(pre["environment"], status="fail")
            else:
                # A guest report exists but the container ending contradicts it.
                pre["environment"] = dict(pre["environment"], status="fail")
        if guest:
            result["guest"] = {k: guest.get(k) for k in ("started_utc", "finished_utc", "processes",
                                                         "guest_processes_reaped", "log_redactions",
                                                         "trace_contract_violations", "command_receipts")}
        cleanup_ok = None
        if pre.get("inputs", {}).get("status") == "pass":
            cleanup_ok = "error" not in cleanup and all(
                part.get("complete") for part in cleanup.values() if isinstance(part, dict))
            if guest is not None:
                cleanup_ok = cleanup_ok and bool(guest.get("guest_processes_reaped"))
        result["cleanup"] = cleanup
        table = milestone_table(guest_rows, pre, cleanup_ok, args.variant)
        result["milestones"] = table
        failed = [m for m in table if m["status"] != "pass"]
        first = next((m for m in failed if m["status"] == "fail"), failed[0] if failed else None)
        if first is None:
            exit_code = EXIT_PASS
            result["status"] = "PASS"
        else:
            result["first_failed_milestone"] = first["name"]
            guest_failure = (guest or {}).get("failure") or {}
            if guest_failure.get("milestone") == first["name"]:
                result["failure"] = {k: guest_failure.get(k) for k in ("milestone", "type", "message")}
                result["guest_traceback"] = guest_failure.get("traceback")
            elif host_error:
                result["failure"] = {"milestone": first["name"], "type": host_error[1], "message": host_error[2]}
            elif first["name"] == "cleanup":
                result["failure"] = {"milestone": "cleanup", "type": "CleanupIncomplete",
                                     "message": json.dumps(cleanup, default=str)}
            else:
                result["failure"] = {"milestone": first["name"], "type": "NotRun", "message": first.get("note")}
            if cleanup_ok is False:
                exit_code = EXIT_CLEANUP
            elif host_error:
                exit_code = host_error[3]
            else:
                exit_code = EXIT_FAIL
        result["exit_code"] = exit_code
        result["finished_utc"] = utc()
        result["seconds"] = round(time.monotonic() - started, 3)
        if run_dir and run_dir.exists():
            logs = run_dir / "output" / "logs"
            artifacts = result.setdefault("artifacts", {})
            artifacts["logs"] = sorted(str(p) for p in logs.glob("*.log")) if logs.is_dir() else []
            artifacts["guest_log"] = str(run_dir / "guest.log")
            artifacts["evidence"] = str(run_dir / "output" / "evidence")
            artifacts["state"] = str(run_dir / "output" / "state")
            artifacts["result"] = str(run_dir / "result.json")
            write_json(run_dir / "result.json", result)
        summary = {k: result.get(k) for k in ("status", "exit_code", "first_failed_milestone")}
        summary["message"] = (result.get("failure") or {}).get("message")
        summary["result"] = str(run_dir / "result.json") if run_dir else None
        print(json.dumps(summary))
    return exit_code


def command_prepare_image(args) -> int:
    state_root = Path(args.state_root).expanduser().resolve()
    archive = Path(args.archive).expanduser().resolve()
    if not archive.is_file():
        print(f"--archive {archive} is not a file", file=sys.stderr)
        return EXIT_USAGE
    record = {"archive": str(archive), "image": args.image, "started_utc": utc(), "image_present": False}
    install_signal_handlers()
    with harness_lock(state_root):
        daemon = Daemon(state_root, "prepare-" + stamp())
        try:
            daemon.start()
            if daemon.docker("image", "inspect", args.image, check=False).returncode == 0:
                record["loaded"] = False
            else:
                load = daemon.docker("load", "-i", str(archive), timeout=1800)
                record["loaded"] = load.stdout.strip()
            ok = daemon.docker("image", "inspect", args.image, check=False).returncode == 0
            record["image_present"] = ok
        except Exception as error:
            record["error"] = f"{type(error).__name__}: {error}"
        finally:
            with signals_deferred():
                record["daemon_cleanup"] = daemon.stop()
    print(json.dumps(record, indent=2))
    return EXIT_PASS if record["image_present"] and record["daemon_cleanup"]["complete"] else EXIT_ENVIRONMENT


def command_build_server(args) -> int:
    """Build and test one exact server commit offline, then copy out the binary."""
    state_root = Path(args.state_root).expanduser().resolve()
    repo = Path(args.repo).expanduser().resolve()
    try:
        commit = git(repo, "rev-parse", "--verify", args.commit + "^{commit}")
        tree = git(repo, "rev-parse", commit + "^{tree}")
    except subprocess.CalledProcessError as error:
        print(f"cannot resolve {args.commit}: {error.stderr.strip()}", file=sys.stderr)
        return EXIT_USAGE
    output_root = outside_repo(Path(args.output_root) if args.output_root else state_root / "builds")
    output_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    build_dir = output_root / f"{stamp()}-{commit[:8]}"
    build_dir.mkdir(mode=0o700)
    source = build_dir / "source"
    source.mkdir(mode=0o700)
    archive = build_dir / "source.tar"
    subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", "-o", str(archive), commit], check=True)
    subprocess.run(["tar", "-xf", str(archive), "-C", str(source)], check=True)
    out = build_dir / "output"
    out.mkdir(mode=0o700)
    record = {"schema": "qeynos2-journey-build/v1", "repo": str(repo), "commit": commit, "tree": tree,
              "archive_sha256": sha256(archive), "image": args.image, "started_utc": utc()}
    script = ("set -eu; export CARGO_TARGET_DIR=/output/target; rustc -Vv > /output/toolchain.log; "
              "cargo build --release --locked --offline > /output/build.log 2>&1; "
              "cargo test --release --locked --offline > /output/tests.log 2>&1")
    code = EXIT_ENVIRONMENT
    install_signal_handlers()
    with harness_lock(state_root):
        daemon = Daemon(state_root, "build-" + stamp())
        container = None
        try:
            daemon.start()
            container = Container(daemon, f"eqemu-rust-journey-build-{commit[:8]}-{secrets.token_hex(3)}")
            container.create(args.image, [(source, "/source", True), (out, "/output", False)],
                             ["sh", "-c", script], workdir="/source")
            record["container"] = container.run(build_dir / "container.log", BUILD_TIMEOUT)
            binary = out / "target/release/bump-eqemu-rust"
            if record["container"]["exit"] == 0 and binary.is_file():
                final = build_dir / "bump-eqemu-rust"
                shutil.copyfile(binary, final)
                final.chmod(0o500)
                record["binary"] = file_identity(final)
                tests = (out / "tests.log").read_text(errors="replace")
                record["test_results"] = [l for l in tests.splitlines() if l.startswith("test result:")]
                code = EXIT_PASS
            else:
                code = EXIT_FAIL
        except Exception as error:
            record["environment_error"] = f"{type(error).__name__}: {error}"
            code = EXIT_ENVIRONMENT
        finally:
            with signals_deferred():
                record["cleanup"] = {"container": container.remove() if container else {"complete": True},
                                     "daemon": daemon.stop()}
            if not all(p.get("complete") for p in record["cleanup"].values()):
                code = EXIT_CLEANUP
            record["finished_utc"] = utc()
            record["exit_code"] = code
            write_json(build_dir / "build.json", record)
    print(json.dumps({"exit_code": code, "binary": record.get("binary"), "commit": commit,
                      "build": str(build_dir / "build.json")}, indent=2))
    return code


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(prog="qeynos2-journey", description=__doc__)
    top.add_argument("--state-root", default=str(DEFAULT_STATE_ROOT),
                     help="harness state: Docker data root, lock, default runs/ and builds/")
    sub = top.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run the full journey once")
    run.add_argument("--server", required=True, help="Rust server executable")
    run.add_argument("--client", required=True, help="eqoxide-headless executable")
    run.add_argument("--maps", required=True, help="directory with qeynos2.map and qeynos2.wtr")
    run.add_argument("--server-revision", help="source revision the server was built from (recorded only)")
    run.add_argument("--client-revision", help="source revision the client was built from (recorded only)")
    run.add_argument("--label", help="free-form label recorded in the result")
    run.add_argument("--output-root", help="parent directory for the run directory")
    run.add_argument("--image", default=DEFAULT_IMAGE)
    run.add_argument("--allow-unpinned-maps", action="store_true")
    run.add_argument("--census", action="store_true",
                     help="also record a passive datagram census (output/evidence/transport-census.json)")
    run.add_argument("--variant", choices=sorted(F.VARIANTS), default="routine",
                     help="routine (default, ~40 s) or kill-respawn (fast-respawn mode, ~60 s)")
    run.set_defaults(func=command_run)
    prep = sub.add_parser("prepare-image", help="load the runtime image into the harness data root")
    prep.add_argument("--archive", required=True)
    prep.add_argument("--image", default=DEFAULT_IMAGE)
    prep.set_defaults(func=command_prepare_image)
    build = sub.add_parser("build-server", help="build and test one server commit in the same image")
    build.add_argument("--repo", required=True)
    build.add_argument("--commit", required=True)
    build.add_argument("--output-root")
    build.add_argument("--image", default=DEFAULT_IMAGE)
    build.set_defaults(func=command_build_server)
    return top


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        return args.func(args)
    except UsageError as error:
        print(str(error), file=sys.stderr)
        return EXIT_USAGE
    except EnvironmentFailure as error:
        print(str(error), file=sys.stderr)
        return EXIT_ENVIRONMENT
