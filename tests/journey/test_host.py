"""Host-side input identity, result table and path checks. No daemon or candidate execution."""

import argparse
import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "qeynos2-journey"))

import fixture as F  # noqa: E402
import host  # noqa: E402


class Inputs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "server").write_bytes(b"server-bytes")
        (self.root / "client").write_bytes(b"client-bytes")
        self.maps = self.root / "maps"
        self.maps.mkdir()
        (self.maps / "qeynos2.map").write_bytes(b"map")
        (self.maps / "qeynos2.wtr").write_bytes(b"wtr")
        self.run_dir = self.root / "run"
        self.run_dir.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def args(self, **kw):
        base = dict(server=str(self.root / "server"), client=str(self.root / "client"), maps=str(self.maps),
                    server_revision="abc", client_revision=None, allow_unpinned_maps=False)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_unpinned_maps_refused(self):
        with self.assertRaises(host.UsageError):
            host.stage_inputs(self.args(), self.run_dir)

    def test_identity_recorded_from_inputs(self):
        identity = host.stage_inputs(self.args(allow_unpinned_maps=True), self.run_dir)
        self.assertEqual(identity["server"]["sha256"], hashlib.sha256(b"server-bytes").hexdigest())
        self.assertEqual(identity["server"]["revision"], "abc")
        self.assertFalse(identity["maps"]["files"]["qeynos2.map"]["pinned"])
        self.assertEqual((self.run_dir / "inputs/client").read_bytes(), b"client-bytes")
        for name in host.HARNESS_FILES:
            self.assertTrue((self.run_dir / "harness" / name).is_file())

    def test_missing_inputs(self):
        with self.assertRaises(host.UsageError):
            host.stage_inputs(self.args(server=str(self.root / "nope")), self.run_dir)
        (self.maps / "qeynos2.wtr").unlink()
        with self.assertRaises(host.UsageError):
            second = self.root / "run2"
            second.mkdir()
            host.stage_inputs(self.args(allow_unpinned_maps=True), second)


class Paths(unittest.TestCase):
    def test_source_tree_refused(self):
        with self.assertRaises(host.UsageError):
            host.outside_repo(host.REPO / "runs")
        self.assertEqual(host.outside_repo(Path("/tmp")), Path("/tmp").resolve())

    def test_lock_is_exclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            with host.harness_lock(Path(tmp)):
                with self.assertRaises(host.EnvironmentFailure):
                    with host.harness_lock(Path(tmp)):
                        pass
            with host.harness_lock(Path(tmp)):
                pass


class Table(unittest.TestCase):
    def test_order_and_not_run(self):
        pre = {"inputs": {"name": "inputs", "status": "pass"}}
        guest = [{"name": "observer_self_check", "status": "pass"},
                 {"name": "server_start", "status": "fail"}]
        table = host.milestone_table(guest, pre, True)
        self.assertEqual([m["name"] for m in table], list(F.MILESTONES))
        self.assertEqual(table[1]["status"], "not_run")
        self.assertEqual(table[3]["status"], "fail")
        self.assertEqual(table[-1]["status"], "pass")
        self.assertEqual(host.milestone_table(None, pre, None)[-1]["status"], "not_run")


def quiet(fn, *args):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*args)


def guest_result(status="PASS", fail_at=None, reaped=True):
    rows, failure = [], None
    for name in F.GUEST:
        if fail_at == name:
            rows.append({"name": name, "status": "fail"})
            failure = {"milestone": name, "type": "CheckFailed", "message": "boom", "traceback": "tb"}
        elif failure:
            rows.append({"name": name, "status": "not_run"})
        else:
            rows.append({"name": name, "status": "pass"})
    return {"status": status, "milestones": rows, "failure": failure,
            "first_failed_milestone": fail_at, "guest_processes_reaped": reaped}


class FakeDaemon:
    stop_complete = True

    def __init__(self, state_root, run_id):
        self.started = False
        self.record = {}

    def start(self):
        self.started = True

    def docker(self, *args, **kw):
        return argparse.Namespace(returncode=0, stdout="", stderr="")

    def stop(self):
        self.started = False
        return {"complete": type(self).stop_complete}


class FakeContainer:
    scenario = {}

    def __init__(self, daemon, name):
        self.created = False
        self.argv = ["fake"]

    def create(self, image, mounts, argv, workdir="/"):
        self.created = True
        self.out = mounts[2][0]

    def run(self, log, timeout):
        log.write_bytes(b"")
        sc = type(self).scenario
        if "guest" in sc:
            (self.out / "guest-result.json").write_text(json.dumps(sc["guest"]))
        if "progress" in sc:
            (self.out / "progress.json").write_text(json.dumps(sc["progress"]))
        return sc.get("run", {"exit": 0, "oom_killed": False, "timed_out": False})

    def remove(self):
        self.created = False
        return {"complete": True}


class RunVerdict(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        for name in ("server", "client"):
            (root / name).write_bytes(name.encode())
        (root / "maps").mkdir()
        for name in F.PINNED_MAPS:
            (root / "maps" / name).write_bytes(b"x")
        self.argv = ["--state-root", str(root / "state"), "run", "--server", str(root / "server"),
                     "--client", str(root / "client"), "--maps", str(root / "maps"), "--allow-unpinned-maps",
                     "--output-root", str(root / "runs")]
        self.root = root
        self.saved = host.Daemon, host.Container
        host.Daemon, host.Container = FakeDaemon, FakeContainer
        FakeDaemon.stop_complete = True

    def tearDown(self):
        host.Daemon, host.Container = self.saved
        self.tmp.cleanup()

    def run_with(self, **scenario):
        FakeContainer.scenario = scenario
        code = quiet(host.main, self.argv)
        result = json.loads(next((self.root / "runs").glob("*/result.json")).read_text())
        return code, result

    def test_pass(self):
        code, result = self.run_with(guest=guest_result())
        self.assertEqual((code, result["status"], result["first_failed_milestone"]), (0, "PASS", None))

    def test_journey_failure(self):
        code, result = self.run_with(guest=guest_result("FAIL", "camp"),
                                     run={"exit": 1, "oom_killed": False, "timed_out": False})
        self.assertEqual((code, result["first_failed_milestone"]), (host.EXIT_FAIL, "camp"))
        self.assertEqual(result["failure"]["message"], "boom")

    def test_oom_or_timeout_never_passes(self):
        for run in ({"exit": 137, "oom_killed": True, "timed_out": False},
                    {"exit": 0, "oom_killed": False, "timed_out": True},
                    {"exit": 2, "oom_killed": False, "timed_out": False}):
            code, result = self.run_with(guest=guest_result(), run=run)
            self.assertEqual(code, host.EXIT_ENVIRONMENT, run)
            self.assertEqual(result["status"], "FAIL")
            self.assertEqual(result["first_failed_milestone"], "environment")
            for p in (self.root / "runs").glob("*/result.json"):
                p.unlink()

    def test_crash_names_running_milestone(self):
        progress = {"milestones": [{"name": "observer_self_check", "status": "pass"},
                                   {"name": "server_start", "status": "pass"},
                                   {"name": "entry", "status": "running"}]}
        code, result = self.run_with(progress=progress, run={"exit": 137, "oom_killed": True, "timed_out": False})
        self.assertEqual((code, result["first_failed_milestone"]), (host.EXIT_ENVIRONMENT, "entry"))
        statuses = {m["name"]: m["status"] for m in result["milestones"]}
        self.assertEqual(statuses["environment"], "pass")
        self.assertEqual(statuses["entry"], "fail")

    def test_cleanup_incomplete_exit_4_with_result(self):
        FakeDaemon.stop_complete = False
        code, result = self.run_with(guest=guest_result())
        self.assertEqual((code, result["first_failed_milestone"]), (host.EXIT_CLEANUP, "cleanup"))

    def test_unreaped_guest_processes_fail_cleanup(self):
        code, result = self.run_with(guest=guest_result(reaped=False))
        self.assertEqual(code, host.EXIT_CLEANUP)

    def test_symlinked_result_refused(self):
        target = self.root / "elsewhere.json"
        target.write_text(json.dumps(guest_result()))
        link = self.root / "link.json"
        os.symlink(target, link)
        with self.assertRaises(host.EnvironmentFailure):
            host.read_guest_json(link)


class Cli(unittest.TestCase):
    def test_usage_exit_writes_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = quiet(host.main, ["--state-root", tmp, "run", "--server", "/nonexistent", "--client",
                                     "/nonexistent", "--maps", tmp, "--output-root", tmp + "/runs"])
            self.assertEqual(code, host.EXIT_USAGE)
            results = list(Path(tmp, "runs").glob("*/result.json"))
            self.assertEqual(len(results), 1)
            result = json.loads(results[0].read_text())
            self.assertEqual(result["first_failed_milestone"], "inputs")
            self.assertEqual(result["exit_code"], host.EXIT_USAGE)
            self.assertEqual(result["milestones"][-1]["status"], "not_run")


if __name__ == "__main__":
    unittest.main()
