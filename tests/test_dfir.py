"""Linux launcher and acquisition tests using only synthetic evidence trees."""

import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock
import zipfile

import dfir
from tools import dfir_runtime as runtime


REPOSITORY = Path(__file__).resolve().parents[1]


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dfir-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "source"
        self.root.mkdir()
        self.storage = self.base / "evidence"
        self.storage.mkdir()
        self.stage = self.storage / "staging"
        self.stage.mkdir()
        self.output = self.stage / "collected"
        self.output.mkdir()
        self.outcomes = self.stage / "outcomes"
        self.outcomes.mkdir()
        self.request = {
            "schema_version": 1, "source_root": str(self.root), "output_parent": str(self.storage),
            "paths": [], "exclude": [], "auto_exclude": [], "profile": "fixture",
            "outcomes": str(self.outcomes), "staging": str(self.stage), "engine_root": "/engine",
            "max_file_bytes": 0, "complete_logs": False, "command_timeout": 5.0,
            "max_command_bytes": 65536, "min_free_bytes": 0, "repository": str(REPOSITORY),
            "discover_config": False, "started_utc": runtime.utc_now(), "format": "directory",
        }
        self.request_path = self.stage / "request.json"
        self.old_umask = os.umask(0o077)
        self.addCleanup(os.umask, self.old_umask)

    def put(self, path, content=b"synthetic evidence\n"):
        destination = self.root / path.lstrip("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        return destination

    def save_request(self, **changes):
        self.request.update(changes)
        runtime.save_json(self.request_path, self.request)

    def finalize(self, discovered=(), **changes):
        self.save_request(**changes)
        data = b"".join(b"fixture\0" + os.fsencode("/engine" + path) + b"\0" for path in discovered)
        (self.stage / "file_collector.nul").write_bytes(data)
        status = runtime.finish(str(self.request_path), str(self.stage), str(self.output), "/engine")
        return status, json.loads((self.output / "manifest.json").read_text())

    def test_native_directory_records_do_not_bypass_artifact_exclusions(self):
        self.put("/etc/passwd", b"fixture passwd")
        self.put("/etc/shadow", b"must remain excluded")
        status, entries = self.finalize(["/etc", "/etc/passwd"])
        self.assertEqual(status, 0)
        self.assertFalse((self.output / "[root]/etc/shadow").exists())
        self.assertEqual((self.output / "[root]/etc/passwd").read_bytes(), b"fixture passwd")
        self.assertEqual(len(entries), 2)

    def test_later_custom_directory_can_expand_a_shallow_native_record(self):
        self.put("/data/one")
        self.put("/data/two")
        status, _ = self.finalize(["/data"], paths=["/data"])
        self.assertEqual(status, 0)
        self.assertTrue((self.output / "[root]/data/one").exists())
        self.assertTrue((self.output / "[root]/data/two").exists())

    def test_repeated_directory_inode_does_not_recurse_indefinitely(self):
        self.put("/data/one")
        self.put("/data/repeated/not-a-new-directory")
        real_lstat = runtime.RootFS.lstat

        def repeated(source, logical):
            return real_lstat(source, "/data" if logical == "/data/repeated" else logical)

        with mock.patch.object(runtime.RootFS, "lstat", repeated):
            status, entries = self.finalize(paths=["/data"])
        self.assertEqual(status, 0)
        self.assertTrue(any(entry.get("duplicate_directory_of") == "/data" for entry in entries))
        self.assertTrue((self.output / "[root]/data/one").exists())

    def test_nul_discovery_preserves_unusual_names_and_integrity(self):
        names = ["line\nbreak", "back\\slash", "quote'$(literal)", "-option", "SHA256SUMS"]
        for name in names:
            self.put("/data/" + name, name.encode())
        status, entries = self.finalize(["/data/" + name for name in names])
        self.assertEqual(status, 0)
        for entry in entries:
            self.assertEqual(entry["sha256"], runtime.sha256_file(self.output / entry["saved_as"]))
        checked = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=self.output, capture_output=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        (self.output / "[root]/data/-option").write_bytes(b"tampered")
        checked = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=self.output, capture_output=True)
        self.assertNotEqual(checked.returncode, 0)

    def test_custom_globs_exclusions_symlinks_and_fifo(self):
        self.put("/data/good.log")
        self.put("/data/ignore.log")
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "secret").write_bytes(b"not evidence")
        (self.root / "data/link").symlink_to(outside, target_is_directory=True)
        (self.root / "escape").symlink_to(outside, target_is_directory=True)
        os.mkfifo(self.root / "data/fifo")
        status, entries = self.finalize(paths=["/data", "/escape/*"], exclude=["/data/ignore.log"])
        self.assertEqual(status, 0)
        self.assertFalse((self.output / "[root]/data/ignore.log").exists())
        self.assertFalse(any(path.name == "secret" for path in self.output.rglob("*")))
        self.assertTrue(any(entry["status"] == "symlink" for entry in entries))
        self.assertTrue(any(entry["status"] == "special" for entry in entries))
        self.assertTrue(any(entry["status"] == "symlink_parent" for entry in entries))

    def test_file_cap_and_complete_logs_option(self):
        self.put("/var/log/large.log", b"L" * 4096)
        self.put("/opt/large.dat", b"D" * 4096)
        status, entries = self.finalize(["/var/log/large.log", "/opt/large.dat"], max_file_bytes=1024,
                                        complete_logs=True)
        self.assertEqual(status, 3)
        self.assertTrue((self.output / "[root]/var/log/large.log").exists())
        self.assertFalse((self.output / "[root]/opt/large.dat").exists())
        self.assertTrue(any(entry["status"] == "limited" for entry in entries))

    def test_sparse_file_bytes_hash_and_allocation(self):
        path = self.put("/var/log/lastlog", b"")
        with path.open("wb") as stream:
            stream.seek(2 * runtime.CHUNK)
            stream.write(b"tail")
        status, _ = self.finalize(["/var/log/lastlog"])
        saved = self.output / "[root]/var/log/lastlog"
        self.assertEqual(status, 0)
        self.assertEqual(runtime.sha256_file(saved), runtime.sha256_file(path))
        self.assertLess(saved.stat().st_blocks * 512, saved.stat().st_size)

    def test_source_permissions_and_xattrs_are_recorded_with_private_output(self):
        path = self.put("/data/file")
        path.chmod(0o640)
        try:
            os.setxattr(path, "user.dfir_fixture", b"attribute\x00value")
        except OSError:
            self.skipTest("user xattrs unavailable on this filesystem")
        status, entries = self.finalize(["/data/file"])
        self.assertEqual(status, 0)
        entry = entries[0]
        self.assertEqual(entry["metadata"]["mode"], "0o640")
        self.assertEqual(entry["xattrs_base64"]["user.dfir_fixture"], "YXR0cmlidXRlAHZhbHVl")
        self.assertEqual((self.output / entry["saved_as"]).stat().st_mode & 0o777, 0o600)

    def test_unreadable_file_is_a_reported_gap_and_others_continue(self):
        self.put("/data/good")
        self.put("/data/denied")
        original = runtime.RootFS.open_file

        def deny(source, logical):
            if logical == "/data/denied":
                raise PermissionError("fixture access denied")
            return original(source, logical)

        with mock.patch.object(runtime.RootFS, "open_file", deny):
            status, entries = self.finalize(["/data/denied", "/data/good"])
        self.assertEqual(status, 3)
        self.assertTrue((self.output / "[root]/data/good").exists())
        self.assertTrue(any(entry["status"] == "error" for entry in entries))

    def test_replaced_source_and_storage_failure_are_reported(self):
        path = self.put("/data/file", b"original")
        real_fstat = os.fstat
        calls = 0

        def replace_on_second_fstat(descriptor):
            nonlocal calls
            calls += 1
            result = real_fstat(descriptor)
            if calls == 2:
                path.unlink()
                path.write_bytes(b"replacement")
            return result

        with mock.patch.object(runtime.os, "fstat", side_effect=replace_on_second_fstat):
            status, entries = self.finalize(["/data/file"])
        self.assertEqual(status, 3)
        self.assertTrue(any(entry["status"] == "changed" for entry in entries))
        with mock.patch.object(runtime, "check_space", side_effect=runtime.StorageLimit("fixture reserve")):
            status, entries = self.finalize(["/data/file"])
        self.assertEqual(status, 3)
        self.assertTrue(any(entry["status"] == "storage_limit" for entry in entries))
        self.assertFalse(list(self.output.rglob("*.part-*")))

    def test_configured_history_and_ssh_paths_are_data_not_code(self):
        self.put("/etc/passwd", b"alice:x:1000:1000::/home/alice:/bin/zsh\n")
        marker = self.base / "must-not-exist"
        self.put("/home/alice/.zshenv", b'ZDOTDIR="/srv/zsh"\n')
        self.put("/srv/zsh/.zshrc", b'HISTFILE="$ZDOTDIR/history"\n')
        self.put("/srv/zsh/history", b"configured shell history")
        self.put("/home/alice/.bashrc", ('HISTFILE=$(touch ' + str(marker) + ')\n').encode())
        self.put("/etc/ssh/sshd_config", b"Include sshd_config.d/*.conf\n")
        self.put("/etc/ssh/sshd_config.d/keys.conf", b"AuthorizedKeysFile /srv/keys/%u\nAuthorizedKeysCommand /bin/false\n")
        self.put("/srv/keys/alice", b"ssh-ed25519 fixture")
        status, entries = self.finalize(discover_config=True)
        self.assertEqual(status, 0)
        self.assertEqual((self.output / "[root]/srv/zsh/history").read_bytes(), b"configured shell history")
        self.assertTrue((self.output / "[root]/srv/keys/alice").exists())
        self.assertFalse(marker.exists())
        self.assertTrue(any(entry["status"] == "unresolved_config" for entry in entries))
        self.assertTrue(any(entry["status"] == "external_key_source" for entry in entries))

    def test_single_quoted_history_path_remains_literal(self):
        self.put("/etc/passwd", b"alice:x:1000:1000::/home/alice:/bin/bash\n")
        self.put("/home/alice/.bashrc", b"HISTFILE='/srv/history[$USER]$(literal)'\n")
        self.put("/srv/history[$USER]$(literal)", b"literal filename history")
        status, _ = self.finalize(discover_config=True)
        self.assertEqual(status, 0)
        self.assertTrue((self.output / "[root]/srv/history[$USER]$(literal)").exists())

    def test_missing_explicit_custom_path_reports_a_gap(self):
        status, entries = self.finalize(paths=["/does-not-exist"])
        self.assertEqual(status, 3)
        self.assertEqual(entries[0]["status"], "error")

    def test_explicit_private_key_selection_overrides_only_the_default_policy(self):
        self.put("/etc/ssh/ssh_host_ed25519_key", b"fixture private key")
        status, entries = self.finalize(["/etc/ssh/ssh_host_ed25519_key"], paths=["/etc/ssh/ssh_host_ed25519_key"])
        self.assertEqual(status, 0)
        self.assertEqual((self.output / "[root]/etc/ssh/ssh_host_ed25519_key").read_bytes(), b"fixture private key")
        self.assertTrue(any(entry["status"] == "policy_overridden" for entry in entries))

    def test_home_discovery_refuses_a_symlinked_passwd(self):
        self.put("/etc/dummy")
        outside = self.base / "outside-passwd"
        outside.write_bytes(b"outside:x:1000:1000::/outside-secret:/bin/sh\n")
        (self.root / "etc/passwd").symlink_to(outside)
        self.save_request()
        result = subprocess.run([sys.executable, "tools/dfir_runtime.py", "homes", str(self.request_path), "false"],
                                cwd=REPOSITORY, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("outside-secret", result.stdout)
        records = [json.loads(path.read_text()) for path in self.outcomes.glob("*.json")]
        self.assertTrue(any(record["status"] == "error" for record in records))

    def test_discovery_filters_and_parent_symlink_refusal(self):
        self.put("/logs/good.log")
        self.put("/logs/ignore.log")
        self.put("/logs/not-selected.txt")
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "secret.log").write_bytes(b"not evidence")
        (self.root / "escape").symlink_to(outside, target_is_directory=True)
        self.save_request()
        result = subprocess.run(
            [sys.executable, "tools/dfir_runtime.py", "discover", "--", str(self.request_path),
             "/logs /escape/*", "false", "", "*.log", "", "ignore.log", "f", "0", "", "", "fixture"],
            cwd=REPOSITORY, capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        values = result.stdout.split(b"\0")
        self.assertIn(b"/engine/logs/good.log", values)
        self.assertFalse(any(b"secret.log" in value for value in values))
        self.assertFalse(any(b"ignore.log" in value for value in values))
        record = json.loads(next(self.outcomes.glob("*.json")).read_text())
        self.assertTrue(any(issue["status"] == "symlink_parent" for issue in record["issues"]))

    def run_command(self, command, **changes):
        self.save_request(**changes)
        result = subprocess.run(
            [sys.executable, "tools/dfir_runtime.py", "command", str(self.request_path), command,
             "false", "command", "fixture"], cwd=REPOSITORY, capture_output=True, timeout=10,
        )
        records = [json.loads(path.read_text()) for path in self.outcomes.glob("*.json")]
        return result, records[-1]

    def test_bounded_command_success_stderr_and_failure(self):
        command = shlex.quote(sys.executable) + " -c " + shlex.quote("import sys;print('out');print('err',file=sys.stderr);sys.exit(7)")
        result, record = self.run_command(command)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"out\n")
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["returncode"], 7)
        self.assertEqual((self.outcomes / (record["id"] + ".stderr")).read_bytes(), b"err\n")

    def test_command_output_cap(self):
        command = shlex.quote(sys.executable) + " -c " + shlex.quote("import os;os.write(1,b'X'*100000)")
        result, record = self.run_command(command, max_command_bytes=1024)
        self.assertEqual(record["status"], "truncated")
        self.assertLessEqual(len(result.stdout), 1024)
        self.assertLessEqual(record["stdout_bytes"] + record["stderr_bytes"], 1024)

    def test_command_timeout_stops_descendants(self):
        pid_file = self.base / "child.pid"
        code = ("import subprocess,time,pathlib;child=subprocess.Popen(['" + sys.executable + "','-c','import time;time.sleep(30)']);"
                "pathlib.Path(" + repr(str(pid_file)) + ").write_text(str(child.pid));print('partial',flush=True);time.sleep(30)")
        started = time.monotonic()
        result, record = self.run_command(shlex.quote(sys.executable) + " -c " + shlex.quote(code), command_timeout=0.3)
        self.assertEqual(record["status"], "timeout")
        self.assertIn(b"partial", result.stdout)
        self.assertLess(time.monotonic() - started, 3)
        child = Path("/proc") / pid_file.read_text() / "stat"
        if child.exists():
            self.assertEqual(child.read_text().split()[2], "Z")


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dfir-cli-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "source'$(literal)"
        self.root.mkdir()
        self.output = self.base / "output"

    def put(self, logical, data=b"synthetic evidence\n"):
        path = self.root / logical.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def run_cli(self, *extra):
        result = subprocess.run(
            [sys.executable, "dfir.py", "--root", str(self.root), "--output", str(self.output),
             "--min-free-mb", "0", *extra], cwd=REPOSITORY, capture_output=True, text=True, timeout=90,
        )
        folders = sorted(path for path in self.output.glob("dfir_*") if path.is_dir()) if self.output.exists() else []
        return result, folders[-1] if folders else None

    def test_all_output_formats_preserve_names_and_original_bytes(self):
        names = ["line\nbreak", "back\\slash", "-option", "white space"]
        for name in names:
            path = self.put("/data/" + name, name.encode())
            os.utime(path, (0, 0))
        for output_format in ("zip", "tar", "tar.gz", "directory"):
            with self.subTest(output_format=output_format):
                result, directory = self.run_cli("--no-defaults", "--path", "/data", "--format", output_format)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for name in names:
                    self.assertEqual((directory / "[root]/data" / name).read_bytes(), name.encode())
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
                self.assertTrue(all(path.stat().st_mode & 0o077 == 0 for path in directory.rglob("*") if path.is_file()))
                checked = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=directory, capture_output=True)
                self.assertEqual(checked.returncode, 0, checked.stderr)
                if output_format == "directory":
                    continue
                archive = directory.with_name(directory.name + "." + output_format)
                expected_hash = archive.with_name(archive.name + ".sha256").read_text().split()[0]
                self.assertEqual(expected_hash, runtime.sha256_file(archive))
                if output_format == "zip":
                    with zipfile.ZipFile(archive) as bundle:
                        for name in names:
                            self.assertEqual(bundle.read(directory.name + "/[root]/data/" + name), name.encode())
                else:
                    with tarfile.open(archive) as bundle:
                        for name in names:
                            self.assertEqual(bundle.extractfile(directory.name + "/[root]/data/" + name).read(), name.encode())

    def test_default_profile_logs_histories_keys_and_native_exclusions(self):
        self.put("/etc/passwd", b"root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/zsh\nsvc:x:900:900::/srv/service:/bin/sh\n")
        artifacts = ["/var/log/auth.log", "/var/log/auth.log.1.gz", "/var/log/wtmp",
                     "/var/log/journal/machine/system.journal", "/run/log/journal/machine/user.journal",
                     "/root/.bash_history", "/home/alice/.zsh_history", "/srv/service/.sh_history",
                     "/home/alice/.ssh/authorized_keys", "/home/alice/.ssh/known_hosts",
                     "/home/alice/.config/systemd/user/test.service", "/etc/cron.d/task",
                     "/var/lib/docker/containers/abc/abc-json.log.1"]
        for path in artifacts:
            self.put(path)
        self.put("/etc/shadow", b"excluded account hashes")
        self.put("/etc/ssh/ssh_host_ed25519_key", b"private host key")
        self.put("/home/alice/.ssh/id_ed25519", b"private user key")
        self.put("/home/alice/.zshenv", b'ZDOTDIR="/srv/zsh"\n')
        self.put("/srv/zsh/.zshrc", b'HISTFILE="$ZDOTDIR/custom_history"\n')
        self.put("/srv/zsh/custom_history", b"configured history")
        result, directory = self.run_cli("--format", "directory")
        self.assertEqual(result.returncode, 0, result.stdout[-6000:] + result.stderr[-4000:])
        for path in artifacts:
            self.assertTrue((directory / "[root]" / path.lstrip("/")).exists(), path)
        self.assertTrue((directory / "[root]/srv/zsh/custom_history").exists())
        for path in ("/etc/shadow", "/etc/ssh/ssh_host_ed25519_key", "/home/alice/.ssh/id_ed25519"):
            self.assertFalse((directory / "[root]" / path.lstrip("/")).exists(), path)
        commands = json.loads((directory / "commands.json").read_text())
        self.assertFalse(any(record["kind"] == "command" for record in commands))

    def test_dry_run_and_invalid_configuration_do_not_collect(self):
        result, directory = self.run_cli("--no-defaults", "--path", "/data", "--dry-run")
        self.assertEqual(result.returncode, 0)
        self.assertIsNone(directory)
        self.assertFalse(self.output.exists())
        for extra in (("--path", "../bad"), ("--path", "/data/../bad"), ("--command-timeout", "nan"),
                      ("--max-file-size-mb", "1e300"), ("--max-command-output-mb", "0")):
            result, directory = self.run_cli(*extra)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIsNone(directory)

    def test_archive_budget_failure_keeps_original_evidence(self):
        directory = self.base / "ready"
        directory.mkdir()
        (directory / "fixture").write_bytes(b"preserve")
        with mock.patch.object(dfir, "check_space", side_effect=runtime.StorageLimit("fixture reserve")):
            with self.assertRaises(runtime.StorageLimit):
                dfir.make_archive(directory, "zip")
        self.assertEqual((directory / "fixture").read_bytes(), b"preserve")
        self.assertFalse(list(self.base.glob("*.partial")))

    def test_path_file_custom_glob_and_exclusion(self):
        self.put("/srv/app/one.log")
        self.put("/srv/app/ignore.log")
        paths = self.base / "extra-paths.txt"
        paths.write_text("# fixture\n/srv/app/*.log\n")
        result, directory = self.run_cli("--no-defaults", "--paths-file", str(paths),
                                         "--exclude", "/srv/app/ignore.log", "--format", "directory",
                                         "--case-id", "IR-FIXTURE", "--operator", "Analyst")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((directory / "[root]/srv/app/one.log").exists())
        self.assertFalse((directory / "[root]/srv/app/ignore.log").exists())
        self.assertEqual(json.loads((directory / "collection.json").read_text())["case_id"], "IR-FIXTURE")

    def test_partial_report_hashes_saved_bytes_without_source_reads(self):
        partial = self.base / "partial"
        partial.mkdir()
        (partial / "partial-file").write_bytes(b"saved bytes")
        options = {"source_root": str(self.root), "case_id": "IR", "operator": "fixture"}
        with mock.patch.object(runtime.RootFS, "open_file", side_effect=AssertionError("no more source reads")):
            dfir.report_partial(partial, options, "interrupted")
        self.assertFalse(json.loads((partial / "partial_collection.json").read_text())["complete"])
        checked = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=partial, capture_output=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_launcher_cancellation_retains_partial_reports(self):
        # The only command is a synthetic query. No host file artifact is selected.
        ready = self.base / "query-ready"
        profile = self.base / "cancel-profile.yaml"
        artifact = self.base / "cancel-query.yaml"
        script = "import pathlib,time;pathlib.Path(" + repr(str(ready)) + ").write_text('ready');print('fixture',flush=True);time.sleep(30)"
        query = shlex.quote(sys.executable) + " -c " + shlex.quote(script)
        artifact.write_text("version: 1.0\noutput_directory: /fixture\nartifacts:\n  -\n    description: Synthetic query\n"
                            "    supported_os: [linux]\n    collector: command\n    command: " + query + "\n    output_file: fixture.txt\n")
        profile.write_text("name: cancel_fixture\ndescription: Synthetic query only\nartifacts:\n  - " + str(artifact) + "\n")
        log = self.base / "launcher.log"
        with log.open("w") as stream:
            process = subprocess.Popen([sys.executable, "dfir.py", "--root", "/", "--profile", str(profile),
                                        "--no-config-discovery", "--output", str(self.output), "--min-free-mb", "0"],
                                       cwd=REPOSITORY, stdout=stream, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 15
                while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(ready.exists(), log.read_text())
                process.send_signal(signal.SIGINT)
                self.assertEqual(process.wait(timeout=10), 130)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        stage = next(self.output.glob(".dfir-*"))
        self.assertTrue((stage / "partial_collection.json").exists(), log.read_text())
        self.assertTrue((stage / "SHA256SUMS").exists())
        checked = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=stage, capture_output=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)


if __name__ == "__main__":
    unittest.main()
