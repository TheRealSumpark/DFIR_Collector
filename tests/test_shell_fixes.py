"""Synthetic regression cases for portable UAC evidence-handling helpers."""

import concurrent.futures
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import zipfile


REPOSITORY = Path(__file__).resolve().parents[1]
SHELL = shlex.split(os.environ.get("UAC_TEST_SHELL", "/bin/sh"))


class ShellFixTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="uac-regression-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.stage = self.base / "stage"
        self.stage.mkdir()
        self.data = self.base / "uac-data.tmp"
        self.data.mkdir()
        self.environment = {
            **os.environ, "__UAC_DIR": str(REPOSITORY),
            "__UAC_TEMP_DATA_DIR": str(self.data),
            "__UAC_ARTIFACTS_OUTPUT_DIR": str(self.stage),
            "__UAC_MOUNT_POINT": "/", "__UAC_LOG_FILE": "uac.log",
            "__UAC_OPERATING_SYSTEM": "linux", "__UAC_VERBOSE_MODE": "false",
            "__UAC_DEBUG_MODE": "false", "__UAC_TOOL_TAR_NO_FROM_FILE_SUPPORT": "false",
            "__UAC_VERBOSE_CMD_PREFIX": " > ", "FIXTURE_BASE": str(self.base),
        }

    def shell(self, code, **environment):
        return subprocess.run(
            [*SHELL, "-c", '. "$__UAC_DIR/lib/load_libraries.sh"\n' + code],
            cwd=self.stage, env={**self.environment, **environment},
            capture_output=True, text=True, timeout=20,
        )

    def test_copy_preserves_literal_names_and_unterminated_final_line(self):
        source = self.base / "mounted [evidence]"
        source.mkdir()
        names = ["white space.log", "back\\slash.log", " trailing .log ", "quote'$(literal).log"]
        for name in names:
            (source / name).write_bytes(name.encode())
        files = self.base / "files.txt"
        files.write_text("\n" + "\n\n".join(str(source / name) for name in names))
        result = self.shell('_copy_data "$FIXTURE_LIST" "$FIXTURE_DEST"',
                            __UAC_MOUNT_POINT=str(source), FIXTURE_LIST=str(files),
                            FIXTURE_DEST=str(self.stage))
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in names:
            self.assertEqual((self.stage / name).read_bytes(), name.encode())

    def test_copy_failure_survives_later_success(self):
        valid = self.base / "valid"
        valid.write_bytes(b"fixture")
        files = self.base / "files.txt"
        files.write_text(str(self.base / "missing") + "\n" + str(valid) + "\n")
        result = self.shell('_copy_data "$FIXTURE_LIST" "$FIXTURE_DEST"',
                            FIXTURE_LIST=str(files), FIXTURE_DEST=str(self.stage))
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any(path.name == "valid" for path in self.stage.rglob("*")))

    def test_tar_fallback_includes_hidden_and_option_like_names(self):
        for name in (".hidden", "-option", "space name", "back\\slash"):
            (self.stage / name).write_bytes(b"fixture")
        files = self.base / "files.txt"
        files.write_text(".hidden\n-option\nspace name\nback\\slash\n")
        archive = self.base / "evidence.tar"
        result = self.shell('_tar_data "$FIXTURE_LIST" "$FIXTURE_ARCHIVE"',
                            FIXTURE_LIST=str(files), FIXTURE_ARCHIVE=str(archive),
                            __UAC_TOOL_TAR_NO_FROM_FILE_SUPPORT="true")
        self.assertEqual(result.returncode, 0, result.stderr)
        with tarfile.open(archive) as bundle:
            files_saved = {member.name.removeprefix("./") for member in bundle if member.isfile()}
        self.assertEqual(files_saved, {".hidden", "-option", "space name", "back\\slash"})

    def test_gnu_tar_file_list_is_literal(self):
        names = [".hidden", "-option", "back\\slash", "quote'$(literal)"]
        for name in names:
            (self.stage / name).write_bytes(b"fixture")
        files = self.base / "files.txt"
        files.write_text("\n".join(names) + "\n")
        archive = self.base / "evidence.tar"
        result = self.shell('_tar_data "$FIXTURE_LIST" "$FIXTURE_ARCHIVE"',
                            FIXTURE_LIST=str(files), FIXTURE_ARCHIVE=str(archive))
        self.assertEqual(result.returncode, 0, result.stderr)
        with tarfile.open(archive) as bundle:
            self.assertEqual(set(bundle.getnames()), set(names))

    def test_tar_gzip_success_and_failed_tar_status(self):
        (self.stage / "fixture").write_bytes(b"evidence")
        files = self.base / "files.txt"
        files.write_text("fixture\n")
        archive = self.base / "evidence.tar.gz"
        result = self.shell('_tar_gz_data "$FIXTURE_LIST" "$FIXTURE_ARCHIVE"',
                            FIXTURE_LIST=str(files), FIXTURE_ARCHIVE=str(archive))
        self.assertEqual(result.returncode, 0, result.stderr)
        with tarfile.open(archive) as bundle:
            self.assertEqual(bundle.extractfile("fixture").read(), b"evidence")
        result = self.shell('tar() { return 7; }\n_tar_gz_data "$FIXTURE_LIST" "$FIXTURE_ARCHIVE"',
                            FIXTURE_LIST=str(files), FIXTURE_ARCHIVE=str(self.base / "failed.tar.gz"))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(list(self.data.glob("*.fifo")))

    def test_tar_gzip_reports_compression_failure(self):
        (self.stage / "fixture").write_bytes(b"evidence")
        files = self.base / "files.txt"
        files.write_text("fixture\n")
        result = self.shell('gzip() { cat >/dev/null; return 8; }\n_tar_gz_data "$FIXTURE_LIST" "$FIXTURE_ARCHIVE"',
                            FIXTURE_LIST=str(files), FIXTURE_ARCHIVE=str(self.base / "failed.tar.gz"))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(list(self.data.glob("*.fifo")))

    def test_unique_private_temp_reservation_keeps_old_evidence(self):
        (self.data / "old-evidence").write_bytes(b"preserve")

        def reserve(_):
            return self.shell('umask 022\n_init_temp_data_dir || exit\nprintf "%s\\n" "$__UAC_TEMP_DATA_DIR"')

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(reserve, range(2)))
        paths = []
        for result in results:
            self.assertEqual(result.returncode, 0, result.stderr)
            path = Path(result.stdout.strip())
            paths.append(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
            self.assertEqual((path / "uac.log").stat().st_mode & 0o777, 0o600)
        self.assertNotEqual(paths[0], paths[1])
        self.assertEqual((self.data / "old-evidence").read_bytes(), b"preserve")

    def test_cleanup_refuses_unowned_or_symlink_directory(self):
        protected = self.base / "protected"
        protected.mkdir()
        (protected / "fixture").write_bytes(b"preserve")
        result = self.shell('_remove_temp_data_dir', __UAC_TEMP_DATA_DIR=str(protected))
        self.assertEqual(result.returncode, 0)
        self.assertTrue((protected / "fixture").exists())
        link = self.base / "link"
        link.symlink_to(protected, target_is_directory=True)
        result = self.shell('_remove_temp_data_dir', __UAC_TEMP_DATA_DIR=str(link),
                            __UAC_OWNED_TEMP_DATA_DIR=str(link))
        self.assertEqual(result.returncode, 0)
        self.assertTrue((protected / "fixture").exists())

    def test_interruption_retains_partial_evidence(self):
        (self.data / "partial").write_bytes(b"preserve")
        result = self.shell('_terminate')
        self.assertEqual(result.returncode, 130)
        self.assertTrue((self.data / "partial").exists())

    def test_literal_secret_redaction_handles_specials_and_newlines(self):
        secret = "dummy [a.*]\\token\nnext line"
        result = self.shell('_redact_secrets "$FIXTURE_MESSAGE"',
                            __UAC_OUTPUT_PASSWORD=secret, FIXTURE_MESSAGE="before " + secret + " after")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "before [REDACTED] after\n")

    def test_invocation_log_and_verbose_output_redact_all_secret_options(self):
        (self.data / "uac.log").touch()
        result = self.shell('''
_redact_command_line uac --output-password "$__UAC_OUTPUT_PASSWORD" --s3-token "$__UAC_S3_TOKEN"
_log_msg INF "password=$__UAC_OUTPUT_PASSWORD token=$__UAC_S3_TOKEN"
_verbose_msg "password=$__UAC_OUTPUT_PASSWORD token=$__UAC_S3_TOKEN"
''', __UAC_OUTPUT_PASSWORD="dummy-password", __UAC_S3_TOKEN="dummy-token", __UAC_VERBOSE_MODE="true")
        output = result.stdout + result.stderr + (self.data / "uac.log").read_text()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("dummy-password", output)
        self.assertNotIn("dummy-token", output)
        self.assertIn("[REDACTED]", output)

    def test_acquisition_log_does_not_contain_zip_password(self):
        log = self.base / "acquisition.log"
        result = self.shell('_create_acquisition_log "$FIXTURE_LOG" start end "" "" hash',
                            FIXTURE_LOG=str(log), __UAC_OUTPUT_FORMAT="zip", __UAC_OUTPUT_PASSWORD="dummy-password")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("dummy-password", log.read_text())
        self.assertNotIn("Password:", log.read_text())

    def test_secret_file_is_literal_and_descriptor_input_works(self):
        secrets = self.base / "secrets"
        marker = self.base / "must-not-exist"
        value = "$(touch " + str(marker) + ")='literal'\\tail"
        secrets.write_text("# fixture\noutput_password=" + value)
        result = self.shell('exec 3<"$FIXTURE_SECRETS"\n_load_secrets /dev/fd/3 || exit\nprintf "%s" "$__UAC_OUTPUT_PASSWORD"',
                            FIXTURE_SECRETS=str(secrets))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, value)
        self.assertFalse(marker.exists())

    def test_trace_with_secrets_rejected_before_disclosure(self):
        result = subprocess.run([*SHELL, "./uac", "--trace", "-P", "dummy-password"],
                                cwd=REPOSITORY, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("dummy-password", result.stdout + result.stderr)
        self.assertIn("tracing", result.stderr)

    @unittest.skipUnless(shutil.which("zip"), "zip executable unavailable")
    def test_zip_output_and_password_are_literal(self):
        source = self.stage / "fixture"
        source.write_bytes(b"evidence")
        files = self.base / "files.txt"
        files.write_text("fixture\n")
        marker = self.base / "must-not-exist"
        password = "dummy'$(touch " + str(marker) + ")"
        archive = self.base / "evidence.zip"
        result = self.shell('_zip_data "$FIXTURE_LIST" "$FIXTURE_ARCHIVE" "$__UAC_OUTPUT_PASSWORD"',
                            FIXTURE_LIST=str(files), FIXTURE_ARCHIVE=str(archive),
                            __UAC_OUTPUT_PASSWORD=password, __UAC_VERBOSE_MODE="true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())
        self.assertNotIn(password, result.stdout + result.stderr)
        with zipfile.ZipFile(archive) as bundle:
            self.assertEqual(bundle.read("fixture", pwd=password.encode()), b"evidence")

    def test_native_uac_archives_mounted_fixture_in_zip_and_tar(self):
        root = self.base / "source"
        (root / "var/log").mkdir(parents=True)
        (root / "var/log/auth.log").write_bytes(b"synthetic ssh event\n")
        destination = self.base / "destination"
        destination.mkdir()
        artifact = self.base / "fixture.yaml"
        artifact.write_text("version: 1.0\nartifacts:\n  -\n    description: Fixture logs\n"
                            "    supported_os: [linux]\n    collector: file\n    path: /var/log\n")
        for output_format in ("tar", "zip"):
            with self.subTest(output_format=output_format):
                result = subprocess.run(
                    [*SHELL, "./uac", "-a", str(artifact), "-m", str(root), "-s", "linux", "-u", "-H",
                     "--hostname", "fixture", "-f", output_format, "-o", "fixture-" + output_format,
                     str(destination)], cwd=REPOSITORY, capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                if output_format == "zip":
                    with zipfile.ZipFile(destination / "fixture-zip.zip") as bundle:
                        self.assertEqual(bundle.read("[root]/var/log/auth.log"), b"synthetic ssh event\n")
                        self.assertIn("hash_list.sha256", bundle.namelist())
                else:
                    with tarfile.open(destination / "fixture-tar.tar.gz") as bundle:
                        self.assertEqual(bundle.extractfile("[root]/var/log/auth.log").read(), b"synthetic ssh event\n")
                        self.assertIn("hash_list.sha256", bundle.getnames())
                self.assertFalse(list(destination.glob("uac-data.tmp.*")))


if __name__ == "__main__":
    unittest.main()
