#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Linux DFIR launcher for UAC. Python 3.9+, no third-party Python packages."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import uuid
import zipfile

from tools.dfir_runtime import CHUNK, check_space, checksum_line, normalized_path, save_json, sha256_file, utc_now, write_checksums

REPOSITORY = Path(__file__).resolve().parent


def finite_number(value):
    number = float(value)
    if not math.isfinite(number) or number < 0 or number > sys.maxsize / CHUNK:
        raise argparse.ArgumentTypeError("must be a finite nonnegative number within the supported range")
    return number


def positive(value):
    number = finite_number(value)
    if number == 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def make_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-o", "--output", default="collections", help="parent directory for a unique collection")
    parser.add_argument("--root", default="/", help="already mounted evidence root; disables live commands")
    parser.add_argument("--profile", default="linux_dfir", help="UAC profile name or trusted profile file")
    parser.add_argument("--no-defaults", action="store_true", help="collect custom paths only")
    parser.add_argument("-p", "--path", action="append", default=[], help="absolute file/directory or quoted glob; repeatable")
    parser.add_argument("--paths-file", action="append", default=[], help="UTF-8 path list; blank lines and # comments ignored")
    parser.add_argument("--exclude", action="append", default=[], help="source path/glob excluded from file copying; repeatable")
    parser.add_argument("--format", choices=("directory", "tar", "tar.gz", "zip"), default="tar.gz", help="archive format; evidence directory is also retained")
    parser.add_argument("--complete-logs", action="store_true", help="attempt all /var/log and /run/log regular files without a file-size cap")
    parser.add_argument("--max-file-size-mb", type=finite_number, default=1024.0, help="regular-file size cap in MiB; 0 is unlimited")
    parser.add_argument("--command-timeout", type=positive, default=60.0, help="seconds allowed per command")
    parser.add_argument("--max-command-output-mb", type=positive, default=128.0, help="combined stdout/stderr cap per command, MiB")
    parser.add_argument("--min-free-mb", type=finite_number, default=256.0, help="free-space reserve on evidence storage, MiB")
    parser.add_argument("--no-live", action="store_true", help="skip live command collectors")
    parser.add_argument("--discover-config", action="store_true", default=None, help="discover literal configured history/SSH locations; automatic for linux_dfir")
    parser.add_argument("--no-config-discovery", action="store_false", dest="discover_config", help="disable additional configuration-based source discovery")
    parser.add_argument("--case-id", default="", help="investigator case identifier")
    parser.add_argument("--operator", default=str(os.geteuid()), help="investigator/operator identifier")
    parser.add_argument("--dry-run", action="store_true", help="print selections and limits without creating files or running UAC")
    return parser


class BudgetWriter:
    def __init__(self, path, reserve):
        self.path, self.reserve = path, reserve
        self.stream = path.open("xb")

    def write(self, data):
        check_space(self.path.parent, self.reserve, len(data))
        return self.stream.write(data)

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stream.close()


def make_archive(directory, output_format, min_free_bytes=0):
    if output_format == "directory":
        return None
    archive = directory.with_name(directory.name + "." + output_format)
    temporary = archive.with_name(archive.name + ".partial")
    if archive.exists() or temporary.exists():
        raise FileExistsError("archive destination already exists")
    try:
        if output_format == "zip":
            with BudgetWriter(temporary, min_free_bytes) as writer, zipfile.ZipFile(writer, "w", compression=zipfile.ZIP_DEFLATED,
                                 compresslevel=6, allowZip64=True, strict_timestamps=False) as bundle:
                for path in sorted(directory.rglob("*")):
                    check_space(directory.parent, min_free_bytes)
                    if path.is_symlink():
                        raise OSError("refusing an unexpected output symlink")
                    bundle.write(path, arcname=directory.name + "/" + path.relative_to(directory).as_posix())
        else:
            with BudgetWriter(temporary, min_free_bytes) as writer, tarfile.open(fileobj=writer, mode="w:gz" if output_format == "tar.gz" else "w:") as bundle:
                for path in [directory, *sorted(directory.rglob("*"))]:
                    check_space(directory.parent, min_free_bytes)
                    if path.is_symlink():
                        raise OSError("refusing an unexpected output symlink")
                    arcname = directory.name if path == directory else directory.name + "/" + path.relative_to(directory).as_posix()
                    bundle.add(path, arcname=arcname, recursive=False)
        temporary.replace(archive)
        archive.with_name(archive.name + ".sha256").write_text(
            checksum_line(sha256_file(archive), archive.name), encoding="utf-8")
        return archive
    except BaseException:
        if temporary.exists():
            temporary.unlink()
        raise


def report_partial(directory, options, reason):
    """Document saved bytes only; never continue acquiring source files after cancellation."""
    if directory is None or not directory.is_dir():
        return
    save_json(directory / "partial_collection.json", {
        "schema_version": 1, "finished_utc": utc_now(), "complete": False,
        "source_root": options["source_root"], "case_id": options["case_id"],
        "operator": options["operator"], "reason": reason,
        "limitations": ["These checksums cover the bytes saved before failure or cancellation.",
                        "Some files may be partial; source metadata may not have been finalized.",
                        "No additional source acquisition was performed during this recovery report."],
    })
    write_checksums(directory)


def main(argv=None):
    parser = make_parser()
    args = parser.parse_args(argv)
    if sys.version_info < (3, 9):
        parser.error("Python 3.9 or newer is required")
    if not sys.platform.startswith("linux"):
        parser.error("the DFIR launcher requires Linux; use ./uac for other Unix systems")
    try:
        root = Path(args.root).resolve(strict=True)
        if not root.is_dir():
            raise ValueError("source root must be a directory")
        if any(root == Path(prefix) or Path(prefix) in root.parents for prefix in ("/proc", "/sys", "/dev")):
            raise ValueError("source root must be a filesystem evidence root, not a kernel pseudo-filesystem")
        output_parent = Path(args.output).expanduser().resolve()
        if root != Path("/") and (output_parent == root or root in output_parent.parents):
            raise ValueError("output must be outside an alternate evidence root")
        paths = list(args.path)
        for filename in args.paths_file:
            paths.extend(line.strip() for line in Path(filename).read_text(encoding="utf-8").splitlines()
                         if line.strip() and not line.lstrip().startswith("#"))
        paths = [normalized_path(path) for path in paths]
        exclusions = [normalized_path(path) for path in args.exclude]
        if args.no_defaults and not paths:
            raise ValueError("--no-defaults requires at least one custom path")
        profile = Path(args.profile)
        if not profile.is_file():
            profile = REPOSITORY / "profiles" / (args.profile + ".yaml")
        if not args.no_defaults and not profile.is_file():
            raise ValueError("profile does not exist")
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    options = {"schema_version": 1, "source_root": str(root), "output_parent": str(output_parent),
               "profile": "custom_paths" if args.no_defaults else str(profile.resolve()),
               "paths": paths, "exclude": exclusions, "format": args.format,
               "no_live": args.no_live or root != Path("/") or args.no_defaults,
               "complete_logs": args.complete_logs, "max_file_bytes": max(1, int(args.max_file_size_mb * CHUNK)) if args.max_file_size_mb else 0,
               "command_timeout": args.command_timeout, "max_command_bytes": max(1, int(args.max_command_output_mb * CHUNK)),
               "min_free_bytes": int(args.min_free_mb * CHUNK), "case_id": args.case_id, "operator": args.operator,
               "discover_homes": not args.no_defaults,
               "discover_config": not args.no_defaults and (args.discover_config if args.discover_config is not None else profile.resolve() == REPOSITORY / "profiles/linux_dfir.yaml"),
               "started_utc": utc_now(), "repository": str(REPOSITORY)}
    if args.dry_run:
        print(json.dumps(options, indent=2))
        return 0
    old_umask = os.umask(0o077)
    stage, control, process, result = None, None, None, None
    try:
        output_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        check_space(output_parent, options["min_free_bytes"], 4096)
        identifier = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:10]
        stage = Path(tempfile.mkdtemp(prefix=".dfir-" + identifier + "-", dir=output_parent))
        # Only small control data goes in /tmp. The storage alias keeps arbitrary
        # output/root names out of UAC's shell-generated command text.
        control = Path(tempfile.mkdtemp(prefix="uac-dfir-", dir="/tmp"))
        (control / "storage").symlink_to(stage, target_is_directory=True)
        (control / "target").symlink_to(root, target_is_directory=True)
        options["outcomes"] = str(stage / ".control/outcomes")
        options["staging"] = str(stage)
        options["engine_root"] = str(control / "target")
        options["auto_exclude"] = [str(control), str(stage), str(output_parent / "dfir_[0-9]*"),
                                   str(output_parent / ".dfir-*")]
        Path(options["outcomes"]).mkdir(parents=True, mode=0o700)
        request = control / "request.json"
        save_json(request, options)
        command_line = ["/bin/sh", "./uac", "-s", "linux", "-m", str(control / "target"),
                        "-u", "-f", "none", "-o", "collected", "--hostname", "dfir_source",
                        "--temp-dir", str(control / "storage")]
        if args.no_defaults:
            artifact = control / "custom.yaml"
            artifact.write_text("version: 1.0\nartifacts:\n  -\n    description: Custom path request\n"
                                "    supported_os: [linux]\n    collector: file\n    path: /__uac_dfir_custom_request__\n")
            command_line.extend(["-a", str(artifact)])
        else:
            command_line.extend(["-p", str(profile.resolve())])
        command_line.append(str(control / "storage"))
        print("Collecting with UAC; evidence storage: " + str(stage), flush=True)
        process = subprocess.Popen(command_line, cwd=REPOSITORY, start_new_session=True,
                                   env={**os.environ, "UAC_DFIR_REQUEST": str(request),
                                        "UAC_DFIR_PYTHON": sys.executable,
                                        "UAC_DFIR_NO_LIVE": "true" if options["no_live"] else "false"})
        status = process.wait()
        if status not in (0, 3) or not (stage / "collected/collection.json").is_file():
            raise OSError("UAC did not finalize a collection (exit {})".format(status))
        result = output_parent / ("dfir_" + identifier)
        (stage / "collected").rename(result)
        archive = make_archive(result, args.format, options["min_free_bytes"])
        print("Evidence: " + str(result))
        if archive:
            print("Archive: " + str(archive))
        summary = json.loads((result / "collection.json").read_text())["summary"]
        print("Finished with {} acquisition gap(s). Review manifest.json and commands.json.".format(summary["gaps"]))
        shutil.rmtree(stage)
        shutil.rmtree(control)
        return status
    except KeyboardInterrupt:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        try:
            report_partial(result or stage, options, "interrupted by operator")
        except OSError as exc:
            print("Partial report could not be completed: " + str(exc), file=sys.stderr)
        print("Interrupted; partial evidence retained at {} (control: {}).".format(result or stage, control), file=sys.stderr)
        return 130
    except (OSError, ValueError) as exc:
        try:
            report_partial(result or stage, options, str(exc))
        except OSError:
            pass
        print("Collection failed: " + str(exc), file=sys.stderr)
        if result or stage:
            print("Evidence retained at {} (control: {}).".format(result or stage, control), file=sys.stderr)
        return 1
    finally:
        os.umask(old_umask)


if __name__ == "__main__":
    sys.exit(main())
