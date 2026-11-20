#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reproduce four UAC review findings using dummy evidence in temporary folders.

Does not run a UAC collection, access live artifacts, or modify the UAC checkout.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run_helper(repository, helper, body, environment):
    result = subprocess.run(
        ["/bin/sh", "-c", '. "$DFIR_REVIEW_HELPER"\n' + body],
        env={**os.environ, **environment,
             "DFIR_REVIEW_HELPER": str(repository / "lib" / helper)},
        capture_output=True, text=True, timeout=10,
    )
    return result


def review(repository):
    results = []
    with tempfile.TemporaryDirectory(prefix="uac-review-") as temporary:
        base = Path(temporary)
        temp_data = base / "uac-data.tmp"
        environment = {
            "__UAC_TEMP_DATA_DIR": str(temp_data),
            "__UAC_ARTIFACTS_OUTPUT_DIR": str(temp_data / "collected"),
            "__UAC_LOG_FILE": "uac.log",
        }
        result = run_helper(repository, "init_temp_data_dir.sh", "umask 022\n_init_temp_data_dir", environment)
        results.append({
            "finding": "temporary_evidence_permissions",
            "reproduced": result.returncode == 0 and (temp_data.stat().st_mode & 0o777) == 0o755,
            "observed_directory_mode": oct(temp_data.stat().st_mode & 0o777),
            "observed_log_mode": oct((temp_data / "uac.log").stat().st_mode & 0o777),
        })

        log_path = base / "acquisition.log"
        result = run_helper(repository, "create_acquisition_log.sh",
                            '_create_acquisition_log "$DFIR_REVIEW_LOG" start end "" "" ""',
                            {**environment, "DFIR_REVIEW_LOG": str(log_path),
                             "__UAC_OUTPUT_FORMAT": "zip", "__UAC_OUTPUT_PASSWORD": "DUMMY-REVIEW-SECRET"})
        results.append({
            "finding": "zip_password_in_acquisition_log",
            "reproduced": result.returncode == 0 and "DUMMY-REVIEW-SECRET" in log_path.read_text(),
            "observed": "dummy archive password is included in the acquisition log",
        })

        source_dir = base / "source"
        source_dir.mkdir()
        source_path = source_dir / "back\\slash.log"
        source_path.write_bytes(b"dummy evidence\n")
        list_path = base / "files.txt"
        list_path.write_text(str(source_path) + "\n")
        destination = base / "copied"
        destination.mkdir()
        result = run_helper(repository, "copy_data.sh",
                            '_copy_data "$DFIR_REVIEW_LIST" "$DFIR_REVIEW_DEST"',
                            {**environment, "__UAC_MOUNT_POINT": "/",
                             "DFIR_REVIEW_LIST": str(list_path), "DFIR_REVIEW_DEST": str(destination)})
        results.append({
            "finding": "backslash_filename_copy",
            "reproduced": not any(path.is_file() for path in destination.rglob("*")),
            "observed": "dummy source exists but the copy loop drops the backslash",
            "helper_exit_code": result.returncode,
        })

        calls = base / "tar-arguments.txt"
        result = run_helper(repository, "tar_data.sh", '''
_verbose_msg() { :; }
tar() { printf '%s\\n' "$@" >"$DFIR_REVIEW_CALLS"; return 0; }
_tar_data "$DFIR_REVIEW_LIST" "$DFIR_REVIEW_ARCHIVE"
''', {**environment, "__UAC_OPERATING_SYSTEM": "linux",
      "__UAC_TOOL_TAR_NO_FROM_FILE_SUPPORT": "true", "__UAC_VERBOSE_CMD_PREFIX": "",
      "DFIR_REVIEW_CALLS": str(calls), "DFIR_REVIEW_LIST": str(list_path),
      "DFIR_REVIEW_ARCHIVE": str(base / "dummy.tar")})
        arguments = calls.read_text().splitlines()
        results.append({
            "finding": "tar_without_file_list_support",
            "reproduced": result.returncode == 0 and "-T" in arguments,
            "observed": "tar still receives -T when the unsupported-file-list flag is true",
        })
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    results = review(args.repository.resolve(strict=True))
    print(json.dumps(results, indent=2))
    return 0 if all(item["reproduced"] for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
