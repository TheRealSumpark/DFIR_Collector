#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Safe file acquisition and bounded commands for UAC's optional Linux launcher."""

from __future__ import annotations

import argparse
import base64
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
import errno
import fnmatch
import glob
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import selectors
import shutil
import signal
import subprocess
import sys
import time
import uuid
import stat

CHUNK = 1024 * 1024
GAPS = {"error", "changed", "limited", "failed", "timeout", "truncated", "storage_limit"}
HOST_PRIVATE_KEY_REASON = "SSH host private keys require an explicit custom path"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def save_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".partial")
    try:
        temporary.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def load_request(filename):
    with open(filename, encoding="utf-8") as stream:
        request = json.load(stream)
    if request.get("schema_version") != 1:
        raise ValueError("unsupported DFIR request schema")
    return request


class StorageLimit(OSError):
    pass


def check_space(directory, reserve, additional=0):
    if shutil.disk_usage(directory).free < reserve + additional:
        raise StorageLimit("free space would fall below the configured reserve")

def normalized_path(value):
    """Accept paths in the source's namespace, never host-relative or traversal."""
    if not value.startswith("/") or "\x00" in value:
        raise ValueError("source paths must be absolute and contain no NUL bytes")
    if ".." in PurePosixPath(value).parts:
        raise ValueError("parent traversal ('..') is not permitted")
    if "**" in value:
        raise ValueError("use a directory for recursive collection instead of '**'")
    return "/" + str(PurePosixPath(value)).lstrip("/")


class RootFS:
    """Root-anchored descriptor access; refuse symlinks in every parent component."""

    def __init__(self, root):
        self.root = Path(root).resolve(strict=True)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        os.close(self.fd)

    @contextmanager
    def parent(self, logical):
        parts = PurePosixPath(normalized_path(logical)).parts[1:]
        descriptor = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_fd
            yield descriptor, parts[-1] if parts else "."
        finally:
            os.close(descriptor)

    def lstat(self, path):
        with self.parent(path) as (parent, name):
            return os.stat(name, dir_fd=parent, follow_symlinks=False)

    def readlink(self, path):
        with self.parent(path) as (parent, name):
            return os.readlink(name, dir_fd=parent)

    def listdir(self, path):
        with self.parent(path) as (parent, name):
            descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                 dir_fd=parent)
        try:
            return sorted(os.listdir(descriptor))
        finally:
            os.close(descriptor)

    def open_file(self, path):
        with self.parent(path) as (parent, name):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            try:
                return os.open(name, flags | getattr(os, "O_NOATIME", 0), dir_fd=parent)
            except OSError as exc:
                if exc.errno not in (errno.EPERM, errno.EINVAL, errno.EOPNOTSUPP):
                    raise
                return os.open(name, flags, dir_fd=parent)

    def expand(self, pattern):
        """Component globs without glob's implicit traversal through symlinks."""
        parts = PurePosixPath(normalized_path(pattern)).parts[1:]
        matches, issues = [], []

        def walk(prefix, remaining):
            try:
                if not remaining:
                    self.lstat(prefix)
                    matches.append(prefix)
                    return
                part, rest = remaining[0], remaining[1:]
                names = (name for name in self.listdir(prefix)
                         if fnmatch.fnmatchcase(name, part)) if glob.has_magic(part) else [part]
                for name in names:
                    child = prefix.rstrip("/") + "/" + name
                    if rest:
                        info = self.lstat(child)
                        if stat.S_ISLNK(info.st_mode):
                            issues.append({"source": child, "status": "symlink_parent",
                                           "target": self.readlink(child)})
                            continue
                        if not stat.S_ISDIR(info.st_mode):
                            continue
                    walk(child, rest)
            except FileNotFoundError:
                return
            except OSError as exc:
                issues.append({"source": prefix, "status": "error", "error": str(exc)})

        walk("/", parts)
        return matches, issues


def source_metadata(info):
    data = {
        "mode": oct(stat.S_IMODE(info.st_mode)), "uid": info.st_uid, "gid": info.st_gid,
        "size": info.st_size, "inode": info.st_ino, "device": info.st_dev,
        "nlink": info.st_nlink, "atime_ns": info.st_atime_ns,
        "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
        "blocks": getattr(info, "st_blocks", None),
    }
    if hasattr(info, "st_birthtime"):
        data["birthtime"] = info.st_birthtime
    return data


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def checksum_line(digest, filename):
    # GNU sha256sum escaping for unusual evidence filenames.
    if "\\" in filename or "\n" in filename:
        return "\\" + digest + "  " + filename.replace("\\", "\\\\").replace("\n", "\\n") + "\n"
    return digest + "  " + filename + "\n"


def write_checksums(directory):
    with (directory / "SHA256SUMS").open("w", encoding="utf-8", errors="surrogateescape") as output:
        for path in sorted(directory.rglob("*")):
            if not path.is_symlink() and path.is_file() and path != directory / "SHA256SUMS":
                output.write(checksum_line(sha256_file(path), path.relative_to(directory).as_posix()))



class EvidenceCollector:
    def __init__(self, source, output, request):
        self.source, self.output, self.request = source, Path(output), request
        self.output_base = Path(request["output_parent"]).resolve()
        self.args = argparse.Namespace(
            max_file_size_mb=request["max_file_bytes"] / CHUNK,
            exclude=request.get("exclude", []) + request.get("auto_exclude", []),
        )
        self.entries, self.seen = [], {}
        self.traversed_directories = {}

    def event(self, category, path, status, **extra):
        item = {"category": category, "source": path, "status": status, **extra}
        self.entries.append(item)
        return item


    def excluded(self, logical, category=None):
        if category != "custom" and fnmatch.fnmatchcase(logical, "/etc/ssh/ssh_host_*_key"):
            return HOST_PRIVATE_KEY_REASON
        for pattern in self.args.exclude:
            if fnmatch.fnmatchcase(logical, pattern) or logical.startswith(pattern.rstrip("/") + "/"):
                return "investigator exclusion"
        if logical.split("/")[1:2] in (["proc"], ["sys"], ["dev"]):
            return "pseudo-filesystem (use live snapshots)"
        return None


    def collect_path(self, logical, category, recursive=True):
        stack = [logical]
        while stack:
            path = stack.pop()
            previous = self.seen.get(path)
            if previous and category == "custom" and previous.get("reason") == HOST_PRIVATE_KEY_REASON:
                previous.update(status="policy_overridden", overridden_by="explicit custom selection")
                del self.seen[path]
            if path in self.seen:
                categories = self.seen[path].setdefault("categories", [])
                if category not in categories:
                    categories.append(category)
                previous = self.seen[path]
                if recursive and previous["status"] == "directory" and not previous.get("traversed", False):
                    try:
                        previous["traversed"] = True
                        info = self.source.lstat(path)
                        identity = (info.st_dev, info.st_ino)
                        if identity in self.traversed_directories:
                            previous["duplicate_directory_of"] = self.traversed_directories[identity]
                            continue
                        self.traversed_directories[identity] = path
                        stack.extend(path.rstrip("/") + "/" + name
                                     for name in reversed(self.source.listdir(path)))
                    except OSError as exc:
                        self.event(category, path, "error", error=str(exc))
                continue
            reason = self.excluded(path, category)
            if reason:
                entry = self.event(category, path, "excluded", reason=reason)
                self.seen[path] = entry
                continue
            entry = self.event(category, path, "pending", categories=[category])
            self.seen[path] = entry
            try:
                info = self.source.lstat(path)
                entry["metadata"] = source_metadata(info)
                if stat.S_ISLNK(info.st_mode):
                    entry.update(status="symlink", target=self.source.readlink(path))
                elif stat.S_ISDIR(info.st_mode):
                    entry["status"] = "directory"
                    entry["traversed"] = recursive
                    if recursive:
                        identity = (info.st_dev, info.st_ino)
                        if identity in self.traversed_directories:
                            entry["duplicate_directory_of"] = self.traversed_directories[identity]
                            continue
                        self.traversed_directories[identity] = path
                        stack.extend(path.rstrip("/") + "/" + name
                                     for name in reversed(self.source.listdir(path)))
                elif stat.S_ISREG(info.st_mode):
                    self.copy_regular(path, info, entry)
                else:
                    entry.update(status="special", reason="FIFO/socket/device; metadata only")
            except StorageLimit as exc:
                entry.update(status="storage_limit", error=str(exc))
                raise
            except OSError as exc:
                entry.update(status="error", error=str(exc))


    def copy_regular(self, logical, info, entry):
        limit = int(self.args.max_file_size_mb * CHUNK)
        if self.request.get("complete_logs") and (logical == "/var/log" or logical.startswith("/var/log/") or logical.startswith("/run/log/")):
            limit = 0
        check_space(self.output, self.request["min_free_bytes"])
        if limit and info.st_size > limit:
            entry.update(status="limited", reason="file exceeds --max-file-size-mb")
            return
        destination = self.output / "[root]" / logical.lstrip("/")
        part = destination.with_name(destination.name + ".part-" + uuid.uuid4().hex)
        digest, copied = hashlib.sha256(), 0
        try:
            with os.fdopen(self.source.open_file(logical), "rb") as original:
                opened = os.fstat(original.fileno())
                if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise OSError("source was replaced between discovery and open")
                entry["metadata"] = source_metadata(opened)
                if limit and opened.st_size > limit:
                    entry.update(status="limited", reason="file grew beyond --max-file-size-mb")
                    return
                try:
                    entry["xattrs_base64"] = {
                        name: base64.b64encode(os.getxattr(original.fileno(), name)).decode("ascii")
                        for name in os.listxattr(original.fileno())
                    }
                except OSError as exc:
                    entry["xattr_error"] = str(exc)
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with part.open("xb") as saved:
                    remaining = opened.st_size
                    while remaining:
                        block = original.read(min(CHUNK, remaining))
                        if not block:
                            break
                        check_space(self.output, self.request["min_free_bytes"], 0 if block.count(0) == len(block) else len(block))
                        # Keep sparse zero regions sparse (e.g. lastlog databases).
                        if block.count(0) == len(block):
                            saved.seek(len(block), os.SEEK_CUR)
                        else:
                            saved.write(block)
                        digest.update(block)
                        copied += len(block)
                        remaining -= len(block)
                    saved.truncate(copied)
                after = os.fstat(original.fileno())
            part.replace(destination)
            os.utime(destination, ns=(opened.st_atime_ns, opened.st_mtime_ns))
            try:
                current = self.source.lstat(logical)
                replaced = (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
            except OSError:
                replaced = True
            changed = (replaced or copied != opened.st_size or
                       (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) !=
                       (after.st_size, after.st_mtime_ns, after.st_ctime_ns))
            entry.update(status="changed" if changed else "collected", bytes=copied,
                         sha256=digest.hexdigest(), saved_as=destination.relative_to(self.output).as_posix(),
                         after_metadata=source_metadata(after))
        finally:
            if part.exists():
                part.unlink()


def nul_records(path):
    pending = b""
    with open(path, "rb") as stream:
        while True:
            block = stream.read(CHUNK)
            if not block:
                break
            pending += block
            values = pending.split(b"\0")
            pending = values.pop()
            if len(pending) > CHUNK:
                raise ValueError("oversized or unterminated discovery record")
            for value in values:
                yield os.fsdecode(value)
    if pending:
        raise ValueError("discovery stream ended inside a NUL-delimited record")


def command(request_file, shell_command, redirect_stderr, kind, artifact):
    """Run a trusted catalog command, preserving output and killing its process group."""
    request = load_request(request_file)
    outcomes = Path(request["outcomes"])
    outcomes.mkdir(parents=True, exist_ok=True, mode=0o700)
    identifier = uuid.uuid4().hex
    record = {"kind": kind, "artifact": artifact, "command": shell_command,
              "started_utc": utc_now(), "status": "error", "returncode": None,
              "stdout_bytes": 0, "stderr_bytes": 0}
    stdout_path, stderr_path = (outcomes / (identifier + suffix) for suffix in (".stdout", ".stderr"))
    process = None
    selector = selectors.DefaultSelector()
    discovery_buffer = b""
    deadline = time.monotonic() + request["command_timeout"]
    used = 0
    status = "collected"

    def terminate_group():
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def cancel(signum, frame):
        raise KeyboardInterrupt

    old_term = signal.signal(signal.SIGTERM, cancel)
    try:
        with stdout_path.open("xb") as saved_stdout, stderr_path.open("xb") as saved_stderr:
            check_space(outcomes, request["min_free_bytes"])
            process = subprocess.Popen(
                ["/bin/sh", "-c", '. "$1/lib/command_exists.sh"; eval "$2"', "uac-command",
                 request["repository"], shell_command],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True, env={**os.environ, "LC_ALL": "C", "TZ": "UTC",
                                             "SYSTEMD_PAGER": "cat", "PAGER": "cat"},
            )
            selector.register(process.stdout, selectors.EVENT_READ, (saved_stdout, "stdout"))
            selector.register(process.stderr, selectors.EVENT_READ, (saved_stderr, "stderr"))
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    status = "timeout"
                    break
                for key, _ in selector.select(min(0.2, remaining)):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    allowed = min(len(block), max(0, request["max_command_bytes"] - used))
                    clipped = block[:allowed]
                    check_space(outcomes, request["min_free_bytes"], len(clipped))
                    destination, channel = key.data
                    destination.write(clipped)
                    record[channel + "_bytes"] += len(clipped)
                    used += len(clipped)
                    if kind == "discovery" and channel == "stdout":
                        discovery_buffer += clipped
                        values = discovery_buffer.split(b"\0")
                        discovery_buffer = values.pop()
                        for value in values:
                            sys.stdout.buffer.write(os.fsencode(artifact) + b"\0" + value + b"\0")
                    elif channel == "stdout" or redirect_stderr:
                        sys.stdout.buffer.write(clipped)
                    if allowed < len(block):
                        status = "truncated"
                        break
                if status != "collected":
                    break
            if status != "collected":
                terminate_group()
            try:
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                status = "timeout"
                terminate_group()
                process.wait()
            record["returncode"] = process.returncode
            if status == "collected" and discovery_buffer:
                status = "truncated"
                record["error"] = "discovery command emitted an incomplete NUL record"
            if status == "collected" and process.returncode:
                saved_stderr.flush()
                stderr_text = stderr_path.read_text(errors="replace")
                # Missing default paths are expected; permissions and other errors remain gaps.
                missing = [line for line in stderr_text.splitlines() if line]
                if kind == "condition":
                    status = "condition_not_met"
                elif kind == "discovery" and missing and all("No such file or directory" in line for line in missing):
                    status = "missing"
                elif process.returncode == 127:
                    status = "unavailable"
                else:
                    status = "failed"
    except StorageLimit as exc:
        status = "storage_limit"
        record["error"] = str(exc)
    except KeyboardInterrupt:
        status = "error"
        record["error"] = "command cancelled"
    except (OSError, ValueError) as exc:
        status = "error"
        record["error"] = str(exc)
    finally:
        terminate_group()
        if process is not None:
            process.wait()
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        selector.close()
        signal.signal(signal.SIGTERM, old_term)
        record.update(status=status, finished_utc=utc_now(), id=identifier)
        save_json(outcomes / (identifier + ".json"), record)
    return record["returncode"] if status in {"collected", "missing", "condition_not_met", "unavailable"} else 124


def read_config(source, path):
    if any(path == prefix or path.startswith(prefix + "/") for prefix in ("/proc", "/sys", "/dev")):
        raise ValueError("kernel pseudo-filesystems are not configuration sources")
    with os.fdopen(source.open_file(path), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("configuration source is not a regular file")
        data = stream.read(CHUNK + 1)
    if len(data) > CHUNK:
        raise ValueError("configuration discovery is limited to 1 MiB per file")
    return data.decode("utf-8", errors="replace")


def record_outcome(request, value):
    directory = Path(request["outcomes"])
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    value.setdefault("id", uuid.uuid4().hex)
    value.setdefault("started_utc", utc_now())
    value.setdefault("finished_utc", utc_now())
    value.setdefault("stdout_bytes", 0)
    value.setdefault("stderr_bytes", 0)
    save_json(directory / (value["id"] + ".json"), value)


def homes(request_file, skip_nologin):
    request = load_request(request_file)
    candidates = {("root", "/root")}
    if not request.get("discover_homes", True):
        print("root:/root")
        return 0
    with RootFS(request["source_root"]) as source:
        try:
            for line in read_config(source, "/etc/passwd").splitlines():
                fields = line.split(":")
                if len(fields) < 7 or (skip_nologin and fields[6].endswith(("false", "nologin", "halt", "shutdown", "sync", "git-shell"))):
                    continue
                try:
                    home = normalized_path(fields[5])
                    if "\n" not in home and ":" not in home and "\n" not in fields[0] and ":" not in fields[0]:
                        candidates.add((fields[0], home))
                except ValueError:
                    continue
        except FileNotFoundError:
            pass
        except (ValueError, OSError) as exc:
            if not skip_nologin:
                record_outcome(request, {"kind": "discovery", "artifact": "account_homes", "status": "error", "error": str(exc)})
        matches, issues = source.expand("/home/*")
        for home in matches:
            if stat.S_ISDIR(source.lstat(home).st_mode) and ":" not in home and "\n" not in home:
                candidates.add((PurePosixPath(home).name, home))
        if issues and not skip_nologin:
            record_outcome(request, {"kind": "discovery", "artifact": "account_homes", "status": "policy_skipped", "issues": issues})
    for user, home in sorted(candidates):
        print(user + ":" + home)
    return 0


def discover(request_file, path_text, is_file_list, path_pattern, name_pattern,
             exclude_path, exclude_name, file_type, max_depth, min_size, permissions, artifact):
    """Apply UAC file-collector rules using root-anchored traversal, never shell eval."""
    import shlex

    request = load_request(request_file)
    record = {"kind": "discovery", "artifact": artifact, "path": path_text,
              "status": "collected", "started_utc": utc_now(), "matches": 0,
              "stdout_bytes": 0, "stderr_bytes": 0, "issues": []}
    deadline = time.monotonic() + request["command_timeout"]
    status_code = 0
    try:
        patterns = shlex.split(path_text)
        if is_file_list:
            expanded = []
            for path in patterns:
                candidate = Path(path).resolve()
                staging = Path(request["staging"]).resolve()
                if staging == candidate or staging in candidate.parents:
                    # These are lists generated by trusted catalog commands in the private workspace.
                    content = candidate.read_text(errors="surrogateescape")
                else:
                    with RootFS(request["source_root"]) as source:
                        content = read_config(source, normalized_path(path))
                expanded.extend(line for line in content.splitlines() if line)
            patterns = expanded
        types = set(file_type.split("|")) if file_type else set()
        names = [value for value in name_pattern.split("|") if value]
        paths = [value for value in path_pattern.split("|") if value]
        excluded_paths = [value for value in exclude_path.split("|") if value] + request.get("exclude", []) + request.get("auto_exclude", [])
        excluded_names = [value for value in exclude_name.split("|") if value]
        depth_limit = int(max_depth or 0)
        minimum = int(min_size or 0)
        with RootFS(request["source_root"]) as source:
            traversed_directories = {}
            for pattern in patterns:
                engine_prefix = request["engine_root"].rstrip("/") + "/"
                if pattern.startswith(engine_prefix):
                    pattern = "/" + pattern[len(engine_prefix):]
                matches, issues = source.expand(normalized_path(pattern))
                record["issues"].extend(issues)
                stack = [(value, 0) for value in reversed(matches)]
                while stack:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("file discovery exceeded its deadline")
                    logical, depth = stack.pop()
                    name = PurePosixPath(logical).name
                    if any(fnmatch.fnmatchcase(logical, value) or logical.startswith(value.rstrip("/") + "/") for value in excluded_paths):
                        continue
                    if any(fnmatch.fnmatchcase(name, value) for value in excluded_names):
                        continue
                    try:
                        info = source.lstat(logical)
                    except OSError as exc:
                        record["issues"].append({"source": logical, "status": "error", "error": str(exc)})
                        continue
                    mode = info.st_mode
                    kind = ("d" if stat.S_ISDIR(mode) else "l" if stat.S_ISLNK(mode) else
                            "f" if stat.S_ISREG(mode) else "p" if stat.S_ISFIFO(mode) else
                            "s" if stat.S_ISSOCK(mode) else "b" if stat.S_ISBLK(mode) else "c")
                    if kind == "d" and (not depth_limit or depth < depth_limit):
                        try:
                            identity = (info.st_dev, info.st_ino)
                            if identity not in traversed_directories:
                                traversed_directories[identity] = logical
                                stack.extend((logical.rstrip("/") + "/" + child, depth + 1)
                                             for child in reversed(source.listdir(logical)))
                            else:
                                record["issues"].append({"source": logical, "status": "duplicate_directory", "first_seen": traversed_directories[identity]})
                        except OSError as exc:
                            record["issues"].append({"source": logical, "status": "error", "error": str(exc)})
                    if types and kind not in types:
                        continue
                    if names and not any(fnmatch.fnmatchcase(name, value) for value in names):
                        continue
                    if paths and not any(fnmatch.fnmatchcase(logical, value) for value in paths):
                        continue
                    if minimum and info.st_size < minimum:
                        continue
                    if permissions:
                        def permitted(value):
                            bits = int(value.lstrip("-"), 8)
                            actual = stat.S_IMODE(mode)
                            return actual & bits == bits if value.startswith("-") else actual == bits
                        if not any(permitted(value) for value in permissions.split("|")):
                            continue
                    value = os.fsencode(artifact) + b"\0" + os.fsencode(request["engine_root"].rstrip("/") + logical) + b"\0"
                    if record["stdout_bytes"] + len(value) > request["max_command_bytes"]:
                        record["status"] = "truncated"
                        raise ValueError("file discovery exceeded its output budget")
                    sys.stdout.buffer.write(value)
                    record["stdout_bytes"] += len(value)
                    record["matches"] += 1
        if any(issue["status"] == "error" for issue in record["issues"]):
            record["status"] = "error"
        elif not record["matches"]:
            record["status"] = "missing" if not record["issues"] else "policy_skipped"
    except FileNotFoundError:
        record["status"] = "missing"
    except TimeoutError as exc:
        record.update(status="timeout", error=str(exc))
        status_code = 124
    except (ValueError, OSError) as exc:
        if record["status"] != "truncated":
            record["status"] = "error"
        record["error"] = str(exc)
        status_code = 1
    record_outcome(request, record)
    return status_code


def configured_paths(collector):
    """Discover literal history/key locations without sourcing shell files or running sshd."""
    import re
    import shlex

    source = collector.source
    accounts = []
    try:
        for line in read_config(source, "/etc/passwd").splitlines():
            fields = line.split(":")
            if len(fields) >= 7:
                try:
                    accounts.append((fields[0], fields[2], normalized_path(fields[5])))
                except ValueError:
                    collector.event("configuration", "/etc/passwd", "unresolved_config", reason="invalid home path")
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        collector.event("configuration", "/etc/passwd", "error", error=str(exc))
    accounts = list(dict.fromkeys([("root", "0", "/root"), *accounts]))
    assignment = re.compile(r"^\s*(?:export\s+)?(HISTFILE|ZDOTDIR|XDG_DATA_HOME|XDG_CONFIG_HOME)\s*=\s*(.*)$")
    for user, uid, home in accounts:
        variables = {"HOME": home, "USER": user, "LOGNAME": user,
                     "XDG_DATA_HOME": home + "/.local/share", "XDG_CONFIG_HOME": home + "/.config"}
        configs = ["/etc/profile", home + "/.profile", home + "/.bash_profile", home + "/.bashrc",
                   home + "/.zshenv", home + "/.zprofile", home + "/.zshrc"]
        visited = set()
        while configs and len(visited) < 64:
            path = configs.pop(0)
            if path in visited:
                continue
            visited.add(path)
            try:
                content = read_config(source, path)
            except FileNotFoundError:
                continue
            except (OSError, ValueError) as exc:
                collector.event("configuration", path, "unresolved_config", error=str(exc))
                continue
            yield "configured_startup", path
            for line in content.splitlines():
                match = assignment.match(line)
                if not match:
                    continue
                key, raw_value = match.groups()
                try:
                    raw_tokens = shlex.split(raw_value, comments=True, posix=False)
                    values = shlex.split(raw_value, comments=True)
                    if not values and key == "HISTFILE":
                        continue
                    literal = len(raw_tokens) == 1 and raw_tokens[0].startswith("'") and raw_tokens[0].endswith("'")
                    if len(values) != 1 or (not literal and ("$(" in values[0] or "`" in values[0])):
                        raise ValueError("dynamic shell assignment is not evaluated")
                    value = values[0]
                    if not literal:
                        value = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)",
                                       lambda m: variables.get(m.group(1) or m.group(2), m.group(0)), value)
                    if not literal and "$" in value:
                        raise ValueError("assignment references an unresolved variable")
                    if value.startswith("~/"):
                        value = home + value[1:]
                    value = normalized_path(value)
                    if key == "HISTFILE":
                        yield "configured_history", value
                    elif key == "ZDOTDIR":
                        configs.extend(value + suffix for suffix in ("/.zshenv", "/.zprofile", "/.zshrc"))
                        yield "configured_history", value + "/.zsh_history"
                    elif key == "XDG_DATA_HOME":
                        yield "configured_history", value + "/fish"
                    elif key == "XDG_CONFIG_HOME":
                        yield "configured_startup", value + "/fish"
                    variables[key] = value
                except ValueError as exc:
                    collector.event("configuration", path, "unresolved_config", setting=key, reason=str(exc))

    configs, _ = source.expand("/etc/ssh/sshd_config*")
    queue = list(configs)
    visited = set()
    while queue and len(visited) < 128:
        path = queue.pop(0)
        if path in visited:
            continue
        visited.add(path)
        try:
            if stat.S_ISDIR(source.lstat(path).st_mode):
                queue.extend(path.rstrip("/") + "/" + name for name in source.listdir(path))
                continue
            content = read_config(source, path)
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            collector.event("configuration", path, "unresolved_config", error=str(exc))
            continue
        for line in content.splitlines():
            try:
                fields = shlex.split(line, comments=True)
            except ValueError:
                continue
            if len(fields) < 2:
                continue
            key, values = fields[0].lower(), fields[1:]
            if key == "include":
                for value in values:
                    try:
                        matches, issues = source.expand(value if value.startswith("/") else "/etc/ssh/" + value)
                        queue.extend(matches)
                        collector.entries.extend({"category": "configuration", **issue} for issue in issues)
                    except ValueError as exc:
                        collector.event("configuration", path, "unresolved_config", reason=str(exc))
            elif key in {"authorizedkeysfile", "authorizedprincipalsfile"}:
                for value in values:
                    if value.lower() == "none":
                        continue
                    for user, uid, home in accounts:
                        try:
                            if re.search(r"%(?![%huU])", value):
                                raise ValueError("SSH key path uses an unsupported token")
                            replacements = {"%": "%", "h": home, "u": user, "U": uid}
                            candidate = re.sub(r"%([%huU])", lambda m: replacements[m.group(1)], value)
                            yield "configured_ssh", normalized_path(candidate if candidate.startswith("/") else home + "/" + candidate)
                        except ValueError as exc:
                            collector.event("configuration", path, "unresolved_config", reason=str(exc))
            elif key == "authorizedkeyscommand":
                collector.event("configuration", path, "external_key_source", reason="AuthorizedKeysCommand is recorded but not executed")


def finish(request_file, temp_directory, output_directory, engine_root):
    request = load_request(request_file)
    output, temp = Path(output_directory), Path(temp_directory)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    command_records = []
    with RootFS(request["source_root"]) as source:
        collector = EvidenceCollector(source, output, request)
        try:
            discoveries = temp / "file_collector.nul"
            if discoveries.exists():
                records = iter(nul_records(discoveries))
                while True:
                    artifact = next(records, None)
                    if artifact is None:
                        break
                    candidate = next(records, None)
                    if candidate is None:
                        raise ValueError("unpaired artifact/path discovery record")
                    prefix = engine_root.rstrip("/") + "/"
                    if not candidate.startswith(prefix):
                        collector.event(artifact, candidate, "error", error="discovery path is outside the selected evidence root")
                        continue
                    logical = normalized_path("/" + candidate[len(prefix):])
                    collector.collect_path(logical, artifact, recursive=False)
            selections = [("custom", path) for path in request.get("paths", [])]
            if request.get("complete_logs"):
                selections.extend(("complete_logs", path) for path in ("/var/log", "/run/log"))
            if request.get("discover_config", True):
                selections.extend(configured_paths(collector))
            for category, pattern in selections:
                if category.startswith("configured_"):
                    try:
                        source.lstat(pattern)
                        matches, issues = [pattern], []
                    except FileNotFoundError:
                        matches, issues = [], []
                    except OSError as exc:
                        matches, issues = [], [{"source": pattern, "status": "error", "error": str(exc)}]
                else:
                    matches, issues = source.expand(pattern)
                collector.entries.extend({"category": category, **issue} for issue in issues)
                if not matches and not issues:
                    collector.event(category, pattern, "error" if category == "custom" else "missing",
                                    reason="explicit custom path did not match" if category == "custom" else "optional source not present")
                for logical in matches:
                    collector.collect_path(logical, category)
        except (StorageLimit, ValueError, OSError) as exc:
            collector.event("collector", "file acquisition", "storage_limit" if isinstance(exc, StorageLimit) else "error", error=str(exc))
        for path in sorted(Path(request["outcomes"]).glob("*.json")):
            record = json.loads(path.read_text())
            command_records.append(record)
            if record["kind"] == "command" or record["stderr_bytes"]:
                destination = output / "command_results"
                destination.mkdir(mode=0o700, exist_ok=True)
                for suffix in (".stdout", ".stderr"):
                    saved = path.with_suffix(suffix)
                    if saved.exists():
                        target = destination / saved.name
                        saved.replace(target)
                        record[suffix[1:] + "_file"] = target.relative_to(output).as_posix()
        if (temp / "uac.log").exists():
            shutil.copyfile(temp / "uac.log", output / "uac.log")
        for path in list(output.rglob("*")):
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) and not stat.S_ISDIR(info.st_mode):
                collector.event("generated_output", path.relative_to(output).as_posix(), "policy_skipped", reason="generated link/special file is metadata only")
                path.unlink()
        entries = collector.entries
        gaps = sum(entry["status"] in GAPS or "xattr_error" in entry for entry in [*entries, *command_records])
        save_json(output / "manifest.json", entries)
        save_json(output / "commands.json", command_records)
        definitions = []
        if (temp / "artifact_list.tmp").exists():
            for filename in (temp / "artifact_list.tmp").read_text().splitlines():
                path = Path(filename)
                if path.is_file():
                    definitions.append({"path": filename, "sha256_at_finalization": sha256_file(path)})
        save_json(output / "artifact_definitions.json", definitions)
        save_json(output / "collection.json", {
            "schema_version": 1, "collector": "UAC Linux DFIR", "started_utc": request["started_utc"],
            "runtime_sha256": sha256_file(Path(__file__)),
            "finished_utc": utc_now(), "source_root": request["source_root"], "profile": request["profile"],
            "case_id": request.get("case_id", ""), "operator": request.get("operator", ""),
            "mode": "live" if request["source_root"] == "/" else "mounted-source",
            "options": {key: request[key] for key in ("complete_logs", "max_file_bytes", "command_timeout", "max_command_bytes", "min_free_bytes", "format")},
            "configuration_discovery": request.get("discover_config", True),
            "summary": {"gaps": gaps, "file_status_counts": dict(Counter(entry["status"] for entry in entries)),
                        "command_status_counts": dict(Counter(entry["status"] for entry in command_records))},
            "limitations": ["Live acquisition is not an atomic snapshot; source reads can change access times.",
                            "Source symlinks and devices are metadata only; symlink parents are refused.",
                            "Only literal recognized history/SSH configuration is discovered; dynamic and external sources are reported.",
                            "SSH Match rules are not evaluated; configured key paths are considered for all discovered accounts.",
                            "Collector definition hashes are recorded at finalization, not an atomic snapshot of code during execution.",
                            "No deleted-file recovery, memory acquisition, or remote-log retrieval."],
        })
        write_checksums(output)
    return 3 if gaps else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    runner = subparsers.add_parser("command")
    runner.add_argument("request")
    runner.add_argument("shell_command")
    runner.add_argument("redirect_stderr")
    runner.add_argument("kind")
    runner.add_argument("artifact")
    finalizer = subparsers.add_parser("finish")
    finalizer.add_argument("request")
    finalizer.add_argument("temp_directory")
    finalizer.add_argument("output_directory")
    finalizer.add_argument("engine_root")
    home_parser = subparsers.add_parser("homes")
    home_parser.add_argument("request")
    home_parser.add_argument("skip_nologin")
    finder = subparsers.add_parser("discover")
    for name in ("request", "path_text", "is_file_list", "path_pattern", "name_pattern", "exclude_path", "exclude_name", "file_type", "max_depth", "min_size", "permissions", "artifact"):
        finder.add_argument(name)
    rejected = subparsers.add_parser("unsupported")
    rejected.add_argument("request")
    rejected.add_argument("collector")
    rejected.add_argument("artifact")
    args = parser.parse_args(argv)
    if args.action == "command":
        return command(args.request, args.shell_command, args.redirect_stderr == "true", args.kind, args.artifact)
    if args.action == "finish":
        return finish(args.request, args.temp_directory, args.output_directory, args.engine_root)
    if args.action == "homes":
        return homes(args.request, args.skip_nologin == "true")
    if args.action == "discover":
        return discover(args.request, args.path_text, args.is_file_list == "true", args.path_pattern,
                        args.name_pattern, args.exclude_path, args.exclude_name, args.file_type,
                        args.max_depth, args.min_size, args.permissions, args.artifact)
    if args.action == "unsupported":
        record_outcome(load_request(args.request), {"kind": "discovery", "artifact": args.artifact,
                       "status": "error", "error": "Unsupported collector in confined DFIR mode: " + args.collector})
        return 1
    parser.error("unsupported action")


if __name__ == "__main__":
    sys.exit(main())
