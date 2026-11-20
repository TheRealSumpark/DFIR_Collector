# Linux DFIR launcher

`dfir.py` uses UAC's profile and artifact definitions with a root-confined Linux
file backend and bounded command runner. Python 3.9+ and Linux are required; there
are no external Python dependencies. UAC's ordinary shell interface remains
available for other Unix systems and existing profiles.

Run as root for protected artifacts. Non-root runs continue and report unreadable
sources as acquisition gaps.

## Collect and select sources

```shell
python3 dfir.py --help
sudo python3 dfir.py --output /mnt/evidence --complete-logs --format zip \
  --case-id IR-2026-001 --operator Analyst

sudo python3 dfir.py --output /mnt/evidence \
  --path /srv/application/logs --path '/opt/application/audit/*.log*'

# Custom paths only. No live commands or automatic configuration discovery.
sudo python3 dfir.py --output /mnt/evidence --no-defaults \
  --path /var/log --path /root/.ssh/authorized_keys --format tar.gz

# UTF-8 path list: one absolute path or glob per line; blank/# comment lines ignored.
sudo python3 dfir.py --output /mnt/evidence --paths-file extra-paths.txt \
  --exclude '/var/log/app/cache/*'

python3 dfir.py --root /mnt/linux-image --output /mnt/evidence --dry-run
```

Paths are in the source filesystem's namespace. With `--root /mnt/linux-image`,
`--path /var/log` selects `/mnt/linux-image/var/log`. Output must be outside an
alternate source root. Mounting evidence read-only is recommended; the launcher
does not mount or change the source's mount options. Kernel pseudo-filesystems
are not valid alternate evidence roots.

Directories recurse. Globs support `*`, `?` and bracket expressions within a path
component; select a directory for recursive acquisition instead of `**`.
`--path` preserves whitespace and newline characters passed as one argument.
Path-list files are line-oriented and strip surrounding whitespace; use `--path`
for names a line list cannot represent. Parent traversal and NUL bytes are refused.
Custom paths are transported as JSON, not evaluated as shell fragments.

The default `linux_dfir` profile selects logs, shell/database histories, SSH access
files, configuration, persistence, package information, container logs and live
state. See [ARTIFACTS.md](../ARTIFACTS.md) for sources and boundaries. Missing
optional sources/tools are normal. An explicit unmatched custom path is a gap.

Use `--profile NAME` or a trusted profile file for a different selection. Profiles
contain executable commands; only run definitions you trust. The Linux backend
supports file collectors and command collectors. It honors file path/name/type,
exclusion, depth, minimum-size and permission predicates. Unsupported collector
types and no-user/no-group/filesystem predicates are recorded as gaps rather than
executed with weaker root confinement. Ordinary `./uac` retains these capabilities.
The launcher's file-size policy replaces individual artifact maximum-size limits;
its own exclusions and explicit source selection are applied to copying. Native
`uac.conf` filesystem exclusions are not the launcher's mount-selection policy;
use source paths and `--exclude` to control mounted subtrees.

## Output formats and verification

Choose `--format directory`, `tar`, `tar.gz` or `zip`. The default is `tar.gz`.
The evidence directory is retained alongside an optional archive, allowing direct
review and verification. ZIP uses Python's ZIP64-capable implementation without
requiring a `zip` executable. It is unencrypted. Original timestamps are kept in
the manifest even when ZIP's timestamp range requires clipping.

```text
/mnt/evidence/dfir_UTC_ID/
  [root]/                 source files with their original hierarchy
  live_response/          UAC's named command outputs
  command_results/        raw command stdout/stderr where retained
  manifest.json           file outcomes, SHA-256, source metadata, link targets
  commands.json           artifact/query/discovery outcomes and command codes
  artifact_definitions.json  hashes of selected definitions at finalization
  collection.json         case, operator, times, settings, counts, limitations
  uac.log                 redacted UAC progress log
  SHA256SUMS              hashes for all saved files and reports except itself
```

The archive and its `.sha256` file are written beside this directory.

```shell
cd /mnt/evidence/dfir_UTC_ID
sha256sum --check SHA256SUMS

cd /mnt/evidence
sha256sum --check dfir_UTC_ID.zip.sha256
```

Manifest hashes describe acquired bytes. Metadata includes ownership, original
modes, sizes, inode/device/link counts, nanosecond timestamps and regular-file
extended attributes encoded as base64. Birth time is included only when the
platform exposes it. Copies and reports stay private; source ownership/modes
are documented rather than restored as permissive output permissions.

ZIP filenames must be representable by the ZIP writer. If a name cannot be
encoded, packaging fails explicitly and the evidence directory remains available;
tar output can be used for byte-oriented Unix filenames. Source symlinks are
metadata-only and do not become output links.

## Limits and partial collections

```shell
sudo python3 dfir.py --output /mnt/evidence \
  --max-file-size-mb 2048 --command-timeout 120 \
  --max-command-output-mb 256 --min-free-mb 512 --format zip
```

- The default regular-file cap is 1 GiB. `--max-file-size-mb 0` removes it for all
  selected files. Omitted large files are recorded individually as gaps.
- `--complete-logs` additionally selects `/var/log` and `/run/log` recursively and
  removes the file-size cap for their regular log files. It does not discover
  every relocated application or remote log destination.
- Each live command has a 60-second deadline and 128 MiB combined stdout/stderr
  cap by default. Partial output is retained and labeled. Discovery also checks a
  deadline and output budget, while filesystem calls themselves can block on an
  unhealthy filesystem. File copying does not provide a hard I/O timeout.
- The default free-space reserve is 256 MiB. Space is checked during copying,
  command capture and archive writes. Sparse zero regions stay sparse where
  supported, but reading and hashing their logical bytes can still take time.
- `--no-live` skips command collectors. Mounted-source mode and `--no-defaults`
  do this automatically. Runtime data cannot be recovered from a mounted disk.
- A command's return code follows the shell expression in the trusted artifact;
  a custom pipeline can mask an earlier stage's failure. The focused snapshot
  artifact runs its queries separately.

| Exit | Meaning |
| --- | --- |
| `0` | Finished without detected acquisition gaps. Review missing/skipped/unresolved sources. |
| `1` | Fatal collection, storage, or packaging failure; partial evidence is retained. |
| `2` | Invalid CLI/source/output configuration. |
| `3` | Finished with gaps, such as unreadable/changed/oversized files or failed/bounded commands. |
| `130` | Interrupted by the operator; saved bytes and partial reporting are retained. |

Incomplete runs retain a private `.dfir-*` workspace on the selected evidence
storage and a small `/tmp/uac-dfir-*` control directory. The error message gives
their exact paths. Cancellation does not resume source acquisition to finish a
report: `partial_collection.json` and checksums describe only bytes already saved.
If storage itself prevents report writing, existing evidence is left in place.
Successful runs remove their own staging/control directories, never another run's.

## Configuration discovery and evidence limitations

The backend reads account homes and recognized literal `HISTFILE`, `ZDOTDIR` and
XDG assignments without sourcing shell files. It can substitute known home/user
variables. Dynamic expressions are reported and not executed. SSH configuration
includes and `AuthorizedKeysFile`/`AuthorizedPrincipalsFile` tokens are considered;
`AuthorizedKeysCommand` is recorded without executing it. SSH `Match` conditions
are not evaluated, so configured key paths can be considered for multiple accounts.
LDAP-only homes, arbitrary scripting and remote key/log sources may need paths
provided by the investigator.
Configuration discovery is automatic for `linux_dfir`. Use `--discover-config`
to enable it for a custom profile or `--no-config-discovery` to disable it.

Symlink parents are refused, including during home discovery and file selection.
Leaf links and special files are recorded as metadata. Add an intended target
explicitly when its contents are required. Custom `/proc`, `/sys` and `/dev` trees
are excluded; the snapshot artifact supplies selected live queries instead.
Repeated directory inodes are recorded and not traversed again, preventing
recursive bind-mount aliases from causing an endless walk.

The profile excludes account password hashes and SSH private keys by default;
the host-private-key rule is enforced by the copier as well. Explicitly selecting
a sensitive file or an entire directory such as `/etc` or `.ssh` can include
credentials. Collected configuration and histories can also contain secrets.
Protect all collection output and publish only source code.

Live collection creates processes, reads files, and can change access times.
`O_NOATIME` is attempted for regular-file reads. Size/timestamp/inode checks detect
some source changes; this is not an atomic snapshot and cannot establish trust
in a compromised kernel or its tools. Pending history is not flushed, deleted
files are not recovered, and neither disk imaging nor RAM acquisition is included.

## Portable UAC and archive passwords

The native interface also supports ZIP:

```shell
./uac -p linux_dfir -f zip /mnt/evidence
./uac -p ir_triage -f zip --secrets-file /secure/uac-secrets.conf /mnt/evidence
./uac -p ir_triage -f zip --secrets-file /dev/fd/3 /mnt/evidence 3</secure/uac-secrets.conf
```

Secret input is literal `key=value`, for example `output_password=...`; supported
keys are listed by `./uac --help`. Keep the input private. Values are redacted from
invocation/verbose logs and never written as an acquisition-log password. Shell
tracing with configured secrets is rejected. The external native `zip` tool can
still expose its password argument to privileged process inspection; the secret
file avoids putting it in the shell invocation/history, not in that child process.
The Python launcher's ZIP format does not implement password encryption.

Native UAC now defaults to SHA-256. Use `-H` for acquired-file hashes, or a custom
UAC configuration to add MD5/SHA-1 compatibility hashes. The original native
file-list workflow retains its historical line-oriented filename limits; use
`dfir.py` for the Linux NUL-delimited selection/copy/archive path.
