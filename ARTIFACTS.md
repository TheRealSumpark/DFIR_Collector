# Linux DFIR source and functionality tracker

Implemented in the `linux_dfir` profile and `dfir.py` backend. Representative
sources are checked with synthetic evidence; actual availability depends on the
host, distribution, configuration and permissions. Every row describes a selected
scope, not an assertion that absent evidence proves no activity occurred.

| Source / utility | What is collected | Implementation / limits |
| --- | --- | --- |
| `/var/log` | Authentication/SSH/sudo logs, syslog/messages, kernel, audit, cron, firewall, package, mail and application logs; rotations and compressed files; binary login records | UAC log artifacts, copied as raw bytes. Default file cap 1 GiB; `--complete-logs` removes it for selected log trees. |
| `/run/log`, journals | Volatile logs and raw persistent/runtime systemd journals | Raw files through file collectors; an optional live journal JSON-lines query is in the focused snapshot and uses command limits. |
| Histories in `/root`, `/home/*`, passwd-listed service/nonstandard homes | Bash, Zsh, Fish and other UAC shell histories, startup files, Python/database histories, editor/pager/download traces | Existing shell/application artifacts plus additions; recognized literal configured history/XDG/Zsh paths are discovered without executing shell startup files. |
| User `.ssh` and `/etc/ssh` | Authorized keys/principals, known hosts, public keys, access/client/server configuration and SSH rc files | Existing SSH artifacts plus access configuration additions. Configured key paths/includes are considered. Private keys require explicit custom selection. |
| `/etc`, accounts and logging configuration | User/group/account context, sudo/PAM, audit rules, logging/rotation configuration, host/network/service configuration | Native `/etc` artifact predicates are retained; password hash databases are excluded by default. Explicit custom directory selections can include them. |
| Cron/anacron/at | System cron schedules, user spool files and job queues, startup schedules | Job-scheduler artifact plus additional Debian/RHEL-style cron/anacron/at paths. |
| systemd/init/login persistence | System/user services, timers, transient units, init/startup/profile files, autostart, dynamic-loader configuration, udev | Existing system artifacts plus targeted additions. Linked unit files are metadata-only; select their targets explicitly if needed. |
| Network and OS/package context | NetworkManager and `/etc` network/firewall configuration, hosts/resolver/OS identity, installed package databases and repository configuration | Existing package/system artifacts. Linked resolver/OS files are not followed automatically; known real OS-release paths are also selected. |
| Docker/Kubernetes | Docker JSON log rotations and container configuration; pod/container log locations | Host filesystem sources only. No image commit/export, daemon mutation or volume-wide acquisition. |
| Live process/network/session state | Process command lines, sockets, addresses, routes/neighbors, open files, sessions, uptime, kernel, mounts/modules, services/timers, audit and firewall state | Independent read-only queries in `live_response/dfir/snapshot.yaml`, before file copying. Missing tools/conditions and bounded/failed commands are recorded. Disabled on mounted sources. |
| `--path`, `--paths-file` | Investigator-selected files, directories and component globs | JSON transport; root-anchored discovery/copy; same metadata/hash/error handling. Repeated paths deduplicate with provenance categories. |
| Output/integrity | Directory, tar, tar.gz, ZIP; per-file and per-query outcomes, source metadata, case/operator/timing, SHA-256 and archive sidecars | Private storage, optional caps/reserve, partial-evidence retention and verification commands in the launcher guide. |

Source symlinks, devices, sockets and FIFOs are metadata-only when selected.
Unselected special files excluded by artifact type predicates are not individually
acquired. Custom kernel pseudo-filesystem trees are excluded. Collection output
and current staging/control paths are excluded from file copying.

Additional custom application logs, nonstandard homes, remote stores, pending
interactive history and dynamic configuration cannot all be inferred from a static
profile. The manifest and query reports distinguish omissions, unresolved settings,
intentional policy skips and acquisition errors. See
[the launcher guide](docs/LINUX_DFIR.md) for full boundaries and verification.
