# DFIR skill installation and review

Requested upstream: [mukul975/anthropic-cybersecurity-skills](https://github.com/mukul975/anthropic-cybersecurity-skills).
Reviewed revision: `54a798831d2266a3ca61ce68a7acb80b81160d57`.

Seven packages were reviewed during development from the pinned revision above.
They were installed in the development workspace's `skills/` directory using the
Codex skill installer's local-clone workflow. Their contents are reference
material; this fork does not vendor or execute their scripts, and the collector
has no runtime dependency on them.

| Skill (upstream `skills/<name>/SKILL.md`) | Findings applied to this collector |
| --- | --- |
| `analyzing-linux-system-artifacts` | Root/user histories, SSH trust/access, account and sudo configuration, cron/systemd, login records and source timestamps form the baseline. |
| `performing-linux-log-forensics-investigation` | Preserve text logs and rotations, binary session databases, audit data and raw journals; export structured journal data without limiting collection to SSH events. |
| `analyzing-linux-audit-logs-for-intrusion` | Preserve audit configuration/rules and raw records, capture `auditctl -s` and `auditctl -l`. Do not deploy rules, reload auditd, or generate test events. |
| `analyzing-persistence-mechanisms-in-linux` | Add user systemd units, login profiles, loader preload files, cron/anacron and startup mechanisms. Collect content without assigning speculative risk scores. |
| `collecting-volatile-evidence-from-compromised-host` | Capture network/process/session/runtime state before lengthy file copying; document UTC times, operator, case ID, hashes and acquisition limitations. RAM acquisition requires a separate trusted workflow. |
| `analyzing-web-server-logs-for-intrusion` | Preserve Apache/Nginx and other application logs under `/var/log` as bytes; use custom paths for logs under `/srv`, `/opt`, custom vhosts or remote destinations. No GeoIP downloads or detection dependencies in acquisition. |
| `analyzing-docker-container-forensics` | Include Docker container JSON logs, metadata/configuration and Kubernetes log locations; do not commit images, execute inside containers, or collect entire volumes implicitly. |

## Review conclusions

The skills are reference procedures, not executable requirements. Some examples
change the host (installing scanners, altering audit rules, `docker commit`, or
reloading services). Those actions are inappropriate defaults for this collector.
No downloaded skill scripts are executed by the collector, and no third-party code
is required at runtime. Integrity hashes describe the acquired bytes; acquisition
metadata starts a handling record but does not establish a complete chain of custody.

The artifact inventory also checks primary [systemd documentation](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html),
[OpenSSH configuration](https://man.openbsd.org/sshd_config), and
[Bash history documentation](https://www.gnu.org/software/bash/manual/html_node/Bash-History-Facilities.html).
These explain raw/volatile journal storage, configurable key sources, and unflushed
history limitations that a static path list cannot fully resolve.
