# UAC review and proposed improvements

Reviewed [tclahr/uac](https://github.com/tclahr/uac) at
`db563110cb9d2d3a5ad8aa985c267205d45ce4da` (UAC 3.4.0).
Local checkout: this repository; branch: `review/linux-dfir-improvements`;
remote: `upstream=https://github.com/tclahr/uac.git`.

The user has approved a **public GitHub fork** named `DFIR_Collector`.
The local checkout is ready for development. An account-owned GitHub fork has
**not** been created: GitHub API access from this environment is unavailable.
Public visibility is authorized; no further visibility confirmation is needed.

## Implementation status

The first implementation group fixes tar fallback and compression failure handling,
literal file-list copying, private unique temporary workspaces, secret redaction
and secret-file/descriptor inputs. SHA-256 is now the default. Fork CI checks out
this repository and uses pinned compatibility fixtures. Native ZIP and tar.gz
collections are verified with synthetic mounted evidence. See
[the implementation tracker](IMPLEMENTATION_PLAN.md) for remaining work.

## Recommended direction

Use UAC's existing collection engine and artifact catalog as the foundation.
Add a focused Linux DFIR profile and a small Python launcher for simple custom-path
selection, preflight, and reporting. Keep changes in small commits so the fork
can be updated from upstream and suitable fixes can be proposed separately.

UAC already has shell histories (including some configured `HISTFILE` discovery),
SSH authorized keys/known hosts, raw journals, audit queries, cron/systemd evidence,
user-home discovery, mounted-source mode, custom artifact YAML, case information,
hash support, and remote transfer. These should be retained and tested. The
following proposals address observed behavior and the user's ease-of-use goals.

## First changes: evidence handling and correctness

| Priority | Finding | Evidence / verification | Suggested change and acceptance check |
| --- | --- | --- | --- |
| P1 | Passwords and transfer credentials can enter acquisition logs | [`uac:372`](https://github.com/tclahr/uac/blob/db563110cb9d2d3a5ad8aa985c267205d45ce4da/uac#L372) records the full invocation; [`create_acquisition_log.sh:55`](https://github.com/tclahr/uac/blob/db563110cb9d2d3a5ad8aa985c267205d45ce4da/lib/create_acquisition_log.sh#L55) writes the ZIP password. Isolated reproduction confirms a dummy password appears in the acquisition log. | Redact password, access-key, secret-key, token, presigned URL and SAS URL values before logging. Remove the password from the acquisition log. Offer prompt/file-descriptor inputs to reduce process-list exposure. Test that recognizable dummy secrets appear in neither logs nor reports. |
| P1 | Temporary evidence permissions and names depend on the caller | [`init_temp_data_dir.sh:13`](https://github.com/tclahr/uac/blob/db563110cb9d2d3a5ad8aa985c267205d45ce4da/lib/init_temp_data_dir.sh#L13) removes/reuses a predictable `uac-data.tmp` path; it creates files without setting a private umask. Under umask `022`, reproduction produces directory `0755` and log `0644`. Actual accessibility also depends on ancestor permissions. | Set umask `077` before creating evidence. Allocate a unique private temporary directory per run; refuse symlink destinations. Preserve failed-run evidence explicitly and test two concurrent runs targeting the same output parent. |
| P1 | The Linux/ESXi tar fallback assigns the wrong variable | [`tar_data.sh:30`](https://github.com/tclahr/uac/blob/db563110cb9d2d3a5ad8aa985c267205d45ce4da/lib/tar_data.sh#L30) assigns `__tg_tar_command`, while the function executes `__td_tar_command`. With the no-file-list-support flag set, the isolated helper still calls tar with `-T`. | Correct the variable and exercise this fallback with a tar stub rejecting `-T`. Include dotfiles and option-like filenames in the archive test. |
| P1 | Legal filenames can be lost in file-list copying | [`copy_data.sh:21`](https://github.com/tclahr/uac/blob/db563110cb9d2d3a5ad8aa985c267205d45ce4da/lib/copy_data.sh#L21) uses `read` without `IFS=` or `-r`. A dummy filename containing a backslash is not copied. Newline-delimited lists also cannot represent every Unix filename. | First preserve backslashes and whitespace with `IFS= read -r`, handling an unterminated final line. For Linux, add a NUL-delimited path through discovery/copy/archive. Keep capability-based fallbacks for other Unix variants and report unrepresentable filenames. |
| P1 | Unit-test checkout is hardcoded to upstream | [`unit-testing.yaml:25`](https://github.com/tclahr/uac/blob/db563110cb9d2d3a5ad8aa985c267205d45ce4da/.github/workflows/unit-testing.yaml#L25) checks out `tclahr/uac`. The workflow also references external test repositories. This is a source-inspection finding; GitHub Actions was not executed. | Use the current repository/PR checkout, with an intentional PR merge/head ref, so a fork's changes are tested. Pin external harness revisions and handle manual-dispatch refs. Prove that a deliberate failing change in a test branch makes CI fail. |

The logging observation includes the directly reproduced ZIP password case and a
source-derived inference for other secret command-line options; no real credentials
were used. These are review findings, not claims of exploitation or a complete
security audit.

## Next changes: the Linux collection experience

| Priority | Improvement | Current behavior / proposed acceptance criteria |
| --- | --- | --- |
| P2 | A `linux_dfir` profile and source coverage document | Base it on existing histories, SSH, `/var/log`, journals, audit, account/persistence/configuration and live-state artifacts. Document each source and exclusions. Mark heavy root-wide searches, process strings, image exports and memory acquisition as optional selections with visible runtime/storage implications. |
| P2 | Repeatable `--path` and `--paths-file` in a Python launcher | UAC's `-a` accepts artifact definitions, rather than directly accepting an arbitrary evidence path. Generate a private temporary file-collector YAML from literal paths/globs with safe quoting; use the existing engine for acquisition. Validate paths without shell interpolation and test spaces, quotes, backslashes, leading hyphens and mounted roots. |
| P2 | A structured manifest and meaningful completion status | Add per-artifact/file status, source path, destination, size, timestamps, hash, start/end time, command return code and error. [`run_command.sh`](https://github.com/tclahr/uac/blob/db563110cb9d2d3a5ad8aa985c267205d45ce4da/lib/run_command.sh) returns a code but logs command text; the main script finishes with `exit 0`. Aggregate acquisition gaps distinctly from missing optional tools/artifacts and intentional exclusions. |
| P2 | SHA-256 and explicit integrity verification | [`config/uac.conf:42`](https://github.com/tclahr/uac/blob/db563110cb9d2d3a5ad8aa985c267205d45ce4da/config/uac.conf#L42) defaults to MD5/SHA-1; SHA-256 is already supported. File-level hashing requires `-H`. The focused profile/launcher should enable SHA-256 and acquired-file manifests, retain compatibility hashes when needed, and document verification after transfer. |
| P2 | Command runtime/output budgets and storage preflight | The generic command runner directly evaluates the artifact command, without a general timeout/output ceiling in that helper. Add configurable per-command deadlines, process-group cleanup, byte budgets and free-space checks. Keep partial output and label it as incomplete. Capability-detect the timeout mechanism on non-Linux systems. |
| P2 | Explain large-log omissions and provide a complete-logs selection | The broad [`var_log.yaml`](https://github.com/tclahr/uac/blob/db563110cb9d2d3a5ad8aa985c267205d45ce4da/artifacts/files/logs/var_log.yaml#L9), `run_log.yaml` and advanced log search impose a 1 GiB per-file cap. Other artifacts can overlap this selection (e.g. persistent journal collection), so this is not a universal UAC limit. Report which large files were omitted and let an operator explicitly select unlimited or larger limits. |
| P2 | Optional bounded journal JSON export | Raw journal acquisition already exists. The live `journalctl` artifact currently lists boots. Add an optional JSON-lines export for convenient analysis while retaining raw journals, with clear limits and partial-export status. Do not change journal retention or flush services implicitly. |
| P2 | Snapshot and evidence-root regression tests | Add fixture tests for changing/truncated files, symlinked log directories, absolute links in mounted evidence, sparse login files, unreadable records, XDG/Zsh/custom histories and configured SSH key locations. Record unresolved sources instead of treating a successful archive as complete coverage. These are proposed tests, not all confirmed defects. |

## Verification performed

- Clone revision and version verified; UAC's help/version commands and main shell
  syntax check completed successfully.
- Four isolated helper reproductions confirmed the temporary permission behavior,
  cleartext dummy ZIP password, backslash filename copy failure and tar fallback.
  The original reproductions are preserved in commit `9d86bb9`. The current
  `python3 tools/review_uac.py` verifies corrected behavior.
- The baseline review was performed before implementation. The branch now includes
  the fixes and regression checks tracked above. No full live-host collection,
  remote upload, upstream issue, pull request or GitHub Actions run was performed.
- The separate Python collector prototype passed 22 fixture-based tests. Its
  checksums, manifests, safe path handling and bounded commands provide useful
  examples for a launcher/reporting layer; they are not UAC test results.

## Suggested delivery order

1. Fix tar fallback and file-list handling; add isolated regression tests.
2. Correct fork CI checkout, use private unique temp storage, and redact secrets.
3. Add SHA-256 defaults and structured acquisition outcomes.
4. Add the Linux profile, custom-path launcher and source coverage README.
5. Add command/storage budgets and the mounted-source/large-log regression suite.

For contributions upstream, follow UAC's contribution guide: discuss new features
in an issue first, target `develop`, use its commit conventions and sign off
commits. This review does not publish issues or PRs.
