# Linux DFIR improvement goal

Implement the proposals in [DFIR_IMPROVEMENTS.md](DFIR_IMPROVEMENTS.md) while
retaining UAC's portable shell workflow. Public publication as `DFIR_Collector`
is authorized. ZIP output is an explicit user requirement.

## Work and acceptance checks

- [x] Fix tar fallback and compression error propagation; preserve dotfiles and
  filenames containing whitespace/backslashes; test archive contents and failures.
- [x] Reserve a unique private evidence workspace; never delete another run;
  retain partial evidence on interruption/failure; test concurrent reservations.
- [x] Remove secrets from invocation, verbose and acquisition logs; provide
  secret-file/descriptor input and prevent shell tracing with secrets.
- [x] Test the fork's own checkout in CI, pin external test harness revisions,
  and fail validation workflows on any invalid artifact/profile.
- [x] Default to SHA-256 and provide verifiable acquired-file manifests and
  structured acquisition statuses, including partial results and source changes.
- [x] Add a focused Linux profile, source coverage tracker and Python launcher
  with repeatable paths, path files, exclusions, dry run and mounted-source mode.
- [x] Support directory, tar/tar.gz and ZIP output, preserving filenames and
  verifying archive contents; expose ZIP directly in the Python CLI.
- [x] Enforce configurable command/output budgets and free-space checks, record
  large-log omissions, and offer explicit complete-log selection.
- [x] Cover symlinks/evidence-root confinement, sparse files, unreadable sources,
  source mutation, configured homes/history/key paths and command cancellation.
- [x] Update README, artifact tracker, review status and change notes; commit
  validated changes in reviewable groups with sign-offs.
- [ ] Create the public GitHub fork, push, and verify visibility and remote SHA.

Tests must use synthetic evidence. Cross-platform shell compatibility is checked
with available shells; remote CI and other operating systems are reported as
unverified unless actually executed. GitHub API connectivity currently blocks
publication but does not block local implementation.

## Linux launcher architecture

The implementation keeps UAC's YAML catalog and shell orchestration. `dfir.py`
passes a private JSON request through an optional Linux backend. That backend
applies file-collector rules using root-anchored descriptors, writes NUL-delimited
discovery records, copies files safely, and adds explicit paths from JSON. No
investigator path is interpolated into a shell command. Home/configuration
discovery uses the same confinement. Mounted mode skips live command collectors.

The launcher packages private output using Python's tar/ZIP APIs. ZIP's filename
encoding limitations fail explicitly and preserve the evidence directory. A
bounded Python runner records query outcomes and stops process groups at limits.
The ordinary portable shell workflow remains available. Final reports include
source metadata, per-file/query outcomes, definition hashes and SHA-256 verification.
Failure/cancellation retain partial bytes with a recovery report where possible.

Native helper cases are exercised under dash, Bash and BusyBox sh. The complete
fork suite additionally covers the Python backend and mounted-source launcher.
The pinned upstream compatibility suite runs 640 cases: 633 passed and 7 skipped.
Five test files with intentionally superseded temp/log contracts are replaced by
fork fixtures. One pinned string expectation is migrated because it encoded the
previous backslash-loss bug; functional quoting tests verify literal values.
The external main-script suite is not run against this host's `/etc`.

All 449 artifact/profile YAML definitions passed UAC validation. Hosted GitHub CI
has not run because API access remains unavailable; other operating systems are
also unverified. Python 3.9 is the declared minimum; local execution used the
available Python interpreter rather than a separate Python 3.9 installation.

The final local suite has 43 passing tests. Detailed validation and the compatibility
fixture migration are recorded in [VALIDATION.md](VALIDATION.md). Local changes
are committed in signed-off groups; public fork creation/push is the remaining
goal item and will be retried when GitHub access is available.
