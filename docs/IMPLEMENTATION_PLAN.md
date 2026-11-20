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
- [ ] Default to SHA-256 and provide verifiable acquired-file manifests and
  structured acquisition statuses, including partial results and source changes.
- [ ] Add a focused Linux profile, source coverage tracker and Python launcher
  with repeatable paths, path files, exclusions, dry run and mounted-source mode.
- [ ] Support directory, tar/tar.gz and ZIP output, preserving filenames and
  verifying archive contents; expose ZIP directly in the Python CLI.
- [ ] Enforce configurable command/output budgets and free-space checks, record
  large-log omissions, and offer explicit complete-log selection.
- [ ] Cover symlinks/evidence-root confinement, sparse files, unreadable sources,
  source mutation, configured homes/history/key paths and command cancellation.
- [ ] Update README, artifact tracker, review status and change notes; commit
  validated changes in reviewable groups with sign-offs.
- [ ] Create the public GitHub fork, push, and verify visibility and remote SHA.

Tests must use synthetic evidence. Cross-platform shell compatibility is checked
with available shells; remote CI and other operating systems are reported as
unverified unless actually executed. GitHub API connectivity currently blocks
publication but does not block local implementation.

## Linux launcher architecture

The next implementation layer keeps UAC's YAML catalog and shell orchestration.
The Python launcher will pass a private JSON request through a dedicated optional
Linux mode. The shell file collector will write NUL-delimited discovery results;
a Python helper will copy them using root-anchored descriptors, then add literal
custom paths from JSON. No investigator path is interpolated into a shell command.
Mounted mode skips live command collectors. The launcher will package the resulting
private directory with Python's tar/ZIP APIs so arbitrary Unix filenames survive
discovery, copying and archiving. Command execution will use a bounded Python
runner only in this optional mode; the ordinary portable shell workflow remains
available. A finalizer will emit source metadata, per-command/file outcomes and
SHA-256 verification files, and preserve partial evidence on failure.

Native helper regression coverage now includes 16 cases, including complete UAC
collections from synthetic mounted evidence to tar.gz and ZIP. The original 15
helper cases pass under dash, Bash and BusyBox sh. Upstream compatibility fixtures
with intentionally superseded temp/log/redaction contracts are replaced by the
fork tests; the external main-script suite is not run against this host's `/etc`.
