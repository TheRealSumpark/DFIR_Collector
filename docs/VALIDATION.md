# Local validation

Validated on 2026-11-20 with Linux and Python 3.13.11.

| Check | Result |
| --- | --- |
| Complete fork regression suite | 43 tests passed. |
| Portable helper tests | 17 cases passed under `/bin/sh`, Bash and BusyBox sh. |
| Pinned upstream compatibility suite | 640 cases: 633 passed, 7 skipped, 986 assertions passed. |
| UAC artifact/profile validation | All 449 YAML definitions passed. |
| Shell syntax | All shell libraries and the entry point passed dash and Bash parsing. |
| Workflow YAML | Parsed locally; hosted execution is pending GitHub access. |
| Whitespace/patch checks | `git diff --check` passed. |

Coverage includes synthetic complete collections to ZIP, tar and tar.gz; raw file
hashes and archive sidecars; rotations/binary logs/histories/SSH/persistence;
custom paths/globs/path lists; source metadata/xattrs; sparse files; default
exclusions and explicit sensitive-source overrides; malicious quoting/newline
filenames; mounted-source symlinks; permission and source-replacement failures;
storage/output/time limits; child-process cleanup; and cancellation with partial
reports. The cancellation fixture executes only a synthetic sleeping query and
does not select host file artifacts.

The original upstream fixtures for five changed temp/log helper contracts are
replaced by fork regression tests. `tools/prepare_compat_tests.py` migrates one
pinned expectation that encoded backslash loss; functional tests instead evaluate
literal values across quoting contexts and confirm no injected command executes.
The upstream main-script suite, which selects live `/etc`, is not used here.

Re-run from this repository root:

```shell
python3 -m unittest discover -s tests -v
UAC_TEST_SHELL='/bin/bash' python3 -m unittest discover -s tests -p test_shell_fixes.py -v
UAC_TEST_SHELL='busybox sh' python3 -m unittest discover -s tests -p test_shell_fixes.py -v
```

GitHub Actions, other operating systems and a separate Python 3.9 installation
have not been exercised. ShellCheck was unavailable locally; shell syntax and
functional checks do not substitute for its analysis. Hosted workflows retain
the ShellCheck job and run regression/schema checks on the fork's source.
