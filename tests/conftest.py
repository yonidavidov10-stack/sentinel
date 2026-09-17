"""
conftest.py — every test runs against a git with NO personal configuration.

WHY. On 2026-09-17 eighteen tests failed that had passed for days, and nothing
in them had changed. The owner's global git config had: `commit.gpgsign true`,
a passphrase-protected signing key, and — after a restart — an empty ssh agent.
Every `git commit` in a scratch repository tried to sign, could not, and
failed; `git rev-list --count` then returned nothing and the tests died on
`int('')`.

The suite was reading the developer's machine. A test that passes or fails
depending on whose laptop runs it is not testing the code, and CI — which has
no such config — would never have seen the failure at all. That is the same
lesson as the signing check itself, from the other side: the place a test runs
is part of the test.

So every test gets an empty HOME for git's purposes and no system or global
config. Tests that need an identity set it on their own repository, which they
already do.
"""

from __future__ import annotations

import pytest


# Variables that tell code it is running in CI. Cleared for every test, so a
# test's verdict does not depend on WHERE the suite happens to run.
#
# Added the same day as the git isolation, and for the same reason one layer
# out: `test_an_unplugged_drive_is_unknown_not_a_failure` passed on the laptop
# and failed in CI, because the backup check had just learned to answer SKIP
# when GITHUB_ACTIONS=true. A test that wants CI behaviour sets it itself.
_CI_ENV = ("GITHUB_ACTIONS", "CI", "GITHUB_WORKFLOW", "GITHUB_RUN_ID",
           "RUNNER_TEMP")


@pytest.fixture(autouse=True)
def _isolated_git_config(tmp_path_factory, monkeypatch):
    for name in _CI_ENV:
        monkeypatch.delenv(name, raising=False)
    home = tmp_path_factory.mktemp("git-home")
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(home / ".gitconfig"))
    # Identity for any test that forgets to set one on its own repo; never the
    # owner's address, so nothing a test creates can be mistaken for theirs.
    (home / ".gitconfig").write_text(
        "[user]\n\tname = sentinel test\n\temail = test@example.invalid\n"
        "[init]\n\tdefaultBranch = main\n"
        "[commit]\n\tgpgsign = false\n",
        encoding="utf-8")
