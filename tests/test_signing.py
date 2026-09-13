"""
test_signing.py
---------------
`_owner_commits_are_signed`.

The value is narrow and worth stating exactly: anyone with write access can
author a commit under any name, because `git commit --author` takes a string
and nothing verifies it. A signature is what makes that forgery visible.

The exemption is by ADDRESS, and building this check exposed why that matters.
Every workflow was committing as "sentinel audit bot" — with the OWNER'S email
address. So every automated commit was already indistinguishable from a human
one forged with --author, which is precisely what signing exists to expose.
The bots now use noreply.github.com addresses. These tests pin both halves:
that bots are exempt, and that the owner's address is not.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.checks import security                  # noqa: E402
from sentinel.manifest import Manifest                # noqa: E402
from sentinel.verdict import Verdict                  # noqa: E402

OWNER = "owner@example.com"
BOT = "audit-bot@users.noreply.github.com"


def git(repo: Path, *args: str):
    return subprocess.run(("git",) + args, cwd=repo, text=True,
                          capture_output=True)


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "config", "user.email", OWNER)
    git(tmp_path, "config", "user.name", "Owner")
    git(tmp_path, "config", "commit.gpgsign", "false")
    return tmp_path


def _commit(repo, msg, email=OWNER, name="Owner"):
    (repo / msg.replace(" ", "_")).write_text("x", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "-c", f"user.email={email}", "-c", f"user.name={name}",
        "commit", "-q", "-m", msg)


def _m(repo, **sec):
    return Manifest(path=repo / "SENTINEL.toml", name="t", purpose="p",
                    security={"owner_email": OWNER, **sec})


def _one(m):
    out = []
    security._owner_commits_are_signed(m, out)
    assert out
    return out[0]


def test_unsigned_owner_commits_are_reported(repo):
    _commit(repo, "one")
    _commit(repo, "two")
    f = _one(_m(repo))
    assert f.verdict is Verdict.WARN
    assert "2 of the last" in f.detail
    assert "indistinguishable from a forgery" in f.detail


def test_bot_commits_are_exempt(repo):
    """CI runners hold no key. Without this the check fires on every scheduled
    run forever, and a check that fires forever gets switched off."""
    _commit(repo, "bot work", email=BOT, name="audit bot")
    _commit(repo, "more bot work", email=BOT, name="audit bot")
    f = _one(_m(repo))
    assert f.verdict is Verdict.PASS
    assert "none of the last" in f.detail


def test_a_bot_name_with_the_owners_address_is_still_reported(repo):
    """THE CASE THIS CHECK WAS BUILT ON, and the reason the exemption keys on
    the address rather than the name. Every workflow used to commit as
    'sentinel audit bot' with the owner's email — so the name said bot, the
    address said human, and nothing could tell that apart from a forgery.

    Exempting by NAME would have hidden exactly the attack: call yourself
    'audit bot', use the owner's address, and be waved through."""
    _commit(repo, "wearing the owners address", email=OWNER,
            name="sentinel audit bot")
    f = _one(_m(repo))
    assert f.verdict is Verdict.WARN
    assert "wearing the owners address" in f.evidence


def test_a_forged_commit_under_the_owners_address_is_caught(repo):
    _commit(repo, "bot work", email=BOT, name="audit bot")
    _commit(repo, "looks like the owner", email=OWNER, name="Owner")
    f = _one(_m(repo))
    assert f.verdict is Verdict.WARN
    assert "looks like the owner" in f.evidence
    assert "bot work" not in f.evidence


def test_the_window_is_configurable_so_old_history_ages_out(repo):
    """Commits made before signing existed cannot be signed retroactively. If
    the window were all of history the check could never pass, and one that can
    never pass gets turned off rather than fixed."""
    for n in range(5):
        _commit(repo, f"old {n}")
    assert _one(_m(repo, signing_lookback=5)).verdict is Verdict.WARN
    assert "2 of the last 2" in _one(_m(repo, signing_lookback=2)).detail


def test_no_declared_owner_means_no_finding(repo):
    _commit(repo, "one")
    out = []
    security._owner_commits_are_signed(
        Manifest(path=repo / "SENTINEL.toml", name="t", purpose="p"), out)
    assert out == []


def test_the_remedy_names_the_trap_that_wastes_an_hour(repo):
    """GitHub keeps authentication keys and signing keys in separate lists.
    Uploading to the wrong one leaves every commit Unverified with no hint."""
    _commit(repo, "one")
    assert "SIGNING key" in _one(_m(repo)).remedy


def test_a_directory_that_is_not_a_repository_says_nothing(tmp_path):
    out = []
    security._owner_commits_are_signed(_m(tmp_path), out)
    assert out == []
