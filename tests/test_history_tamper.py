"""
test_history_tamper.py
----------------------
`_history_is_append_only` — the control that stands in for branch protection,
which GitHub refuses on a private repository on a free plan.

It serves both threats at once, which is why it was the first thing built for
the security programme: an intruder covering their tracks and an owner typing
`git push --force` on the wrong branch leave identical evidence — a commit that
used to be reachable from the branch no longer is.

Every case here REWRITES REAL HISTORY in a scratch repository. A tamper
detector that has only been watched not firing has not been tested, and this
file exists in a project that has now shipped three checks which passed while
testing nothing.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.checks import security                      # noqa: E402
from sentinel.checks.security import LEDGER               # noqa: E402
from sentinel.manifest import Manifest                    # noqa: E402
from sentinel.verdict import Severity, Verdict            # noqa: E402


def git(repo: Path, *args: str) -> str:
    return subprocess.run(("git",) + args, cwd=repo, text=True,
                          capture_output=True).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "config", "user.email", "t@t")
    git(tmp_path, "config", "user.name", "t")
    for n in range(3):
        (tmp_path / f"f{n}.txt").write_text(str(n), encoding="utf-8")
        git(tmp_path, "add", "-A")
        git(tmp_path, "commit", "-qm", f"c{n}")
    return tmp_path


def _m(repo):
    return Manifest(path=repo / "SENTINEL.toml", name="t", purpose="p")


def _record(repo):
    (repo / ".security").mkdir(exist_ok=True)
    (repo / LEDGER).write_text(json.dumps({
        "head": git(repo, "rev-parse", "HEAD"),
        "count": int(git(repo, "rev-list", "--count", "HEAD")),
    }), encoding="utf-8")


def _one(repo):
    out = []
    security._history_is_append_only(_m(repo), out)
    assert out, "the check said nothing at all"
    return out[0]


def test_no_ledger_is_unknown_not_a_pass(repo):
    """A first audit has nothing to compare against. Reporting PASS would
    claim a verification that never happened."""
    f = _one(repo)
    assert f.verdict is Verdict.UNKNOWN
    assert f.verdict.is_actionable


def test_ordinary_commits_pass(repo):
    _record(repo)
    (repo / "new.txt").write_text("x", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "ordinary work")
    f = _one(repo)
    assert f.verdict is Verdict.PASS
    assert "1 commit(s) added" in f.detail


def test_many_commits_still_pass(repo):
    _record(repo)
    for n in range(5):
        (repo / f"n{n}.txt").write_text("x", encoding="utf-8")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", f"more {n}")
    assert _one(repo).verdict is Verdict.PASS


def test_a_rewritten_commit_is_critical(repo):
    """`git commit --amend` after the ledger was written: the recorded commit
    is orphaned, which is exactly what a force-push leaves behind."""
    _record(repo)
    (repo / "f2.txt").write_text("changed", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--amend", "-m", "rewritten")
    f = _one(repo)
    assert f.verdict is Verdict.FAIL
    assert f.severity is Severity.CRITICAL
    assert "rewritten, not extended" in f.detail
    assert "reflog" in f.remedy, "the finding must name the recovery path"


def test_a_hard_reset_that_drops_commits_is_caught(repo):
    """The destructive shape: `reset --hard HEAD~2` then carry on. The branch
    still has commits and the count can even climb back, so counting alone
    would miss it — reachability is the question."""
    _record(repo)
    git(repo, "reset", "--hard", "-q", "HEAD~2")
    for n in range(4):
        (repo / f"r{n}.txt").write_text("x", encoding="utf-8")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", f"after reset {n}")
    assert int(git(repo, "rev-list", "--count", "HEAD")) > 3, \
        "fixture: the count must have climbed back, or this proves nothing"
    assert _one(repo).verdict is Verdict.FAIL


def test_a_vanished_commit_is_still_caught_and_says_so(repo):
    """After the old commit is garbage-collected there is nothing to compare
    against. `merge-base` then fails rather than answering 'no', and folding
    that into a pass would make the check useless at exactly the moment the
    evidence is gone."""
    _record(repo)
    (repo / LEDGER).write_text(json.dumps({"head": "0" * 40, "count": 3}),
                               encoding="utf-8")
    f = _one(repo)
    assert f.verdict is Verdict.FAIL
    assert "no longer exists" in f.detail


def test_an_unreadable_ledger_is_unknown(repo):
    (repo / ".security").mkdir(exist_ok=True)
    (repo / LEDGER).write_text("{not json", encoding="utf-8")
    f = _one(repo)
    assert f.verdict is Verdict.UNKNOWN
    assert "indistinguishable from a deleted one" in f.remedy


def test_a_directory_that_is_not_a_repository_says_nothing(tmp_path):
    out = []
    security._history_is_append_only(_m(tmp_path), out)
    assert out == []


# ── the hole found hours after the check was built ─────────────────────
#
# `sentinel record` existed and nothing called it, so the ledger sat nine
# commits behind in one repo and thirteen in the other. The check kept passing,
# and it was right to: the recorded commit was still an ancestor.
#
# But that is precisely the failure. Force-push away the last few commits and a
# marker from thirty commits back is STILL an ancestor — so the control covered
# an intruder rewriting a whole branch, and did not cover the accident that
# actually happens to people, which is a bad rebase of recent work.
#
# A tamper detector is only as current as its marker.

def _rewrite_recent(repo, keep_back=2):
    """Drop the last `keep_back` commits and build different ones."""
    git(repo, "reset", "--hard", "-q", f"HEAD~{keep_back}")
    for n in range(keep_back):
        (repo / f"replacement{n}.txt").write_text("x", encoding="utf-8")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", f"replacement {n}")


def _extend(repo, n=4):
    for i in range(n):
        (repo / f"later{i}.txt").write_text("x", encoding="utf-8")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", f"later {i}")


def test_a_stale_ledger_misses_a_recent_rewrite(repo):
    """Documents the hole, not the desired behaviour."""
    _record(repo)                    # marker at commit 3
    _extend(repo)                    # four more land on top
    _rewrite_recent(repo)
    assert _one(repo).verdict is Verdict.PASS, (
        "the old marker survives the rewrite, so a stale ledger cannot see it")


def test_a_current_ledger_catches_the_same_rewrite(repo):
    _extend(repo)
    _record(repo)                    # marker advanced to HEAD
    _rewrite_recent(repo)
    f = _one(repo)
    assert f.verdict is Verdict.FAIL
    assert "rewritten, not extended" in f.detail


def test_the_audit_workflows_advance_the_ledger():
    """A control nothing calls is a control that does not exist. Both audit
    workflows must run `sentinel record` AND commit what it writes, or the
    ledger ages and the check silently narrows to guarding ancient history."""
    here = Path(__file__).resolve().parent.parent
    checked = 0
    for wf in (here / ".github" / "workflows" / "audit.yml",
               here.parent / "שוק-ההון" / "stock-predictor"
               / ".github" / "workflows" / "audit.yml"):
        if not wf.is_file():
            continue                 # the sibling project is not always present
        text = wf.read_text(encoding="utf-8")
        assert "sentinel.cli record" in text, f"{wf.parent.parent.parent.name} never advances the ledger"
        assert ".security" in text, f"{wf.parent.parent.parent.name} records the ledger but never commits it"
        checked += 1
    assert checked, "no audit workflow was found to check"
