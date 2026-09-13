"""
test_supply_chain.py
--------------------
Two gaps the security work had left, found on 2026-09-13 while writing up what
was finished.

1. DEPENDENCIES WERE UNPINNED. `yfinance>=1.6.0` tells CI to install whatever
   was published most recently, into a job holding the prediction book, the bot
   tokens, the archive deploy key and a Claude Code token. A package's install
   hooks run as that job. **This is the one risk here that needs no mistake on
   our part and no access to the account** — an upstream compromise anywhere in
   the transitive tree is enough.

2. THE CREDENTIAL SCANNER READ ONLY THE WORKING TREE. A token committed in
   June and deleted in July is absent from every file it examines and present
   in every clone, forever. Deleting a secret from a file does not delete it,
   and a working-tree scanner reports clean the whole time.

Both are tested by BREAKING a scratch repository, because this project has now
shipped three checks that passed while testing nothing, and every one was
caught the same way.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.checks import security                  # noqa: E402
from sentinel.manifest import Manifest                # noqa: E402
from sentinel.verdict import Severity, Verdict        # noqa: E402


def git(repo: Path, *args: str):
    return subprocess.run(("git",) + args, cwd=repo, text=True,
                          capture_output=True)


def _m(tmp_path, **sec):
    return Manifest(path=tmp_path / "SENTINEL.toml", name="t", purpose="p",
                    security=sec)


def _one(fn, m):
    out = []
    fn(m, out)
    assert out, "the check said nothing at all"
    return out[0]


# ── dependencies ───────────────────────────────────────────────────────

def test_pinned_requirements_pass(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# a comment\nyfinance==1.6.0\ntorch==2.13.0\n", encoding="utf-8")
    f = _one(security._dependencies_are_pinned, _m(tmp_path))
    assert f.verdict is Verdict.PASS
    assert "2 direct" in f.detail


def test_a_floor_is_not_a_version(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "yfinance>=1.6.0\ntorch==2.13.0\n", encoding="utf-8")
    f = _one(security._dependencies_are_pinned, _m(tmp_path))
    assert f.verdict is Verdict.WARN
    assert f.severity is Severity.HIGH
    assert "yfinance>=1.6.0" in f.evidence
    assert "torch" not in f.evidence


def test_a_bare_name_is_the_loosest_case_of_all(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests\n", encoding="utf-8")
    assert _one(security._dependencies_are_pinned,
                _m(tmp_path)).verdict is Verdict.WARN


def test_comments_and_flags_are_not_dependencies(tmp_path):
    """`# pyaudio  # OPTIONAL` and `--index-url` lines are not packages.
    Counting them would produce a finding the reader cannot act on."""
    (tmp_path / "requirements.txt").write_text(
        "--index-url https://example\n# pyaudio  # optional\nflask==3.1.3\n",
        encoding="utf-8")
    assert _one(security._dependencies_are_pinned,
                _m(tmp_path)).verdict is Verdict.PASS


def test_a_project_without_requirements_says_nothing(tmp_path):
    out = []
    security._dependencies_are_pinned(_m(tmp_path), out)
    assert out == []


# ── credentials in history ─────────────────────────────────────────────

@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "config", "user.email", "t@t")
    git(tmp_path, "config", "user.name", "t")
    (tmp_path / "README.md").write_text("hello", encoding="utf-8")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "first")
    return tmp_path


def _commit(repo, name, text, msg):
    (repo / name).write_text(text, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", msg)


def test_a_clean_history_passes(repo):
    _commit(repo, "a.py", "print('hello')", "ordinary work")
    assert _one(security._history_holds_no_credential,
                _m(repo)).verdict is Verdict.PASS


def test_a_token_committed_then_deleted_is_still_found(repo):
    """THE WHOLE POINT. The working tree is spotless and the repository is
    not — and every clone taken since already has it."""
    token = "ghp_" + "A" * 36
    _commit(repo, "config.py", f'TOKEN = "{token}"', "oops")
    _commit(repo, "config.py", "TOKEN = os.environ['TOKEN']", "remove the token")

    assert "ghp_" not in (repo / "config.py").read_text(encoding="utf-8"), \
        "fixture: the working tree must be clean, or this proves nothing"

    f = _one(security._history_holds_no_credential, _m(repo))
    assert f.verdict is Verdict.FAIL
    assert f.severity is Severity.CRITICAL
    assert "ROTATE THE CREDENTIAL FIRST" in f.remedy


def test_a_telegram_token_in_history_is_found(repo):
    _commit(repo, "bot.py", 'TOKEN = "8944261201:AA' + "x" * 32 + '"', "bot")
    assert _one(security._history_holds_no_credential,
                _m(repo)).verdict is Verdict.FAIL


def test_documentation_quoting_a_shape_can_be_allowed(repo):
    """The false positive that would get this check disabled: a file
    explaining what a token looks like. The allow-list matches on the COMMIT
    SUBJECT, so silencing one write does not silence the pattern."""
    _commit(repo, "SECURITY.md", "example: ghp_" + "A" * 36,
            "document the token shape")
    assert _one(security._history_holds_no_credential,
                _m(repo)).verdict is Verdict.FAIL
    assert _one(security._history_holds_no_credential,
                _m(repo, allow_patterns=["document the token shape"])
                ).verdict is Verdict.PASS


def test_the_depth_is_the_projects_to_set(repo):
    """A full history walk is slow enough to be run once and switched off.
    Recent history is where an accident is still cheap to fix."""
    token = "ghp_" + "B" * 36
    _commit(repo, "leak.py", f'T = "{token}"', "leak")
    for n in range(5):
        _commit(repo, f"f{n}.py", f"x = {n}", f"work {n}")
    assert _one(security._history_holds_no_credential,
                _m(repo, history_scan_commits=200)).verdict is Verdict.FAIL
    assert _one(security._history_holds_no_credential,
                _m(repo, history_scan_commits=3)).verdict is Verdict.PASS


def test_a_directory_that_is_not_a_repository_says_nothing(tmp_path):
    out = []
    security._history_holds_no_credential(_m(tmp_path), out)
    assert out == []


# ── a lock is a stronger answer than a pin, and must be seen as one ────

LOCKED = ("yfinance==1.6.0 \\\n    --hash=sha256:" + "a" * 64 + "\n"
          "pandas==3.0.5 \\\n    --hash=sha256:" + "b" * 64 + "\n")
ENFORCED = "jobs:\n  t:\n    steps:\n      - run: pip install --require-hashes -r requirements.lock\n"
NOT_ENFORCED = "jobs:\n  t:\n    steps:\n      - run: pip install -r requirements.txt\n"


def _locked_project(tmp_path, workflow: str):
    (tmp_path / "requirements.txt").write_text("yfinance==1.6.0\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text(LOCKED, encoding="utf-8")
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "ci.yml").write_text(workflow, encoding="utf-8")
    return _m(tmp_path)


def test_a_lock_that_ci_enforces_passes_and_counts_the_hashes(tmp_path):
    f = _one(security._dependencies_are_pinned, _locked_project(tmp_path, ENFORCED))
    assert f.verdict is Verdict.PASS
    assert "2 hashes" in f.detail
    assert "refused rather than trusted" in f.detail


def test_a_lock_nobody_installs_from_is_decoration(tmp_path):
    """THE SAME SHAPE AS A HISTORY LEDGER NOTHING ADVANCES: the artefact
    exists, looks right, and protects nothing. Generating a lock and then
    installing from requirements.txt is the most plausible way this goes
    wrong, because everything in the diff looks like progress."""
    f = _one(security._dependencies_are_pinned,
             _locked_project(tmp_path, NOT_ENFORCED))
    assert f.verdict is Verdict.WARN
    assert "not being enforced" in f.detail
    assert "--require-hashes" in f.remedy


def test_a_lock_without_hashes_does_not_count_as_one(tmp_path):
    """`pip freeze > requirements.lock` produces a file with the right name
    and none of the protection. The name is not the property."""
    (tmp_path / "requirements.txt").write_text("yfinance>=1.6.0\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text("yfinance==1.6.0\n", encoding="utf-8")
    f = _one(security._dependencies_are_pinned, _m(tmp_path))
    assert f.verdict is Verdict.WARN
    assert "yfinance>=1.6.0" in f.evidence


def test_pinning_without_a_lock_still_passes(tmp_path):
    """Pinned is a real improvement over floors and must not be graded as a
    failure for falling short of hashes — a check that only accepts the best
    available answer gets switched off by everyone who cannot reach it yet."""
    (tmp_path / "requirements.txt").write_text(
        "yfinance==1.6.0\ntorch==2.13.0\n", encoding="utf-8")
    assert _one(security._dependencies_are_pinned,
                _m(tmp_path)).verdict is Verdict.PASS
