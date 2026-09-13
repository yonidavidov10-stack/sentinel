"""
test_regression_guards.py
-------------------------
Two checks written after making the mistakes they catch, on 2026-09-13.

1. A script meant to delete two expectations cut to the end of SENTINEL.toml
   and took the whole `[security]` table with it, including the allow-list
   that stops the credential scanner flagging documentation quoting a token
   shape. No test noticed — the tests do not read the manifest. The audit
   noticed only indirectly, because a different check flipped PASS to FAIL in
   the same run. That was luck.

2. Twelve .pyc files were tracked in this public repository. `.gitignore`
   listed `__pycache__/`, but it was added after they were committed and
   ignore rules do not untrack anything. The same sequence is how a `.env`
   gets published: committed before the rule exists, then hidden by it.

Both are tested by REPRODUCING THE MISTAKE in a scratch repository, because a
guard verified only against the state it wants has never been shown to fire.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.checks import health          # noqa: E402
from sentinel.manifest import load          # noqa: E402
from sentinel.verdict import Verdict        # noqa: E402

MANIFEST = '''[project]
name = "t"
purpose = "p"

[commands]
tests = "true"
min_tests = 1

[[expectations]]
id = "kept"
says = "a"
kind = "file_exists"
path = "README.md"

[[expectations]]
id = "doomed"
says = "b"
kind = "file_exists"
path = "README.md"

[security]
allow_patterns = ["example"]
'''


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(("git",) + args, cwd=repo, capture_output=True,
                          text=True).stdout


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@t")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "README.md").write_text("x", encoding="utf-8")
    (tmp_path / "SENTINEL.toml").write_text(MANIFEST, encoding="utf-8")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "first")
    return tmp_path


def _find(findings, needle):
    for f in findings:
        if needle in f.title:
            return f
    raise AssertionError(f"no finding matching {needle!r}")


# ── the manifest that lost a table ─────────────────────────────────────

def test_an_untouched_manifest_passes(repo):
    out = []
    health._manifest_shrank(load(repo), out)
    assert _find(out, "disappeared").verdict is Verdict.PASS


def test_a_deleted_expectation_is_named(repo):
    text = (repo / "SENTINEL.toml").read_text(encoding="utf-8")
    i = text.index('[[expectations]]\nid = "doomed"')
    (repo / "SENTINEL.toml").write_text(
        text[:i] + text[text.index("[security]"):], encoding="utf-8")
    out = []
    health._manifest_shrank(load(repo), out)
    f = _find(out, "disappeared")
    assert f.verdict is Verdict.WARN
    assert "doomed" in f.evidence
    assert "kept" not in f.evidence


def test_the_exact_mistake_a_whole_table_cut_away(repo):
    """Reproducing it: delete from the last expectation to end of file."""
    text = (repo / "SENTINEL.toml").read_text(encoding="utf-8")
    (repo / "SENTINEL.toml").write_text(
        text[:text.index('[[expectations]]\nid = "doomed"')], encoding="utf-8")
    out = []
    health._manifest_shrank(load(repo), out)
    f = _find(out, "disappeared")
    assert f.verdict is Verdict.WARN
    assert "doomed" in f.evidence
    assert "[security].allow_patterns" in f.evidence, \
        "the silently-deleted table is the part no test caught last time"


def test_adding_a_promise_is_not_a_shrink(repo):
    text = (repo / "SENTINEL.toml").read_text(encoding="utf-8")
    (repo / "SENTINEL.toml").write_text(
        text + '\n[[expectations]]\nid = "new"\nsays = "c"\nkind = "file_exists"\n'
               'path = "README.md"\n', encoding="utf-8")
    out = []
    health._manifest_shrank(load(repo), out)
    assert _find(out, "disappeared").verdict is Verdict.PASS


def test_a_long_manifest_is_compared_whole_not_clipped(repo):
    """The bug inside the first version of this check. `run()` elides the middle
    of long output by default, so a big manifest arrived as unparseable text
    that still looked like a manifest, and the check reported the committed
    file as unreadable rather than comparing it."""
    padding = "\n".join(f"# {'x' * 100}" for _ in range(200))
    (repo / "SENTINEL.toml").write_text(padding + "\n" + MANIFEST,
                                        encoding="utf-8")
    _git(repo, "commit", "-aqm", "big")
    out = []
    health._manifest_shrank(load(repo), out)
    f = _find(out, "disappeared")
    assert f.verdict is Verdict.PASS, \
        f"a large manifest must still compare, got {f.verdict}: {f.detail}"


# ── files the ignore rule cannot save ──────────────────────────────────

def test_a_clean_repo_passes(repo):
    out = []
    health._ignored_but_tracked(load(repo), out)
    assert _find(out, "ignore").verdict is Verdict.PASS


def test_a_file_tracked_before_the_ignore_rule_is_reported(repo):
    """The real sequence: commit first, add the rule after, see a clean
    `git status` and believe the file is protected."""
    (repo / "__pycache__").mkdir()
    (repo / "__pycache__" / "m.pyc").write_bytes(b"\x00\x01")
    _git(repo, "add", "-Af")
    _git(repo, "commit", "-qm", "oops")
    (repo / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "add the rule, too late")

    out = []
    health._ignored_but_tracked(load(repo), out)
    f = _find(out, "ignore")
    assert f.verdict is Verdict.WARN
    assert "m.pyc" in f.evidence
    assert ".env" in f.remedy, "the remedy must name why this class matters"


def test_an_ignored_file_that_was_never_committed_is_not_reported(repo):
    (repo / ".gitignore").write_text("secret.txt\n", encoding="utf-8")
    (repo / "secret.txt").write_text("s", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "rule only")
    out = []
    health._ignored_but_tracked(load(repo), out)
    assert _find(out, "ignore").verdict is Verdict.PASS


def test_a_directory_that_is_not_a_repository_says_nothing(tmp_path):
    (tmp_path / "SENTINEL.toml").write_text(MANIFEST, encoding="utf-8")
    out = []
    health._ignored_but_tracked(load(tmp_path), out)
    health._manifest_shrank(load(tmp_path), out)
    assert out == []


# ── the function that corrupted the input ──────────────────────────────

def test_run_elides_long_output_by_default(tmp_path):
    """Right for evidence in a report: a reader wants the ends, not four
    thousand lines of pytest in the middle."""
    from sentinel.checks.base import MAX_OUTPUT_CHARS, run

    n = MAX_OUTPUT_CHARS + 5000
    r = run(f"python3 -c \"print('x' * {n})\"", tmp_path, timeout_s=60)
    assert "elided" in r.stdout
    assert len(r.stdout) < n


def test_run_returns_everything_when_asked_not_to_clip(tmp_path):
    """And wrong for reading data. Silently truncated text that still looks
    like text is the worst kind of corrupt input: every layer downstream
    behaves plausibly, and the eventual error names the wrong cause."""
    from sentinel.checks.base import MAX_OUTPUT_CHARS, run

    n = MAX_OUTPUT_CHARS + 5000
    r = run(f"python3 -c \"print('x' * {n})\"", tmp_path, timeout_s=60,
            clip=False)
    assert "elided" not in r.stdout
    assert len(r.stdout.strip()) == n
