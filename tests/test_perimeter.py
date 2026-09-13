"""
test_perimeter.py
-----------------
Two settings that are not in the source, and therefore cannot be reviewed by
reading it.

1. A workflow with no `permissions:` block inherits a repository-wide default.
   Three workflows here did — two `tests.yml` and a `smoke.yml` — so a job that
   only runs tests may have held the right to rewrite the code it was testing.
   Nothing in any diff would have shown it, and a change to that repository
   setting silently re-permissions every workflow that never declared.

2. A private repository made public by accident is silent and total. Nothing
   breaks, no test fails, no workflow turns red; the code, the full history and
   every secret ever committed simply become readable. The first sign is
   usually somebody else finding them.

Both are tested in both directions. The asymmetry in (2) is deliberate and
pinned: declared private and actually public is CRITICAL, the reverse is a
warning — one exposes everything, the other inconveniences a collaborator.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.checks import security                  # noqa: E402
from sentinel.manifest import Manifest                # noqa: E402
from sentinel.verdict import Severity, Verdict        # noqa: E402


def _project(tmp_path, workflows: dict[str, str] | None = None, **sec):
    if workflows:
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True, exist_ok=True)
        for name, text in workflows.items():
            (wf / name).write_text(text, encoding="utf-8")
    return Manifest(path=tmp_path / "SENTINEL.toml", name="t", purpose="p",
                    security=sec)


def _one(fn, m):
    out = []
    fn(m, out)
    assert out, "the check said nothing at all"
    return out[0]


DECLARED = "permissions:\n  contents: read\njobs:\n  t:\n    steps: []\n"
SILENT = "jobs:\n  t:\n    steps: []\n"


# ── workflow permissions ───────────────────────────────────────────────

def test_declared_permissions_pass(tmp_path):
    f = _one(security._workflow_permissions_are_declared,
             _project(tmp_path, {"a.yml": DECLARED, "b.yml": DECLARED}))
    assert f.verdict is Verdict.PASS
    assert "all 2" in f.detail


def test_a_silent_workflow_is_named(tmp_path):
    f = _one(security._workflow_permissions_are_declared,
             _project(tmp_path, {"good.yml": DECLARED, "silent.yml": SILENT}))
    assert f.verdict is Verdict.WARN
    assert f.severity is Severity.HIGH
    assert "silent.yml" in f.evidence
    assert "good.yml" not in f.evidence


def test_write_all_is_critical_and_outranks_a_silent_one(tmp_path):
    """`write-all` is the inherited default made explicit, and no better for
    being written down. It must not be softened by sitting beside a workflow
    that merely forgot to declare."""
    f = _one(security._workflow_permissions_are_declared,
             _project(tmp_path, {"bad.yml": "permissions: write-all\njobs:\n  t:\n    steps: []\n",
                                 "silent.yml": SILENT}))
    assert f.verdict is Verdict.FAIL
    assert f.severity is Severity.CRITICAL
    assert "bad.yml" in f.evidence


def test_pull_request_target_is_critical(tmp_path):
    """It runs with this repository's secrets against code from a fork. With a
    checkout of the pull request's head it is the best-known way to hand an
    attacker a repository's secrets."""
    wf = ("on:\n  pull_request_target:\n    types: [opened]\n"
          "permissions:\n  contents: read\njobs:\n  t:\n    steps: []\n")
    f = _one(security._workflow_permissions_are_declared,
             _project(tmp_path, {"pr.yml": wf}))
    assert f.verdict is Verdict.FAIL
    assert "fork" in f.detail


def test_job_level_permissions_count_as_declared(tmp_path):
    """Tighter than workflow-level, not looser. Demanding a top-level block
    would fail correct configurations, and a check that fails correct code
    gets deleted."""
    wf = "jobs:\n  t:\n    permissions:\n      contents: read\n    steps: []\n"
    assert _one(security._workflow_permissions_are_declared,
                _project(tmp_path, {"a.yml": wf})).verdict is Verdict.PASS


def test_a_project_with_no_workflows_says_nothing(tmp_path):
    out = []
    security._workflow_permissions_are_declared(_project(tmp_path), out)
    assert out == []


# ── repository visibility ──────────────────────────────────────────────

class _R:
    def __init__(self, out, ok=True):
        self.ok, self.stdout, self.output, self.error = ok, out, out, ""


def _with_gh(monkeypatch, visibility, ok=True, present=True):
    monkeypatch.setattr(security, "which", lambda _: "/usr/bin/gh" if present else None)
    monkeypatch.setattr(security, "run", lambda *a, **k: _R(visibility, ok))


def test_agreement_passes(tmp_path, monkeypatch):
    _with_gh(monkeypatch, "PRIVATE")
    f = _one(security._visibility_matches_the_declaration,
             _project(tmp_path, visibility="private"))
    assert f.verdict is Verdict.PASS


def test_declared_private_and_actually_public_is_critical(tmp_path, monkeypatch):
    """The case this exists for, and the only one that loses everything at
    once."""
    _with_gh(monkeypatch, "PUBLIC")
    f = _one(security._visibility_matches_the_declaration,
             _project(tmp_path, visibility="private"))
    assert f.verdict is Verdict.FAIL
    assert f.severity is Severity.CRITICAL
    assert "every secret ever committed" in f.detail
    assert "rotate" in f.remedy.lower()


def test_declared_public_and_actually_private_is_only_medium(tmp_path, monkeypatch):
    """The reverse mismatch is a nuisance, not an exposure. Grading both the
    same would teach the reader that this line does not distinguish."""
    _with_gh(monkeypatch, "PRIVATE")
    f = _one(security._visibility_matches_the_declaration,
             _project(tmp_path, visibility="public"))
    assert f.verdict is Verdict.FAIL
    assert f.severity is Severity.MEDIUM


def test_no_declaration_means_no_finding(tmp_path, monkeypatch):
    out = []
    security._visibility_matches_the_declaration(_project(tmp_path), out)
    assert out == []


def test_a_nonsense_declaration_is_unknown_not_a_pass(tmp_path, monkeypatch):
    f = _one(security._visibility_matches_the_declaration,
             _project(tmp_path, visibility="sort of private"))
    assert f.verdict is Verdict.UNKNOWN


def test_gh_missing_is_unknown_not_a_pass(tmp_path, monkeypatch):
    _with_gh(monkeypatch, "", present=False)
    f = _one(security._visibility_matches_the_declaration,
             _project(tmp_path, visibility="private"))
    assert f.verdict is Verdict.UNKNOWN
    assert f.verdict.is_actionable


def test_gh_failing_is_unknown_not_a_pass(tmp_path, monkeypatch):
    """'I could not ask' must never read as 'it is private'."""
    _with_gh(monkeypatch, "", ok=False)
    assert _one(security._visibility_matches_the_declaration,
                _project(tmp_path, visibility="private")).verdict is Verdict.UNKNOWN


def test_the_security_check_survives_a_directory_that_is_not_a_repository(tmp_path):
    """THE ERROR PATH HAD NEVER RUN. Every project audited so far was a git
    repository, so the early return taken when `git ls-files` fails was dead
    code — and it read `t.seconds`, which the timer only sets on exiting its
    block. Auditing a bare directory crashed the whole security check with
    AttributeError instead of reporting the UNKNOWN it had just constructed.

    An unexercised error path is not a safety net. It is a second failure
    waiting for the first one."""
    from sentinel.checks import security as sec

    (tmp_path / "SENTINEL.toml").write_text(
        '[project]\nname = "t"\npurpose = "p"\n', encoding="utf-8")
    result = sec.check(Manifest(path=tmp_path / "SENTINEL.toml", name="t",
                                purpose="p"))
    assert result.findings, "it must report something, not crash"
    assert any(f.verdict is Verdict.UNKNOWN for f in result.findings)
