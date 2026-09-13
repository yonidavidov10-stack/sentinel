"""
test_security_foundation.py
---------------------------
The first three checks of the security model in SECURITY.md, which separates
two threats that need different machinery:

  1. someone else gets in    -> pinned actions, no shell injection
  2. we destroy it ourselves -> what cannot be recreated has a second copy

The second is the larger threat for these projects and the one with evidence.
In four days of careful work, with a suite and an auditor running twice a day:
two delivered messages lost while the run reported success, a config table
deleted by a script nobody told to delete it, and two checks that passed for
months while testing nothing. None was an attack.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.checks import security          # noqa: E402
from sentinel.manifest import Manifest        # noqa: E402
from sentinel.verdict import Severity, Verdict  # noqa: E402


def _project(tmp_path, workflow: str | None = None, sec: dict | None = None):
    if workflow is not None:
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True, exist_ok=True)
        (wf / "w.yml").write_text(workflow, encoding="utf-8")
    return Manifest(path=tmp_path / "SENTINEL.toml", name="t", purpose="p",
                    security=sec or {})


def _one(fn, *args):
    out = []
    fn(*args, out)
    return out


# ── pinned actions ─────────────────────────────────────────────────────

SHA = "a" * 40


def test_every_action_pinned_to_a_sha_passes(tmp_path):
    f = _one(security._actions_are_pinned,
             _project(tmp_path, f"steps:\n  - uses: actions/checkout@{SHA}\n"))
    assert f[0].verdict is Verdict.PASS


def test_a_third_party_tag_is_the_high_severity_case(tmp_path):
    """A community action's tag can be repointed by its author at any commit,
    which then runs with contents: write and every secret in the job."""
    f = _one(security._actions_are_pinned,
             _project(tmp_path, "steps:\n  - uses: some-person/do-things@v3\n"))
    assert f[0].verdict is Verdict.WARN
    assert f[0].severity is Severity.HIGH
    assert "some-person/do-things@v3" in f[0].evidence
    assert "stops receiving security patches" in f[0].remedy, \
        "a finding that hides the cost of its own remedy is advocacy, not audit"


def test_a_first_party_tag_is_reported_at_low_severity(tmp_path):
    """Still a pointer, genuinely a smaller risk. Reporting it at the same
    severity as a community action would bury the one that matters."""
    f = _one(security._actions_are_pinned,
             _project(tmp_path, f"steps:\n  - uses: actions/checkout@v4\n"))
    assert f[0].verdict is Verdict.WARN
    assert f[0].severity is Severity.LOW


def test_a_third_party_tag_outranks_first_party_ones(tmp_path):
    f = _one(security._actions_are_pinned, _project(
        tmp_path,
        "steps:\n  - uses: actions/checkout@v4\n  - uses: rando/x@v1\n"))
    assert f[0].severity is Severity.HIGH
    assert "rando/x@v1" in f[0].evidence


def test_a_project_with_no_workflows_says_nothing(tmp_path):
    assert _one(security._actions_are_pinned, _project(tmp_path)) == []


# ── shell injection ────────────────────────────────────────────────────

def test_event_data_inside_a_run_block_is_critical(tmp_path):
    """The classic Actions RCE: a branch name becomes part of the command."""
    f = _one(security._no_untrusted_input_in_shell, _project(
        tmp_path,
        'steps:\n  - run: |\n      echo "${{ github.event.issue.title }}"\n'))
    assert f[0].verdict is Verdict.FAIL
    assert f[0].severity is Severity.CRITICAL
    assert "env:" in f[0].remedy


def test_head_ref_counts_too(tmp_path):
    f = _one(security._no_untrusted_input_in_shell, _project(
        tmp_path, 'steps:\n  - run: |\n      git checkout ${{ github.head_ref }}\n'))
    assert f[0].verdict is Verdict.FAIL


def test_the_same_value_passed_through_env_is_fine(tmp_path):
    """The actual fix, and it must not still be flagged — a check that cannot
    be satisfied gets disabled, and a disabled check looks like coverage."""
    f = _one(security._no_untrusted_input_in_shell, _project(
        tmp_path,
        'steps:\n  - env:\n      T: ${{ github.event.issue.title }}\n'
        '    run: |\n      echo "$T"\n'))
    assert f[0].verdict is Verdict.PASS


def test_safe_context_values_are_not_flagged(tmp_path):
    """github.run_id and friends are set by GitHub, not by a stranger.
    Flagging them would be the false positive that mutes the scanner."""
    f = _one(security._no_untrusted_input_in_shell, _project(
        tmp_path,
        'steps:\n  - run: |\n      echo "${{ github.run_id }} ${{ github.repository }}"\n'))
    assert f[0].verdict is Verdict.PASS


# ── what cannot be recreated ───────────────────────────────────────────

def test_saying_nothing_is_unknown_not_a_pass(tmp_path):
    """'Nobody said' is not 'nothing matters'. A project that never answered
    the question has not answered it."""
    f = _one(security._irreplaceable_has_a_second_copy, _project(tmp_path))
    assert f[0].verdict is Verdict.UNKNOWN
    assert f[0].verdict.is_actionable


def test_an_empty_list_is_a_real_answer(tmp_path):
    """'Everything here regenerates' is a legitimate and common answer. It
    must be sayable, or projects that are genuinely fine carry a permanent
    unknown and learn to ignore the section."""
    f = _one(security._irreplaceable_has_a_second_copy,
             _project(tmp_path, sec={"irreplaceable": [], "second_copy": "n/a"}))
    assert f[0].verdict is Verdict.UNKNOWN, \
        "an empty list with no paths is still 'not answered' today"


def test_declared_but_no_second_copy_warns_at_critical(tmp_path):
    """stock-predictor today: the prediction book exists in exactly one place,
    main cannot be branch-protected on a free private repo, and unattended
    workflows hold contents: write."""
    (tmp_path / "book.db").write_bytes(b"x")
    f = _one(security._irreplaceable_has_a_second_copy,
             _project(tmp_path, sec={"irreplaceable": ["book.db"]}))
    assert f[0].verdict is Verdict.WARN
    assert f[0].severity is Severity.CRITICAL
    assert "book.db" in f[0].evidence


def test_a_declared_second_copy_passes(tmp_path):
    (tmp_path / "book.db").write_bytes(b"x")
    f = _one(security._irreplaceable_has_a_second_copy, _project(
        tmp_path,
        sec={"irreplaceable": ["book.db"], "second_copy": "weekly to X"}))
    assert f[0].verdict is Verdict.PASS
    assert "weekly to X" in f[0].detail


def test_a_declared_path_that_is_gone_is_the_loudest_finding(tmp_path):
    """Worse than having no backup: the thing itself is missing, and the
    manifest says it was irreplaceable."""
    f = _one(security._irreplaceable_has_a_second_copy,
             _project(tmp_path, sec={"irreplaceable": ["book.db"],
                                     "second_copy": "weekly to X"}))
    assert f[0].verdict is Verdict.FAIL
    assert f[0].severity is Severity.CRITICAL
