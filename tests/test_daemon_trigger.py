"""
test_daemon_trigger.py
----------------------
When should a self-improvement pass be woken?

THE COMPLAINT THIS ANSWERS, in the owner's words: "it still only sends messages
and does not fix the problems." They were right, and the cause was one line —
the audit workflow summoned the daemon on `exit == 1`, a promise BROKEN. Every
UNKNOWN and every WARN exits 2 and woke nobody. A finding could be reported
every morning for a week while the one thing able to act on it was never told.

Three rules, and the third is the one that keeps this from being worse than
the bug:

  a FAIL              -> act now. A promise the project makes and no longer
                         keeps is the strongest signal available.
  a RECURRING unknown -> act. One "could not check" is information; five
                         mornings of the same one means nobody has made it
                         checkable, and that is squarely daemon work. A WARN
                         never qualifies — `history.recurring` counts FAIL and
                         UNKNOWN only, because a recurring warning is usually a
                         deliberate "not now".
  needs_owner         -> NEVER. Rotating a credential, plugging in a drive,
                         editing a workflow the pass may not touch. Waking it
                         for work it is forbidden to do turns a fixing loop
                         into an expensive reporting loop.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.manifest import Manifest                    # noqa: E402
from sentinel.report import Audit, daemon_should_act      # noqa: E402
from sentinel.verdict import CheckResult, Finding, Severity, Verdict  # noqa: E402


def _audit(tmp_path, *findings) -> Audit:
    m = Manifest(path=tmp_path / "SENTINEL.toml", name="t", purpose="p")
    return Audit(manifest=m,
                 results=[CheckResult(name="t", findings=list(findings))])


def _f(verdict, title="something", needs_owner=False, check="c"):
    return Finding(check=check, title=title, verdict=verdict,
                   severity=Severity.HIGH, detail="d", evidence="e",
                   needs_owner=needs_owner)


def test_a_broken_promise_wakes_it(tmp_path):
    assert daemon_should_act(_audit(tmp_path, _f(Verdict.FAIL))) is True


def test_a_clean_audit_does_not(tmp_path):
    assert daemon_should_act(_audit(tmp_path, _f(Verdict.PASS))) is False


def test_a_single_warning_does_not(tmp_path):
    """One report is information. Waking a pass for every warning would run it
    daily on things nobody has decided are problems yet."""
    assert daemon_should_act(_audit(tmp_path, _f(Verdict.WARN))) is False


def test_a_single_unknown_does_not(tmp_path):
    assert daemon_should_act(_audit(tmp_path, _f(Verdict.UNKNOWN))) is False


def test_a_failure_the_pass_cannot_touch_does_not_wake_it(tmp_path):
    """THE RULE THAT KEEPS THIS HONEST. A credential to rotate or a workflow to
    edit is a FAIL the daemon is structurally forbidden to fix — it would look,
    find nothing it may touch, and burn a run. The message says 'waiting for
    you' instead."""
    assert daemon_should_act(
        _audit(tmp_path, _f(Verdict.FAIL, needs_owner=True))) is False


def test_a_fixable_failure_beside_an_owner_one_still_wakes_it(tmp_path):
    assert daemon_should_act(_audit(
        tmp_path,
        _f(Verdict.FAIL, title="owner's", needs_owner=True),
        _f(Verdict.FAIL, title="the pass can fix this"))) is True


def test_a_recurring_unknown_wakes_it(tmp_path):
    """Five mornings of the same "could not check" is not five pieces of
    information. Nobody has made it checkable, and that is daemon work."""
    hist = tmp_path / ".audit-history"
    hist.mkdir()
    for n in range(6):
        (hist / f"2026-09-{n + 1:02d}.json").write_text(json.dumps({
            "sent": True,
            "findings": [{"check": "c", "title": "something",
                          "verdict": "unknown"}],
        }), encoding="utf-8")
    assert daemon_should_act(_audit(tmp_path, _f(Verdict.UNKNOWN))) is True


def test_a_recurring_unknown_the_pass_cannot_touch_still_does_not(tmp_path):
    """Recurrence does not grant the daemon new powers. A drive unplugged for
    a week recurs every single day and no pass can plug it in."""
    hist = tmp_path / ".audit-history"
    hist.mkdir()
    for n in range(6):
        (hist / f"2026-09-{n + 1:02d}.json").write_text(json.dumps({
            "sent": True,
            "findings": [{"check": "c", "title": "something",
                          "verdict": "unknown"}],
        }), encoding="utf-8")
    assert daemon_should_act(
        _audit(tmp_path, _f(Verdict.UNKNOWN, needs_owner=True))) is False


def test_an_unreadable_history_does_not_wake_it(tmp_path):
    """A history that cannot be read is not evidence of recurrence. Failing
    open here would summon a pass on every audit of every project that has no
    history yet."""
    hist = tmp_path / ".audit-history"
    hist.mkdir()
    (hist / "broken.json").write_text("{not json", encoding="utf-8")
    assert daemon_should_act(_audit(tmp_path, _f(Verdict.UNKNOWN))) is False


def test_this_repo_no_longer_summons_a_pass_on_itself():
    """A DECISION, PINNED SO IT CANNOT DRIFT BACK BY ACCIDENT.

    Every audited project checks this repository out on every run, so a pass
    here would change the standard they are all judged by without review. The
    summon was removed on 2026-09-24 and `_the_fixer_can_act` reports SKIP for
    this repo as a result.

    This used to assert the OPPOSITE, for both this workflow and
    stock-predictor's — reached across the filesystem at
    `../שוק-ההון/stock-predictor/`, a path that exists on one laptop. In CI
    the file was absent, the loop body never ran, and the test passed having
    checked nothing. That guarantee now lives in stock-predictor's own suite
    (`tests/test_summon_gate.py`), where the workflow is and where it runs on
    every push. The place a check runs is part of the check.
    """
    wf = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "audit.yml"
    text = wf.read_text(encoding="utf-8")
    assert "- name: Summon the daemon" not in text, \
        "the summon came back — see the comment block in audit.yml"
    assert "NO SUMMON HERE" in text, \
        "the decision lost its explanation, which is how it gets undone"


def test_a_recurring_warning_is_deliberately_not_enough(tmp_path):
    """`history.recurring` counts FAIL and UNKNOWN only. That is its existing
    judgement, not an oversight here: an untidy .gitignore reported every day
    is mildly annoying, not a system failing to act, and summoning a pass for
    it would make it one."""
    hist = tmp_path / ".audit-history"
    hist.mkdir()
    for n in range(6):
        (hist / f"2026-09-{n + 1:02d}.json").write_text(json.dumps({
            "sent": True,
            "findings": [{"check": "c", "title": "something",
                          "verdict": "warn"}],
        }), encoding="utf-8")
    assert daemon_should_act(_audit(tmp_path, _f(Verdict.WARN))) is False


def test_should_fix_prints_nothing(capsys, tmp_path, monkeypatch):
    """A DECISION, NOT A REPORT. The first version sat after the print and
    dumped the whole audit into a workflow step whose only job was to answer
    yes or no — the log showed a full report followed by "Nothing a pass could
    fix", which reads as though the report caused the verdict.

    Documentation that contradicts the code is a defect in both, and this
    flag's help text had promised silence since the hour it was written."""
    from sentinel import cli

    (tmp_path / "SENTINEL.toml").write_text(
        '[project]\nname = "t"\npurpose = "p"\n\n'
        '[[expectations]]\nid = "x"\nsays = "s"\nkind = "file_exists"\n'
        'path = "README.md"\n', encoding="utf-8")
    (tmp_path / "README.md").write_text("x", encoding="utf-8")

    cli.main(["run", str(tmp_path), "--should-fix"])
    assert capsys.readouterr().out == "", \
        "the decision flag printed a report"
