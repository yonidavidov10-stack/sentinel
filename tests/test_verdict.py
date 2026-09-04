"""The discipline the whole tool rests on: UNKNOWN is never a pass."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.verdict import CheckResult, Finding, Severity, Verdict  # noqa: E402


def test_unknown_is_actionable():
    """If this ever flips, every report the tool has produced becomes
    untrustworthy: it would have been counting unchecked things as healthy."""
    assert Verdict.UNKNOWN.is_actionable


def test_pass_is_not_actionable():
    assert not Verdict.PASS.is_actionable


@pytest.mark.parametrize("v", [Verdict.FAIL, Verdict.WARN, Verdict.UNKNOWN])
def test_everything_a_person_must_look_at_is_actionable(v):
    assert v.is_actionable


def test_skip_is_not_actionable():
    """SKIP means deliberately not applicable — a decision, not an omission."""
    assert not Verdict.SKIP.is_actionable


def test_a_failure_must_carry_evidence():
    """A failure nobody can act on is noise, and noise trains people to ignore
    the whole report."""
    with pytest.raises(ValueError):
        Finding(check="c", title="t", verdict=Verdict.FAIL)


def test_a_failure_with_detail_is_allowed():
    Finding(check="c", title="t", verdict=Verdict.FAIL, detail="because")


def test_a_failure_with_evidence_is_allowed():
    Finding(check="c", title="t", verdict=Verdict.FAIL, evidence="log line")


@pytest.mark.parametrize("v", [Verdict.PASS, Verdict.WARN, Verdict.UNKNOWN,
                               Verdict.SKIP])
def test_other_verdicts_need_no_evidence(v):
    Finding(check="c", title="t", verdict=v)


def test_severity_ranks_critical_first():
    assert Severity.CRITICAL.rank < Severity.HIGH.rank < Severity.MEDIUM.rank \
        < Severity.LOW.rank


def test_worst_prefers_fail_over_unknown_over_warn():
    r = CheckResult(name="x", findings=[
        Finding(check="x", title="a", verdict=Verdict.PASS),
        Finding(check="x", title="b", verdict=Verdict.WARN),
        Finding(check="x", title="c", verdict=Verdict.UNKNOWN),
        Finding(check="x", title="d", verdict=Verdict.FAIL, detail="d"),
    ])
    assert r.worst is Verdict.FAIL


def test_unknown_outranks_warn():
    """An unchecked promise matters more than a tidy-up suggestion."""
    r = CheckResult(name="x", findings=[
        Finding(check="x", title="b", verdict=Verdict.WARN),
        Finding(check="x", title="c", verdict=Verdict.UNKNOWN),
    ])
    assert r.worst is Verdict.UNKNOWN


def test_every_verdict_has_an_icon():
    for v in Verdict:
        assert v.icon
