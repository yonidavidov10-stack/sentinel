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


# ── every 👤 says why ──────────────────────────────────────────────────

def test_every_needs_owner_site_explains_itself():
    """THE OWNER ASKED "למה הוא תמיד רושם ממתין לך, שיעשה לבד" AND THE REPORT
    HAD NO ANSWER IN IT.

    A boundary stated without a reason reads as the tool being lazy, so a
    person pushes back on all of them instead of the wrong ones. Checked by
    reading the source rather than by running the checks, because most of
    these branches need a broken project to reach — the next one added would
    otherwise ship a bare 👤 and nobody would notice until it was sent.
    """
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent / "sentinel"
    bare = []
    for f in sorted(root.rglob("*.py")):
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            kw = {k.arg: k.value for k in node.keywords if k.arg}
            owner = kw.get("needs_owner")
            if not (isinstance(owner, ast.Constant) and owner.value is True):
                continue
            why = kw.get("owner_reason_he")
            text = ast.literal_eval(why) if isinstance(
                why, ast.Constant) else (
                "".join(ast.literal_eval(v) for v in why.values)
                if isinstance(why, ast.JoinedStr) and all(
                    isinstance(v, ast.Constant) for v in why.values)
                else "?" if why is not None else "")
            if len(text.strip()) < 10:
                bare.append(f"{f.name}:{node.lineno}")

    assert not bare, ("needs_owner without a reason the owner can read: "
                      + ", ".join(bare))
