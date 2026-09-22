"""What the bot told its owner, and the pattern only the sequence reveals."""
import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel import history                            # noqa: E402
from sentinel.manifest import Manifest                  # noqa: E402
from sentinel.report import Audit                       # noqa: E402
from sentinel.verdict import CheckResult, Finding, Verdict  # noqa: E402


@pytest.fixture
def root():
    return Path(tempfile.mkdtemp())


def write_report(root: Path, stamp: str, findings: list[dict]):
    d = history.directory(root)
    d.mkdir(exist_ok=True)
    (d / f"{stamp}.json").write_text(
        json.dumps({"started_at": stamp, "findings": findings,
                    "message": "x"}, ensure_ascii=False), encoding="utf-8")


def f(title: str, verdict: str = "fail", check: str = "intent") -> dict:
    return {"check": check, "title": title, "verdict": verdict,
            "severity": "high", "detail": "d", "evidence": "", "remedy": "r"}


def test_a_sent_message_is_recorded(root):
    m = Manifest(path=root / "SENTINEL.toml", name="demo", purpose="p")
    a = Audit(manifest=m, results=[CheckResult(name="intent", findings=[
        Finding(check="intent", title="t", verdict=Verdict.FAIL, detail="d")])])
    history.record(a, "the message")
    saved = history.load(root)
    assert len(saved) == 1
    assert saved[0]["message"] == "the message"


def test_recording_never_raises_on_a_bad_path():
    """Failing to remember a message must not fail the audit that produced it —
    the report has already reached its reader, which is the part that matters."""
    m = Manifest(path=Path("/nonexistent/deep/SENTINEL.toml"), name="d",
                 purpose="p")
    a = Audit(manifest=m)
    assert "could not record" in history.record(a, "msg")


def test_a_repeated_finding_is_surfaced(root):
    """The signal no single report can carry."""
    for i in range(6):
        write_report(root, f"2026-09-0{i+1}T00:00:00", [f("the same problem")])
    repeats = history.recurring(root)
    assert len(repeats) == 1
    assert repeats[0]["count"] == 6


def test_a_finding_below_the_threshold_is_not_surfaced(root):
    for i in range(3):
        write_report(root, f"2026-09-0{i+1}T00:00:00", [f("occasional")])
    assert history.recurring(root) == []


def test_warnings_do_not_count_as_recurring(root):
    """A recurring WARN is usually a deliberate 'not now'. An untidy .gitignore
    reported daily is mildly annoying, not a system failing to act."""
    for i in range(9):
        write_report(root, f"2026-09-0{i+1}T00:00:00", [f("tidy up", "warn")])
    assert history.recurring(root) == []


def test_unknowns_do_count(root):
    """An unchecked promise repeated for a week means nobody made it runnable."""
    for i in range(6):
        write_report(root, f"2026-09-0{i+1}T00:00:00", [f("unchecked", "unknown")])
    assert len(history.recurring(root)) == 1


def test_findings_are_keyed_on_title_not_on_changing_detail(root):
    """The detail carries counts and timestamps that change between runs while
    the finding stays the same one."""
    for i in range(6):
        d = f("same title")
        d["detail"] = f"{i} occurrences"
        write_report(root, f"2026-09-0{i+1}T00:00:00", [d])
    assert history.recurring(root)[0]["count"] == 6


def test_different_findings_are_counted_separately(root):
    for i in range(6):
        write_report(root, f"2026-09-0{i+1}T00:00:00",
                     [f("problem A"), f("problem B")])
    assert len(history.recurring(root)) == 2


def test_a_resolved_finding_stops_accumulating(root):
    """Five old reports, then two clean ones. The count reflects what was
    reported, and the check reads only what is still being reported."""
    for i in range(5):
        write_report(root, f"2026-09-0{i+1}T00:00:00", [f("was broken")])
    for i in range(5, 8):
        write_report(root, f"2026-09-0{i+1}T00:00:00", [])
    assert history.recurring(root)[0]["count"] == 5


def test_an_unreadable_file_is_skipped_not_fatal(root):
    d = history.directory(root)
    d.mkdir()
    (d / "broken.json").write_text("{not json", encoding="utf-8")
    write_report(root, "2026-09-01T00:00:00", [f("fine")])
    assert len(history.load(root)) == 1


def test_no_history_is_not_an_error(root):
    assert history.load(root) == []
    assert history.recurring(root) == []


def test_the_directory_is_capped(root):
    m = Manifest(path=root / "SENTINEL.toml", name="d", purpose="p")
    a = Audit(manifest=m)
    for _ in range(history.KEEP + 15):
        history.record(a, "m")
    assert len(list(history.directory(root).glob("*.json"))) <= history.KEEP


# ── a check that never passes is probably broken, not vigilant ─────────
def test_a_check_that_never_passed_is_surfaced(root):
    """The generalised form of a real bug: "is the latest CI run green" asked
    for the most recent run, which inside CI is the audit currently executing.
    It reported "not finished" forever — nine reports before anyone noticed,
    because one UNKNOWN line looks like ordinary weather."""
    for i in range(8):
        write_report(root, f"2026-09-0{i+1}T00:00:00",
                     [f("stuck check", "unknown"), f("healthy", "pass")])
    stuck = history.never_passed(root)
    assert len(stuck) == 1
    assert stuck[0]["title"] == "stuck check"
    assert stuck[0]["runs"] == 8


def test_a_check_that_passed_once_is_not_flagged(root):
    """One pass proves the question is answerable. After that, a failure is a
    finding about the project, not about the check."""
    for i in range(7):
        write_report(root, f"2026-09-0{i+1}T00:00:00", [f("flaky", "fail")])
    write_report(root, "2026-09-08T00:00:00", [f("flaky", "pass")])
    assert history.never_passed(root) == []


def test_a_check_below_the_run_threshold_is_not_flagged(root):
    """Two unknowns is not a pattern; it is a Tuesday."""
    for i in range(3):
        write_report(root, f"2026-09-0{i+1}T00:00:00", [f("new", "unknown")])
    assert history.never_passed(root) == []


def test_skips_do_not_count_as_never_passing(root):
    """SKIP means deliberately not applicable — a decision, not a failure to
    answer. Counting it would flag every environment-specific check."""
    for i in range(8):
        write_report(root, f"2026-09-0{i+1}T00:00:00", [f("mac only", "skip")])
    assert history.never_passed(root) == []


def test_never_passed_and_recurring_ask_different_questions(root):
    """`recurring` asks "is this still open" — a genuine long-standing problem
    answers yes honestly. `never_passed` asks "has this ever worked", and a no
    points at the check itself."""
    for i in range(8):
        write_report(root, f"2026-09-0{i+1}T00:00:00",
                     [f("real problem", "fail")])
    write_report(root, "2026-09-09T00:00:00", [f("real problem", "pass")])
    assert history.recurring(root), "still worth reporting as recurring"
    assert history.never_passed(root) == [], "but it HAS worked, so not stuck"


def test_a_fixed_finding_stops_being_warned_about(root):
    """A finding fixed yesterday would otherwise keep being counted from the
    history for another month — an alarm about a problem that no longer exists,
    which is exactly the noise this warning was added to prevent."""
    for i in range(8):
        write_report(root, f"2026-09-0{i+1}T00:00:00", [f("was broken")])
    assert history.recurring(root), "raw history still counts it"
    assert history.recurring(root, still_open=set()) == [], \
        "but it is not open now, so it must not be warned about"


def test_a_still_open_finding_is_warned_about(root):
    for i in range(8):
        write_report(root, f"2026-09-0{i+1}T00:00:00", [f("still broken")])
    open_now = {("intent", "still broken")}
    assert len(history.recurring(root, still_open=open_now)) == 1


def test_only_the_open_ones_survive_the_filter(root):
    for i in range(8):
        write_report(root, f"2026-09-0{i+1}T00:00:00",
                     [f("fixed"), f("still broken")])
    got = history.recurring(root, still_open={("intent", "still broken")})
    assert [g["title"] for g in got] == ["still broken"]


def test_a_check_reclassified_to_skip_stops_counting_as_never_passed(tmp_path):
    """Moved to SKIP because CI can never answer it, the secrets check went on
    being reported as "8 runs, zero passes" — its old UNKNOWN rows stayed in
    the sixty-message window. A warning about a check that has already been
    fixed is the noise `_never_passed` exists to remove."""
    import json
    from sentinel import history

    hist = tmp_path / ".audit-history"
    hist.mkdir()
    # Older: unknown, six times. Newest: skip.
    for n in range(6):
        (hist / f"2026090{n + 1}T000000Z.json").write_text(json.dumps({
            "sent": True, "started_at": f"2026-09-0{n + 1}",
            "findings": [{"check": "health", "title": "secrets",
                          "verdict": "unknown"}]}), encoding="utf-8")
    (hist / "20260910T000000Z.json").write_text(json.dumps({
        "sent": True, "started_at": "2026-09-10",
        "findings": [{"check": "health", "title": "secrets",
                      "verdict": "skip"}]}), encoding="utf-8")
    assert history.never_passed(tmp_path) == []


def test_a_check_still_unknown_is_still_reported(tmp_path):
    """The reclassification rule must not swallow the real case."""
    import json
    from sentinel import history

    hist = tmp_path / ".audit-history"
    hist.mkdir()
    for n in range(7):
        (hist / f"2026090{n + 1}T000000Z.json").write_text(json.dumps({
            "sent": True, "started_at": f"2026-09-0{n + 1}",
            "findings": [{"check": "health", "title": "broken",
                          "verdict": "unknown"}]}), encoding="utf-8")
    assert [e["title"] for e in history.never_passed(tmp_path)] == ["broken"]


def test_a_check_that_has_failed_is_not_a_suspect(tmp_path):
    """`_never_passed` means "suspect the check, not the project", and it earns
    that by finding checks stuck on UNKNOWN — ones their environment cannot
    answer. A FAIL is an answer. `_no_workflow_always_fails` was named as a
    suspect nine times while correctly reporting that a workflow had never once
    succeeded, so one real problem arrived as three findings."""
    import json
    from sentinel import history

    hist = tmp_path / ".audit-history"
    hist.mkdir()
    for n in range(8):
        (hist / f"2026091{n}T000000Z.json").write_text(json.dumps({
            "sent": True, "started_at": f"2026-09-1{n}",
            "findings": [{"check": "health", "title": "always fails",
                          "verdict": "fail"},
                         {"check": "health", "title": "cannot tell",
                          "verdict": "unknown"}]}), encoding="utf-8")
    titles = [e["title"] for e in history.never_passed(tmp_path)]
    assert titles == ["cannot tell"]
