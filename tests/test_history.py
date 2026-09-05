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
