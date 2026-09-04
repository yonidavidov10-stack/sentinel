"""The learning loop: a defect written down becomes a check, and a lesson left
open is noticed rather than forgotten.

This is the mechanism the whole tool is meant to run, so it gets the same
scrutiny as the checks: it must fire when a lesson is abandoned, stay quiet
while one is merely recent, and refuse to guess when it cannot read the file.
"""
import subprocess
import sys
import tempfile
from datetime import date, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_open_lessons.py"


def run_against(text: str | None) -> subprocess.CompletedProcess:
    """Run the checker with LESSONS.md replaced by `text` (None = absent)."""
    d = Path(tempfile.mkdtemp())
    (d / "scripts").mkdir()
    (d / "scripts" / SCRIPT.name).write_text(
        SCRIPT.read_text(encoding="utf-8"), encoding="utf-8")
    if text is not None:
        (d / "LESSONS.md").write_text(text, encoding="utf-8")
    return subprocess.run([sys.executable, str(d / "scripts" / SCRIPT.name)],
                          capture_output=True, text=True)


def lesson(num: int, days_ago: int, status: str) -> str:
    when = (date.today() - timedelta(days=days_ago)).isoformat()
    return (f"## L{num:03d} — something got past\n"
            f"**Found** {when} · **status: {status}**\n\nbody\n\n")


def test_a_recent_open_lesson_is_fine():
    """A reminder that fires while someone is still thinking gets muted."""
    r = run_against(lesson(1, 3, "open"))
    assert r.returncode == 0


def test_an_abandoned_lesson_fails():
    r = run_against(lesson(1, 200, "open"))
    assert r.returncode == 1
    assert "L001" in r.stderr


def test_a_closed_lesson_never_ages_out():
    r = run_against(lesson(1, 2000, "closed"))
    assert r.returncode == 0


def test_the_boundary_is_not_off_by_one():
    assert run_against(lesson(1, 56, "open")).returncode == 0
    assert run_against(lesson(1, 57, "open")).returncode == 1


def test_an_open_lesson_with_no_date_is_overdue_not_skipped():
    """Silently skipping it would let it sit open forever, and adding a date is
    a two-second fix."""
    r = run_against("## L001 — no date here\n**status: open**\n\nbody\n")
    assert r.returncode == 1
    assert "no Found date" in r.stderr


def test_an_unreadable_date_is_reported_rather_than_ignored():
    r = run_against("## L001 — bad date\n**Found** yesterday · **status: open**\n")
    assert r.returncode == 1


def test_a_missing_file_is_unknown_not_a_pass():
    """The tool's own discipline: a check that could not run must not report
    health it did not verify."""
    assert run_against(None).returncode == 3


def test_a_file_with_no_lessons_is_unknown_not_a_pass():
    """An empty ledger is not a clean one — it is a ledger nobody is using."""
    assert run_against("# Lessons\n\nnothing here yet\n").returncode == 3


def test_several_overdue_lessons_are_all_reported():
    r = run_against(lesson(1, 100, "open") + lesson(2, 3, "open")
                    + lesson(3, 400, "open"))
    assert r.returncode == 1
    assert "L001" in r.stderr and "L003" in r.stderr
    assert "L002" not in r.stderr


def test_the_real_ledger_is_readable_and_current():
    """The project's own LESSONS.md, not a fixture."""
    r = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True,
                       text=True, cwd=str(ROOT))
    assert r.returncode == 0, r.stderr


def test_every_closed_lesson_names_its_check():
    """A lesson closed without naming what closed it is a lesson nobody can
    verify — the record exists to be checkable, not reassuring."""
    text = (ROOT / "LESSONS.md").read_text(encoding="utf-8")
    import re
    headings = list(re.finditer(r"^## (L\d+) — (.+)$", text, re.M))
    for i, h in enumerate(headings):
        body = text[h.end():headings[i + 1].start() if i + 1 < len(headings)
                    else len(text)]
        if "status: closed" in body:
            assert "**Check:**" in body, f"{h.group(1)} closed without naming a check"
