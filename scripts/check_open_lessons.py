"""
check_open_lessons.py
---------------------
Fails when a lesson has been open too long.

An open lesson is a defect that can still recur. The weekly improvement pass is
meant to close them, and this is what notices when it stops — the pass going
quiet is otherwise indistinguishable from there being nothing left to do.

Eight weeks, not two. Some lessons need a design decision before a check can
exist, and a reminder that fires while someone is still thinking gets muted.
The window is generous on purpose: it is here to catch ABANDONMENT, not delay.

Exit 0 clean · 1 something is overdue · 3 could not read the file (UNKNOWN).
"""

from __future__ import annotations

import re
import sys
from datetime import date, datetime
from pathlib import Path

MAX_OPEN_DAYS = 56

LESSONS = Path(__file__).resolve().parent.parent / "LESSONS.md"

HEADING = re.compile(r"^## (L\d+) — (.+)$", re.M)
FOUND = re.compile(r"\*\*Found\*\*\s+(\d{4}-\d{2}-\d{2})")
STATUS = re.compile(r"status:\s*(open|closed)")


def main() -> int:
    if not LESSONS.is_file():
        print(f"cannot read {LESSONS.name}", file=sys.stderr)
        return 3

    text = LESSONS.read_text(encoding="utf-8")
    headings = list(HEADING.finditer(text))
    if not headings:
        print("no lessons found — the file exists but records nothing",
              file=sys.stderr)
        return 3

    today = date.today()
    overdue: list[str] = []
    open_count = 0

    for i, h in enumerate(headings):
        body = text[h.end():headings[i + 1].start() if i + 1 < len(headings)
                    else len(text)]
        status = STATUS.search(body)
        if not status or status.group(1) != "open":
            continue
        open_count += 1

        found = FOUND.search(body)
        if not found:
            # A lesson with no date cannot be aged, and silently skipping it
            # would let it sit open forever. Treat it as overdue: adding a date
            # is a two-second fix.
            overdue.append(f"{h.group(1)} ({h.group(2)[:50]}) — no Found date")
            continue
        try:
            age = (today - datetime.strptime(found.group(1), "%Y-%m-%d").date()).days
        except ValueError:
            overdue.append(f"{h.group(1)} — unreadable date {found.group(1)!r}")
            continue
        if age > MAX_OPEN_DAYS:
            overdue.append(f"{h.group(1)} ({h.group(2)[:50]}) — open {age} days")

    if overdue:
        print(f"{len(overdue)} lesson(s) open longer than {MAX_OPEN_DAYS} days:",
              file=sys.stderr)
        for line in overdue:
            print(f"  {line}", file=sys.stderr)
        return 1

    print(f"{len(headings)} lesson(s), {open_count} open, none overdue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
