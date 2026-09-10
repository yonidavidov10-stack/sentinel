"""
history.py
----------
Remembers what the bot actually TOLD its owner, and for how long.

WHY THE MESSAGES AND NOT JUST THE AUDITS
----------------------------------------
An audit is data. A message is what a person read. The difference matters,
because the most valuable signal here is not in any single report — it is in
the sequence:

  A FINDING THAT APPEARS IN EVERY MESSAGE FOR A WEEK IS A FAILURE OF THE
  SYSTEM, NOT A FINDING.

Either nobody is fixing it, or it is not really a problem and the report has
been crying wolf about it daily. Both are worth knowing, and neither is visible
from one report. The audit that ran an hour ago cannot tell you it is the
fourteenth time it said the same thing.

Only messages that were actually SENT are recorded. A silent audit told the
owner nothing, and counting it would make a finding look like it had been
reported when nobody ever saw it.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .report import Audit, to_dict

DIR_NAME = ".audit-history"

# Two reports a day, so sixty is about a month. Enough to see a pattern, small
# enough that the directory never becomes a thing anyone has to think about.
KEEP = 60


def directory(root: Path) -> Path:
    return Path(root) / DIR_NAME


def record(audit: Audit, message: str) -> str:
    """Append one sent message. Returns a note for the log, or "".

    Never raises. Failing to remember a message must not fail the audit that
    produced it — the report has already reached its reader, which is the part
    that matters.
    """
    try:
        d = directory(audit.manifest.root)
        d.mkdir(exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        payload = to_dict(audit)
        payload["message"] = message
        (d / f"{stamp}.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

        # Oldest first, drop the surplus. A cap that is never enforced is a
        # directory that grows until someone notices it in a diff.
        files = sorted(d.glob("*.json"))
        for old in files[:-KEEP]:
            old.unlink(missing_ok=True)
        return f"recorded {stamp}, {len(files[-KEEP:])} kept"
    except Exception as e:                                  # noqa: BLE001
        return f"could not record: {type(e).__name__}"


def load(root: Path, limit: int = KEEP) -> list[dict]:
    """Past messages, newest first. Unreadable files are skipped, not fatal."""
    d = directory(root)
    if not d.is_dir():
        return []
    out = []
    for f in sorted(d.glob("*.json"), reverse=True)[:limit]:
        try:
            out.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:                                   # noqa: BLE001
            continue
    return out


def recurring(root: Path, min_appearances: int = 5,
              still_open: set[tuple[str, str]] | None = None) -> list[dict]:
    """Findings reported `min_appearances` times AND STILL OPEN RIGHT NOW.

    `still_open` is the set of (check, title) that the CURRENT audit reports as
    fail or unknown. Without it, a finding fixed yesterday keeps being counted
    from the history and warned about for another month, until it ages out of
    the window — an alarm about a problem that no longer exists, which is
    precisely the noise this warning was added to prevent. Passing None keeps
    the raw historical count, which is what the tests and the ledger want.

    Keyed on (check, title) rather than on the detail text, because the detail
    carries counts and timestamps that change between runs while the finding
    stays the same one.

    Only FAIL and UNKNOWN count. A recurring WARN is usually a deliberate
    "not now" — an untidy .gitignore reported every day is mildly annoying,
    not a system failing to act.
    """
    seen: dict[tuple[str, str], dict] = {}
    for report in load(root):
        for f in report.get("findings") or []:
            if f.get("verdict") not in ("fail", "unknown"):
                continue
            key = (f.get("check", ""), f.get("title", ""))
            entry = seen.setdefault(key, {
                "check": key[0], "title": key[1], "verdict": f.get("verdict"),
                "count": 0, "first_seen": report.get("started_at", ""),
                "remedy": f.get("remedy", ""),
            })
            entry["count"] += 1
            # `load` returns newest first, so each later hit is older.
            entry["first_seen"] = report.get("started_at", entry["first_seen"])
    out = [e for e in seen.values() if e["count"] >= min_appearances]
    if still_open is not None:
        out = [e for e in out if (e["check"], e["title"]) in still_open]
    return sorted(out, key=lambda e: -e["count"])


def never_passed(root: Path, min_runs: int = 6) -> list[dict]:
    """Checks that have run repeatedly and NEVER once passed.

    A CHECK THAT NEVER PASSES IS PROBABLY BROKEN, NOT VIGILANT. One that has
    reported UNKNOWN or FAIL every time it ran is far more likely to be asking
    a question that cannot be answered than to have found a problem nobody has
    fixed in weeks.

    This is the generalised form of a real bug: "is the latest CI run green"
    asked `gh run list --limit 1`, which inside CI returns the audit currently
    executing — so it reported "not finished yet" forever. Nine reports before
    anyone noticed, because one UNKNOWN line looks like ordinary weather.

    Distinct from `recurring`, which asks "is this still open" and would flag a
    genuine long-standing problem. This asks "has this ever worked", and a no
    points at the check rather than at the project.
    """
    seen: dict[tuple[str, str], dict] = {}
    for report in load(root):
        for f in report.get("findings") or []:
            verdict = f.get("verdict")
            if verdict == "skip":          # deliberately not applicable
                continue
            key = (f.get("check", ""), f.get("title", ""))
            entry = seen.setdefault(key, {
                "check": key[0], "title": key[1],
                "title_he": f.get("title_he", ""), "runs": 0, "passes": 0,
            })
            entry["runs"] += 1
            if verdict == "pass":
                entry["passes"] += 1
            if not entry["title_he"]:
                entry["title_he"] = f.get("title_he", "")
    return sorted(
        (e for e in seen.values() if e["passes"] == 0 and e["runs"] >= min_runs),
        key=lambda e: -e["runs"])
