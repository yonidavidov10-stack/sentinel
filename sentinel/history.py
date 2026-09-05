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


def recurring(root: Path, min_appearances: int = 5) -> list[dict]:
    """Findings the owner has now been told about `min_appearances` times.

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
    return sorted((e for e in seen.values() if e["count"] >= min_appearances),
                  key=lambda e: -e["count"])
