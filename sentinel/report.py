"""
report.py
---------
Renders an audit. Two rules govern every line of it.

FIRST: THE SUMMARY NEVER HIDES AN UNKNOWN. "18 passed" when three checks could
not run is a lie of omission, and it is the lie an auditor is most tempted to
tell, because unknowns are boring and passes look like progress. Unknowns get
their own count in the headline and their own section.

SECOND: EVERY FAILURE CARRIES ITS EVIDENCE AND ITS REMEDY. A report that says
something is wrong without showing why, or without saying what to do, converts
into "I'll look at it later" and then into noise.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .manifest import Manifest
from .verdict import CheckResult, Finding, Severity, Verdict

ORDER = [Verdict.FAIL, Verdict.UNKNOWN, Verdict.WARN, Verdict.PASS, Verdict.SKIP]


@dataclass
class Audit:
    manifest: Manifest
    results: list[CheckResult] = field(default_factory=list)
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    @property
    def findings(self) -> list[Finding]:
        return [f for r in self.results for f in r.findings]

    def count(self, v: Verdict) -> int:
        return sum(1 for f in self.findings if f.verdict is v)

    @property
    def failed(self) -> bool:
        return self.count(Verdict.FAIL) > 0

    @property
    def exit_code(self) -> int:
        """0 clean, 1 something failed, 2 nothing failed but something was not
        checked. A separate code for unknown so a scheduler can treat "I could
        not look" differently from "I looked and it is broken"."""
        if self.count(Verdict.FAIL):
            return 1
        if self.count(Verdict.UNKNOWN):
            return 2
        return 0

    @property
    def headline(self) -> str:
        bits = [f"{self.count(v)} {v.value}" for v in ORDER if self.count(v)]
        return " · ".join(bits) or "nothing checked"


def _by_severity(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (Severity(f.severity).rank, f.title))


def to_markdown(audit: Audit) -> str:
    m = audit.manifest
    L: list[str] = []
    L.append(f"# Audit — {m.name}")
    L.append("")
    if m.purpose:
        L.append(f"> {m.purpose}")
        L.append("")
    L.append(f"`{audit.started_at}` · **{audit.headline}**")
    L.append("")

    if audit.count(Verdict.UNKNOWN):
        L.append(f"> ⚠️ **{audit.count(Verdict.UNKNOWN)} check(s) could not be "
                 f"run.** This audit is incomplete; an unknown is not a pass.")
        L.append("")

    # The promises first. They are the reason this tool exists, and burying
    # them under lint would invert the priority.
    intent = [f for f in audit.findings if f.check == "intent"]
    if intent:
        L.append("## What this project promises to do")
        L.append("")
        for f in _by_severity(intent):
            L.append(f"### {f.verdict.icon} {f.title}")
            L.append("")
            if f.detail:
                L.append(f"{f.detail}")
                L.append("")
            if f.evidence and f.verdict.is_actionable:
                L.append("```")
                L.append(f.evidence.strip()[:1500])
                L.append("```")
                L.append("")
            if f.remedy and f.verdict.is_actionable:
                L.append(f"**Fix:** {f.remedy}")
                L.append("")

    for result in audit.results:
        if result.name == "intent":
            continue
        L.append(f"## {result.name.title()}")
        L.append("")
        for f in _by_severity(result.findings):
            L.append(f"- {f.verdict.icon} **{f.title}** — {f.detail}")
            if f.evidence and f.verdict.is_actionable:
                L.append("")
                L.append("  ```")
                for line in f.evidence.strip().splitlines()[:12]:
                    L.append(f"  {line}")
                L.append("  ```")
            if f.remedy and f.verdict.is_actionable:
                L.append(f"  <br>**Fix:** {f.remedy}")
        L.append("")

    L.append("---")
    L.append("")
    L.append(f"_Checked {len(audit.findings)} things in "
             f"{sum(r.duration_s for r in audit.results):.1f}s. "
             f"An UNKNOWN means nobody looked, not that it is fine._")
    return "\n".join(L)


def to_terminal(audit: Audit) -> str:
    m = audit.manifest
    L = [f"\n  {m.name} — {audit.headline}"]
    if m.purpose:
        L.append(f"  {m.purpose.splitlines()[0][:88]}")
    L.append("")
    for result in audit.results:
        L.append(f"  {result.name}")
        for f in _by_severity(result.findings):
            L.append(f"    {f.verdict.icon} {f.title}")
            if f.detail and f.verdict.is_actionable:
                L.append(f"        {f.detail}")
            if f.remedy and f.verdict is Verdict.FAIL:
                L.append(f"        → {f.remedy}")
        L.append("")
    if audit.count(Verdict.UNKNOWN):
        L.append(f"  ❓ {audit.count(Verdict.UNKNOWN)} check(s) could not run — "
                 f"this audit is incomplete.")
        L.append("")
    return "\n".join(L)


def to_dict(audit: Audit) -> dict:
    return {
        "project": audit.manifest.name,
        "purpose": audit.manifest.purpose,
        "started_at": audit.started_at,
        "headline": audit.headline,
        "exit_code": audit.exit_code,
        "counts": {v.value: audit.count(v) for v in ORDER},
        "findings": [
            {"check": f.check, "title": f.title, "verdict": f.verdict.value,
             "severity": f.severity.value, "detail": f.detail,
             "evidence": f.evidence, "remedy": f.remedy,
             # Stored too, so a later reader — the recurring-finding check, the
             # daemon — can name a past finding in the report's own language.
             "title_he": f.title_he, "remedy_he": f.remedy_he,
             # WITHOUT THIS THE ARCHIVE LIES BY OMISSION. A pass reads the last
             # sixty messages to see what keeps repeating; a finding only its
             # owner could ever have closed looks, from the history alone,
             # exactly like one the pass ignored for a fortnight.
             "needs_owner": f.needs_owner}
            for f in audit.findings
        ],
    }


def daemon_should_act(audit) -> bool:
    """Is there something here a self-improvement pass could actually fix?

    THE GAP THIS CLOSES. The daemon was summoned only when a promise was
    BROKEN — exit 1. Every UNKNOWN and every WARN exited 2 and woke nobody, so
    a finding could be reported every morning for a week while the one thing
    able to act on it was never told. The owner saw the same message daily and
    reasonably concluded the system only reports.

    Two conditions, and both matter:

      * a FAIL is acted on immediately — a promise the project makes and no
        longer keeps is the strongest signal available;
      * an UNKNOWN is acted on ONLY ONCE IT RECURS. One "could not check" is
        information; five mornings of the same one means nobody has made it
        checkable, and making a check runnable is squarely daemon work.

    A WARN never triggers on recurrence, and that is `history.recurring`'s
    existing judgement rather than an oversight here: it counts FAIL and
    UNKNOWN only, because a recurring warning is usually a deliberate "not
    now". An untidy .gitignore reported daily is mildly annoying; it is not a
    system failing to act, and summoning a pass for it would make it one.

    AND NEVER FOR SOMETHING THE PASS CANNOT REACH. `needs_owner` findings —
    rotate a credential, plug in a drive, edit a workflow, change an account
    setting — would summon a pass that looks, finds nothing it may touch, and
    burns a run. Waking the daemon for work it is forbidden to do is how a
    fixing loop becomes an expensive reporting loop.
    """
    from .verdict import Verdict

    from . import history

    actionable = [f for f in audit.findings
                  if f.verdict.is_actionable and not f.needs_owner]
    if any(f.verdict is Verdict.FAIL for f in actionable):
        return True

    # A FAIL or UNKNOWN reported five mornings running and still open.
    # `still_open` is what stops a finding fixed yesterday from summoning the
    # daemon for another month out of the history file.
    still_open = {(f.check, f.title) for f in actionable}
    if not still_open:
        return False
    try:
        return bool(history.recurring(audit.manifest.root, still_open=still_open))
    except Exception:                                     # noqa: BLE001
        # A history that cannot be read is not a reason to wake the daemon.
        return False
