"""
verdict.py
----------
The three states a check can end in, and the rule that keeps them honest.

WHY THREE AND NOT TWO
---------------------
A pass/fail auditor lies by omission. When it cannot reach a thing — the
network is down, a credential is missing, a command is not installed — it must
say "I could not check this". Folding that into PASS means the report says the
system is healthy when nobody looked, which is the single worst thing an
auditor can do, because its whole value is that someone reads it instead of
looking themselves.

So UNKNOWN is a first-class outcome, it is counted separately, and the summary
line always names it. An audit with twelve passes and three unknowns is not a
clean audit.

This mirrors `evaluate/objective.py` in the stock-predictor, which refuses to
report a level its sample cannot support. Same discipline, different domain: a
number you did not measure and a check you did not run are the same lie.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Verdict(str, enum.Enum):
    PASS = "pass"          # checked, and it holds
    FAIL = "fail"          # checked, and it does not hold
    WARN = "warn"          # checked; not broken, but worth a human's attention
    UNKNOWN = "unknown"    # NOT checked. Never counts as a pass.
    SKIP = "skip"          # deliberately not applicable to this project

    @property
    def is_actionable(self) -> bool:
        """Does a person need to do something about this?"""
        return self in (Verdict.FAIL, Verdict.WARN, Verdict.UNKNOWN)

    @property
    def icon(self) -> str:
        return {"pass": "✅", "fail": "❌", "warn": "⚠️",
                "unknown": "❓", "skip": "⏭️"}[self.value]


class Severity(str, enum.Enum):
    """How much it matters when this fails. Set by the check, not the runner."""
    CRITICAL = "critical"   # the project's core promise is broken
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3}[self.value]


@dataclass
class Finding:
    """One statement about the project, and the evidence for it.

    `evidence` is not decoration. A finding a reader cannot verify is a finding
    they have to take on trust, and this tool's entire purpose is to remove the
    need for that. Every FAIL must carry the output that proves it.
    """
    check: str
    title: str
    verdict: Verdict
    severity: Severity = Severity.MEDIUM
    detail: str = ""
    evidence: str = ""
    remedy: str = ""

    # Hebrew renderings, used by the Telegram reporter. EXPLICIT FIELDS rather
    # than a lookup keyed on the English title: a translation table matched by
    # string breaks silently the moment someone rewords a title, and the report
    # quietly reverts to English without anyone noticing why.
    title_he: str = ""
    detail_he: str = ""
    remedy_he: str = ""

    def say(self, field: str, lang: str) -> str:
        """The field in `lang`, falling back to English rather than to blank.

        A missing translation must degrade to a readable English line, never to
        an empty one — a finding with no title is a finding nobody can act on.
        """
        if lang == "he":
            translated = getattr(self, f"{field}_he", "")
            if translated:
                return translated
        return getattr(self, field, "")

    def __post_init__(self):
        if self.verdict is Verdict.FAIL and not (self.detail or self.evidence):
            # A failure nobody can act on is noise, and noise trains people to
            # ignore the report — which costs more than the check is worth.
            raise ValueError(
                f"{self.check}: a FAIL must carry detail or evidence")


@dataclass
class CheckResult:
    """Everything one check produced."""
    name: str
    findings: list[Finding] = field(default_factory=list)
    duration_s: float = 0.0

    @property
    def worst(self) -> Verdict:
        for v in (Verdict.FAIL, Verdict.UNKNOWN, Verdict.WARN, Verdict.PASS):
            if any(f.verdict is v for f in self.findings):
                return v
        return Verdict.SKIP
