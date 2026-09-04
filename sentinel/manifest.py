"""
manifest.py
-----------
`SENTINEL.toml` — a project's own statement of what it is supposed to do.

WHY A MANIFEST AND NOT INFERENCE
--------------------------------
An auditor that guesses what a project is for will audit the wrong thing
confidently. What a repo *is supposed to do* is not recoverable from its
source: nothing in the stock-predictor's code says "a Telegram report must
reach its owner every trading day", and that is precisely the promise that
broke on 2026-08-29 and went unnoticed for three days. Tests were green
throughout. The suite verified the parts; nothing verified the promise.

So each project writes its promises down, in its own words, and the auditor
checks those. The manifest is documentation that fails when it stops being
true.

THE RULE THAT MAKES IT TRUSTWORTHY
----------------------------------
An expectation the runner cannot execute reports UNKNOWN — loudly. It is never
dropped and never treated as a pass. A typo in a `kind` would otherwise remove
a promise from the audit while the report stayed green, which is the same trap
as a CI step that collects zero tests and exits 0.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

MANIFEST_NAME = "SENTINEL.toml"

# Every expectation kind the runner knows. A manifest naming anything else is a
# manifest with a hole in it, and `Expectation.known` says so rather than the
# loader silently discarding the entry.
KINDS = {"command", "freshness", "file_exists", "file_absent", "grep",
         "schedule_after"}

SEVERITIES = {"critical", "high", "medium", "low"}


@dataclass
class Expectation:
    """One promise the project makes, and how to check it."""
    id: str
    says: str                       # the promise, in plain language
    kind: str
    why: str = ""                   # why it matters, for the report
    severity: str = "medium"
    config: dict = field(default_factory=dict)
    # Optional Hebrew rendering of the promise, for reports sent in Hebrew.
    # A project writes `says_he` beside `says`; nothing else changes.
    says_he: str = ""

    @property
    def known(self) -> bool:
        return self.kind in KINDS


@dataclass
class Manifest:
    path: Path
    name: str
    purpose: str
    expectations: list[Expectation] = field(default_factory=list)
    commands: dict = field(default_factory=dict)
    security: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def root(self) -> Path:
        return self.path.parent


class ManifestError(Exception):
    pass


def _require(table: dict, key: str, where: str):
    if key not in table:
        raise ManifestError(f"{where}: missing required key {key!r}")
    return table[key]


def load(project_root: Path) -> Manifest:
    """Read SENTINEL.toml. Raises ManifestError if the file cannot be trusted.

    Structural problems raise. Problems with a single expectation are collected
    into `errors` and the expectation is KEPT with its bad kind, so the runner
    reports it as UNKNOWN instead of the audit quietly shrinking.
    """
    path = Path(project_root) / MANIFEST_NAME
    if not path.is_file():
        raise ManifestError(f"no {MANIFEST_NAME} in {project_root}")

    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise ManifestError(f"{path} is not valid TOML: {e}") from None

    project = raw.get("project")
    if not isinstance(project, dict):
        raise ManifestError(f"{path}: missing [project] table")

    errors: list[str] = []
    expectations: list[Expectation] = []
    seen_ids: set[str] = set()

    for i, item in enumerate(raw.get("expectations") or []):
        where = f"{path}: expectation #{i + 1}"
        if not isinstance(item, dict):
            errors.append(f"{where}: not a table")
            continue
        try:
            eid = str(_require(item, "id", where))
            says = str(_require(item, "says", where))
            kind = str(_require(item, "kind", where))
        except ManifestError as e:
            errors.append(str(e))
            continue

        # A duplicate id means one of them silently overwrites the other in any
        # report keyed by id, and the reader is short a promise without knowing.
        if eid in seen_ids:
            errors.append(f"{where}: duplicate id {eid!r}")
            continue
        seen_ids.add(eid)

        severity = str(item.get("severity", "medium"))
        if severity not in SEVERITIES:
            errors.append(f"{where}: unknown severity {severity!r}, using 'medium'")
            severity = "medium"

        if kind not in KINDS:
            errors.append(
                f"{where}: unknown kind {kind!r} — this promise will be "
                f"reported UNKNOWN, not skipped")

        config = {k: v for k, v in item.items()
                  if k not in ("id", "says", "says_he", "kind", "why",
                               "severity")}
        expectations.append(Expectation(
            id=eid, says=says, kind=kind, why=str(item.get("why", "")),
            severity=severity, config=config,
            says_he=str(item.get("says_he", ""))))

    return Manifest(
        path=path,
        name=str(project.get("name") or project_root.resolve().name),
        purpose=str(project.get("purpose", "")).strip(),
        expectations=expectations,
        commands=raw.get("commands") or {},
        security=raw.get("security") or {},
        errors=errors,
    )


def discover(search_root: Path, max_depth: int = 3) -> list[Path]:
    """Every directory under `search_root` holding a SENTINEL.toml."""
    search_root = Path(search_root)
    found: list[Path] = []
    if (search_root / MANIFEST_NAME).is_file():
        found.append(search_root)
    for depth in range(1, max_depth + 1):
        pattern = "/".join(["*"] * depth) + "/" + MANIFEST_NAME
        for m in search_root.glob(pattern):
            root = m.parent
            if root not in found:
                found.append(root)
    return found
