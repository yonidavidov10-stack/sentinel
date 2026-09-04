"""
intent.py
---------
Checks the promises in SENTINEL.toml. This is the check the tool exists for.

A test suite verifies the PARTS. It cannot verify the PROMISE, because the
promise usually lives outside the process: a report reaching a chat app, a
scheduled job actually firing, a file still being written to. The
stock-predictor's suite was green for the whole three days its daily report
silently stopped going out — every part worked, and the thing the project is
FOR did not happen.

So each expectation here is a sentence the project wrote about itself, plus a
mechanical way to find out whether it is still true.
"""

from __future__ import annotations

import json
import re
import warnings
from datetime import datetime, timezone
from pathlib import Path

from ..manifest import Expectation, Manifest
from ..verdict import CheckResult, Finding, Severity, Verdict
from .base import Run, run, timer

NAME = "intent"


def _sev(e: Expectation) -> Severity:
    return Severity(e.severity)


def _unknown(e: Expectation, why: str, evidence: str = "") -> Finding:
    """The honest outcome when a promise could not be tested.

    Never a pass. A promise nobody checked is exactly as unverified as a
    promise that failed, and the report says so.
    """
    return Finding(check=NAME, title=e.says, title_he=e.says_he, verdict=Verdict.UNKNOWN,
                   severity=_sev(e), detail=why, evidence=evidence,
                   remedy=f"Make expectation '{e.id}' runnable, or remove it.")


# ── the kinds ──────────────────────────────────────────────────────────
def _check_command(e: Expectation, root: Path) -> Finding:
    cmd = e.config.get("run")
    if not cmd:
        return _unknown(e, "kind='command' needs a `run` key")

    r: Run = run(str(cmd), root, timeout_s=int(e.config.get("timeout_s", 300)))
    if r.error:
        return _unknown(e, f"could not run: {r.error}", r.output)

    # A check that CANNOT run where it is running must not report a pass.
    # `launchctl list | grep -q ...` succeeds trivially on Linux, where there
    # is no launchd at all — so an expectation about "nothing is scheduled on
    # the Mac" would go green in CI while checking nothing. The command signals
    # that itself with a dedicated exit code, and it becomes UNKNOWN.
    unknown_exit = e.config.get("unknown_exit")
    if unknown_exit is not None and r.exit_code == int(unknown_exit):
        return _unknown(
            e, e.config.get("unknown_reason")
               or f"the command exited {unknown_exit}, its signal for "
                  f"'cannot be checked here'",
            r.output)

    problems: list[str] = []

    expected_exit = e.config.get("expect_exit", 0)
    if expected_exit is not None and r.exit_code != int(expected_exit):
        problems.append(f"exit {r.exit_code}, expected {expected_exit}")

    for needle in e.config.get("expect_stdout_contains") or []:
        if str(needle) not in r.output:
            problems.append(f"output is missing {needle!r}")

    for needle in e.config.get("expect_stdout_absent") or []:
        if str(needle) in r.output:
            problems.append(f"output contains {needle!r}, which it must not")

    if problems:
        return Finding(check=NAME, title=e.says, title_he=e.says_he, verdict=Verdict.FAIL,
                       severity=_sev(e), detail="; ".join(problems),
                       evidence=r.output, remedy=e.config.get("remedy", ""),
                   remedy_he=e.config.get("remedy_he", ""))
    return Finding(check=NAME, title=e.says, title_he=e.says_he, verdict=Verdict.PASS,
                   severity=_sev(e), detail=f"`{cmd}` behaved as promised")


def _age_hours(stamp: str) -> float | None:
    try:
        ts = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - ts).total_seconds() / 3600.0


def _check_freshness(e: Expectation, root: Path) -> Finding:
    """Did the thing that is supposed to happen regularly actually happen?

    THE CHECK THAT WOULD HAVE CAUGHT 2026-08-29. Nothing was broken in a way a
    test could see; a scheduled job simply stopped producing output, and the
    silence looked exactly like everything being fine.
    """
    rel = e.config.get("path")
    if not rel:
        return _unknown(e, "kind='freshness' needs a `path` key")
    max_age = e.config.get("max_age_hours")
    if max_age is None:
        return _unknown(e, "kind='freshness' needs `max_age_hours`")

    target = root / str(rel)
    if not target.exists():
        return Finding(check=NAME, title=e.says, title_he=e.says_he, verdict=Verdict.FAIL,
                       severity=_sev(e),
                       detail=f"{rel} does not exist at all",
                       evidence=str(target),
                       remedy=e.config.get("remedy", ""),
                   remedy_he=e.config.get("remedy_he", ""))

    field = e.config.get("field")
    if field:
        # A timestamp INSIDE the file. Preferred over mtime, which any
        # unrelated touch or checkout resets — git does exactly that, so on a
        # CI runner every file looks freshly written.
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as ex:
            return _unknown(e, f"could not read {rel}: {ex}")
        stamp = data
        for part in str(field).split("."):
            stamp = stamp.get(part) if isinstance(stamp, dict) else None
        age = _age_hours(stamp)
        if age is None:
            return _unknown(e, f"{rel}: field {field!r} is not a readable "
                               f"timestamp", evidence=repr(stamp)[:200])
        source = f"{rel}:{field} = {stamp}"
    else:
        age = (datetime.now(timezone.utc).timestamp()
               - target.stat().st_mtime) / 3600.0
        source = f"{rel} mtime"

    if age > float(max_age):
        return Finding(
            check=NAME, title=e.says, title_he=e.says_he, verdict=Verdict.FAIL, severity=_sev(e),
            detail=f"last updated {age:.1f}h ago; the promise is every "
                   f"{max_age}h",
            evidence=source, remedy=e.config.get("remedy", ""),
                   remedy_he=e.config.get("remedy_he", ""))
    return Finding(check=NAME, title=e.says, title_he=e.says_he, verdict=Verdict.PASS,
                   severity=_sev(e),
                   detail=f"updated {age:.1f}h ago (limit {max_age}h)")


def _check_file_exists(e: Expectation, root: Path) -> Finding:
    rel = e.config.get("path")
    if not rel:
        return _unknown(e, "kind='file_exists' needs a `path` key")
    if (root / str(rel)).exists():
        return Finding(check=NAME, title=e.says, title_he=e.says_he, verdict=Verdict.PASS,
                       severity=_sev(e), detail=f"{rel} is present")
    return Finding(check=NAME, title=e.says, title_he=e.says_he, verdict=Verdict.FAIL,
                   severity=_sev(e), detail=f"{rel} is missing",
                   evidence=str(root / str(rel)),
                   remedy=e.config.get("remedy", ""),
                   remedy_he=e.config.get("remedy_he", ""))


def _check_file_absent(e: Expectation, root: Path) -> Finding:
    rel = e.config.get("path")
    if not rel:
        return _unknown(e, "kind='file_absent' needs a `path` key")
    if not (root / str(rel)).exists():
        return Finding(check=NAME, title=e.says, title_he=e.says_he, verdict=Verdict.PASS,
                       severity=_sev(e), detail=f"{rel} is absent, as promised")
    return Finding(check=NAME, title=e.says, title_he=e.says_he, verdict=Verdict.FAIL,
                   severity=_sev(e), detail=f"{rel} exists and must not",
                   evidence=str(root / str(rel)),
                   remedy=e.config.get("remedy", ""),
                   remedy_he=e.config.get("remedy_he", ""))


# Reading a .pyc with errors="ignore" turns compiled bytecode into a string
# that can match almost any pattern. The very first audit reported three hits
# where grep found two — the third was a __pycache__ artefact of one of the
# other two. A scanner that invents a match is worse than one that misses,
# because the false one gets investigated.
_SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules",
              ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build",
              ".tox", ".idea", ".DS_Store"}
_TEXT_SUFFIXES = {".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".bash", ".zsh",
                  ".yml", ".yaml", ".toml", ".json", ".md", ".txt", ".cfg",
                  ".ini", ".html", ".css", ".sql", ".rb", ".go", ".rs", ""}

# Built rather than written literally, so this file can be patched by scripts
# that use triple-quoted strings without the markers closing them.
_COMMENT_START = ("#", "//", "*", "--", "<!--", chr(34) * 3, chr(39) * 3)


def _scannable(p: Path) -> bool:
    if not p.is_file():
        return False
    if any(part in _SKIP_DIRS for part in p.parts):
        return False
    return p.suffix.lower() in _TEXT_SUFFIXES


def _check_grep(e: Expectation, root: Path) -> Finding:
    pattern = e.config.get("pattern")
    if not pattern:
        return _unknown(e, "kind='grep' needs a `pattern` key")
    paths = e.config.get("paths") or ["."]
    must_exist = bool(e.config.get("must_match", True))

    # A pattern Python WARNS about does not mean what its author thinks. The
    # first manifest written with this kind used POSIX classes — `[[:space:]]`
    # — which Python parses as a nested set and merely warns about. The
    # expectation went green while matching nothing at all: it passed for the
    # wrong reason, which is the failure mode this whole tool exists to catch.
    # So a warning is promoted to UNKNOWN, loudly.
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            rx = re.compile(str(pattern))
        except re.error as ex:
            return _unknown(e, f"pattern is not a valid regex: {ex}")
    if caught:
        return _unknown(
            e,
            f"the regex compiles but Python warns about it: "
            f"{caught[0].message}. A pattern that does not mean what it looks "
            f"like will silently match nothing and report success.",
            evidence=f"pattern: {pattern}")

    # `ignore_comments` matters more than it looks. The first real expectation
    # written with this kind — "hit rate is never scored against a target" —
    # failed on two COMMENTS explaining that the target had been retired. An
    # expectation that trips over its own documentation gets disabled, and a
    # disabled expectation is a promise nobody is checking.
    ignore_comments = bool(e.config.get("ignore_comments", False))

    hits: list[str] = []
    for rel in paths:
        target = root / str(rel)
        files = ([target] if target.is_file()
                 else sorted(p for p in target.rglob("*") if _scannable(p)))
        for f in files[:2000]:
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if ignore_comments and line.strip().startswith(_COMMENT_START):
                    continue
                if rx.search(line):
                    hits.append(f"{f.relative_to(root)}:{lineno}: {line.strip()[:160]}")
                    if len(hits) >= 20:
                        break
            if len(hits) >= 20:
                break

    found = bool(hits)
    if found == must_exist:
        return Finding(check=NAME, title=e.says, title_he=e.says_he, verdict=Verdict.PASS,
                       severity=_sev(e),
                       detail=(f"{len(hits)} match(es), as promised" if must_exist
                               else "no matches, as promised"))
    return Finding(
        check=NAME, title=e.says, title_he=e.says_he, verdict=Verdict.FAIL, severity=_sev(e),
        detail=("expected the pattern to appear and it does not" if must_exist
                else f"the pattern appears {len(hits)} time(s) and must not"),
        evidence="\n".join(hits[:10]) or f"pattern: {pattern}",
        remedy=e.config.get("remedy", ""),
                   remedy_he=e.config.get("remedy_he", ""))


def _check_schedule_after(e: Expectation, root: Path) -> Finding:
    """A workflow that CHECKS must run after the workflow that CHANGES.

    THE DEFECT THIS EXISTS FOR, in full, because it is easy to make again:
    the audit workflow was scheduled at 06:00 UTC "after the daily run". The
    self-improvement daemon edits and pushes code at 06:40. So the audit
    inspected the repository forty minutes BEFORE the thing most likely to
    break it. A pass that broke something at 06:40 went unreported until 06:00
    the next day — twenty-three hours — and the 04:30 daily run used the broken
    code first.

    Nothing was misconfigured in a way any linter would see. Both workflows
    were valid, both ran, both were green. The ORDER was wrong, and order is
    invisible unless something looks at it.

    Passing means one of two things, and both are real fixes:
      * the checker is triggered by `workflow_run` on the writer — it follows
        the daemon rather than guessing at the clock; or
      * every one of the checker's cron times is later in the day than every
        one of the writer's.
    """
    checker = e.config.get("checker")
    writer = e.config.get("writer")
    if not checker or not writer:
        return _unknown(e, "kind='schedule_after' needs `checker` and `writer` "
                           "workflow filenames")

    wf = root / ".github" / "workflows"
    c_path, w_path = wf / str(checker), wf / str(writer)
    for path in (c_path, w_path):
        if not path.is_file():
            return _unknown(e, f"no such workflow: {path.name}",
                            evidence=str(path))

    c_text = c_path.read_text(encoding="utf-8", errors="ignore")
    w_text = w_path.read_text(encoding="utf-8", errors="ignore")

    # `workflow_run` is the strong form: it cannot drift out of order, because
    # it has no clock of its own.
    w_name = re.search(r"^name:\s*(.+)$", w_text, re.M)
    w_name = w_name.group(1).strip().strip('"\'') if w_name else ""
    if "workflow_run" in c_text and (not w_name or w_name in c_text):
        return Finding(check=NAME, title=e.says, title_he=e.says_he, verdict=Verdict.PASS,
                       severity=_sev(e),
                       detail=f"{checker} is triggered by {writer} finishing, "
                              f"so it cannot drift out of order")

    def minutes(text: str) -> list[int]:
        out = []
        for m in re.finditer(r'cron:\s*["\']?\s*(\S+)\s+(\S+)\s', text):
            mi, hr = m.group(1), m.group(2)
            if mi.isdigit() and hr.isdigit():
                out.append(int(hr) * 60 + int(mi))
        return out

    c_times, w_times = minutes(c_text), minutes(w_text)
    if not c_times or not w_times:
        return _unknown(
            e, f"could not read a cron time from "
               f"{checker if not c_times else writer}, and there is no "
               f"workflow_run link either")

    if min(c_times) > max(w_times):
        return Finding(check=NAME, title=e.says, title_he=e.says_he, verdict=Verdict.PASS,
                       severity=_sev(e),
                       detail=f"{checker} runs after {writer} every day")

    def hhmm(t):
        return f"{t // 60:02d}:{t % 60:02d}"
    return Finding(
        check=NAME, title=e.says, title_he=e.says_he, verdict=Verdict.FAIL, severity=_sev(e),
        detail=f"{checker} runs at {', '.join(hhmm(t) for t in sorted(c_times))} "
               f"but {writer} runs at {', '.join(hhmm(t) for t in sorted(w_times))} "
               f"— so the check happens BEFORE the change it is meant to catch",
        evidence=f"{checker}: {sorted(hhmm(t) for t in c_times)}\n"
                 f"{writer}:  {sorted(hhmm(t) for t in w_times)}",
        remedy_he=e.config.get("remedy_he", ""), remedy=e.config.get("remedy") or
               f"Trigger {checker} with `workflow_run` on {writer}, or move its "
               f"cron later than every one of {writer}'s.")


_HANDLERS = {
    "schedule_after": _check_schedule_after,
    "command": _check_command,
    "freshness": _check_freshness,
    "file_exists": _check_file_exists,
    "file_absent": _check_file_absent,
    "grep": _check_grep,
}


def check(m: Manifest) -> CheckResult:
    findings: list[Finding] = []

    # Manifest problems are findings too. A promise that fell out of the audit
    # because of a typo is worse than one that failed, because nothing says so.
    for err in m.errors:
        findings.append(Finding(
            check=NAME, title="The manifest itself is well-formed",
            verdict=Verdict.WARN, severity=Severity.HIGH,
            detail=err, remedy=f"Fix {m.path.name}."))

    if not m.expectations:
        findings.append(Finding(
            check=NAME, title="The project states what it is supposed to do",
            verdict=Verdict.WARN, severity=Severity.HIGH,
            detail="no [[expectations]] in the manifest — nothing about this "
                   "project's actual purpose is being verified",
            remedy="Add at least one expectation describing a promise this "
                   "project makes."))

    with timer() as t:
        for e in m.expectations:
            handler = _HANDLERS.get(e.kind)
            if handler is None:
                findings.append(_unknown(
                    e, f"unknown kind {e.kind!r}; known kinds: "
                       f"{', '.join(sorted(_HANDLERS))}"))
                continue
            try:
                findings.append(handler(e, m.root))
            except Exception as ex:                        # noqa: BLE001
                # A crashing handler must not take the audit down, and must not
                # quietly drop the promise either.
                findings.append(_unknown(
                    e, f"the check itself raised {type(ex).__name__}: {ex}"))

    return CheckResult(name=NAME, findings=findings, duration_s=t.seconds)
