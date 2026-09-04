"""
health.py
---------
Does the project still hold together: is its suite green, does CI run it, is
the work actually pushed, and is anything obviously worth improving.

The order matters. A green suite that no CI runs is a suite that only protects
whoever remembered to run it — which is how a repo with 282 passing tests and
an autonomous agent pushing to it twice a day had nothing verifying either.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..manifest import Manifest
from ..verdict import CheckResult, Finding, Severity, Verdict
from .base import run, timer, which

NAME = "health"

# `Ran N tests` (unittest) or `N passed` (pytest).
_COUNT_RE = re.compile(r"Ran (\d+) tests?|(\d+) passed")


def _test_count(output: str) -> int | None:
    best = None
    for m in _COUNT_RE.finditer(output):
        n = int(m.group(1) or m.group(2))
        best = n if best is None else max(best, n)
    return best


def _tests(m: Manifest, findings: list[Finding]) -> None:
    cmd = m.commands.get("tests")
    if not cmd:
        findings.append(Finding(
            check=NAME, title="The project has an automated test suite",
            verdict=Verdict.WARN, severity=Severity.HIGH,
            detail="no [commands].tests in the manifest, so nothing here can "
                   "run or count them",
            remedy='Add `tests = "..."` under [commands] in SENTINEL.toml.'))
        return

    r = run(str(cmd), m.root, timeout_s=int(m.commands.get("tests_timeout_s", 900)))
    if r.error:
        findings.append(Finding(
            check=NAME, title="The test suite runs and passes",
            verdict=Verdict.UNKNOWN, severity=Severity.CRITICAL,
            detail=f"could not run the suite: {r.error}", evidence=r.output,
            remedy=f"Check that `{cmd}` works from the project root."))
        return

    count = _test_count(r.output)
    if not r.ok:
        findings.append(Finding(
            check=NAME, title="The test suite runs and passes",
            verdict=Verdict.FAIL, severity=Severity.CRITICAL,
            detail=f"`{cmd}` exited {r.exit_code}",
            evidence=r.output[-2000:],
            remedy="Fix the failures before anything else in this report."))
    else:
        findings.append(Finding(
            check=NAME, title="The test suite runs and passes",
            verdict=Verdict.PASS, severity=Severity.CRITICAL,
            detail=f"{count if count is not None else 'an unknown number of'} "
                   f"tests, all green"))

    # A green run that collected nothing is the trap this exists for: both
    # `unittest discover` and `pytest` exit 0 when they find no tests, so a
    # broken collection reports success forever.
    floor = m.commands.get("min_tests")
    if floor is None:
        findings.append(Finding(
            check=NAME, title="The suite is actually collecting its tests",
            verdict=Verdict.WARN, severity=Severity.MEDIUM,
            detail="no [commands].min_tests, so a collection that silently "
                   "drops to zero would still report success",
            remedy="Set min_tests to a floor comfortably below the real count."))
    elif count is None:
        findings.append(Finding(
            check=NAME, title="The suite is actually collecting its tests",
            verdict=Verdict.UNKNOWN, severity=Severity.MEDIUM,
            detail="could not find a test count in the output",
            evidence=r.output[-800:],
            remedy="Use a runner that prints 'Ran N tests' or 'N passed'."))
    elif count < int(floor):
        findings.append(Finding(
            check=NAME, title="The suite is actually collecting its tests",
            verdict=Verdict.FAIL, severity=Severity.HIGH,
            detail=f"collected {count}, floor is {floor} — collection is broken, "
                   f"and a suite that collects nothing still exits 0",
            evidence=r.output[-800:],
            remedy="Fix discovery. A green pipeline running zero tests is worse "
                   "than no pipeline."))
    else:
        findings.append(Finding(
            check=NAME, title="The suite is actually collecting its tests",
            verdict=Verdict.PASS, severity=Severity.MEDIUM,
            detail=f"collected {count} (floor {floor})"))


def _ci(m: Manifest, findings: list[Finding]) -> None:
    wf_dir = m.root / ".github" / "workflows"
    workflows = sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml")) \
        if wf_dir.is_dir() else []
    if not workflows:
        findings.append(Finding(
            check=NAME, title="CI runs the test suite automatically",
            verdict=Verdict.WARN, severity=Severity.HIGH,
            detail="no GitHub Actions workflows at all",
            remedy="Add a workflow that runs the suite on every push."))
        return

    runner = re.compile(r"pytest|unittest|npm (run )?test|go test|cargo test")
    running = [w.name for w in workflows
               if runner.search(w.read_text(encoding="utf-8", errors="ignore"))]
    if running:
        findings.append(Finding(
            check=NAME, title="CI runs the test suite automatically",
            verdict=Verdict.PASS, severity=Severity.HIGH,
            detail=f"{', '.join(running)}"))
    else:
        findings.append(Finding(
            check=NAME, title="CI runs the test suite automatically",
            verdict=Verdict.FAIL, severity=Severity.HIGH,
            detail=f"{len(workflows)} workflow(s), none of which runs tests",
            evidence=", ".join(w.name for w in workflows),
            remedy="A suite nobody runs automatically only protects whoever "
                   "remembered to run it."))


def _ci_status(m: Manifest, findings: list[Finding]) -> None:
    if not which("gh"):
        findings.append(Finding(
            check=NAME, title="The latest CI run is green",
            verdict=Verdict.UNKNOWN, severity=Severity.MEDIUM,
            detail="the `gh` CLI is not installed, so the real run status "
                   "cannot be read",
            remedy="Install and authenticate the GitHub CLI."))
        return
    r = run("gh run list --limit 1 --json conclusion,workflowName,url "
            "--jq '.[0] | \"\\(.conclusion)|\\(.workflowName)|\\(.url)\"'",
            m.root, timeout_s=60)
    if r.error or not r.ok or not r.stdout.strip():
        findings.append(Finding(
            check=NAME, title="The latest CI run is green",
            verdict=Verdict.UNKNOWN, severity=Severity.MEDIUM,
            detail="could not read run history from GitHub",
            evidence=(r.error or r.output)[:400],
            remedy="Check `gh auth status` and that this repo has a remote."))
        return
    parts = r.stdout.strip().split("|")
    conclusion = parts[0] if parts else ""

    # A run still in progress has no conclusion yet, and `gh --jq` renders that
    # as the string "null". Calling it a failure is wrong twice over: it is not
    # broken, and the audit itself is usually what triggered the run it is now
    # judging. UNKNOWN is the honest answer — nobody knows yet.
    if conclusion in ("null", "", "unknown", "None"):
        findings.append(Finding(
            check=NAME, title="The latest CI run is green",
            verdict=Verdict.UNKNOWN, severity=Severity.MEDIUM,
            detail="the latest run has not finished, so there is no result yet",
            evidence=r.stdout.strip(),
            remedy="Re-run the audit once CI settles."))
        return

    if conclusion == "success":
        findings.append(Finding(
            check=NAME, title="The latest CI run is green",
            verdict=Verdict.PASS, severity=Severity.MEDIUM,
            detail=f"{parts[1] if len(parts) > 1 else 'workflow'} succeeded"))
    else:
        findings.append(Finding(
            check=NAME, title="The latest CI run is green",
            verdict=Verdict.FAIL, severity=Severity.HIGH,
            detail=f"latest run concluded '{conclusion or 'unknown'}'",
            evidence=r.stdout.strip(),
            remedy="Open the run and fix it."))


def _git(m: Manifest, findings: list[Finding]) -> None:
    st = run("git status --porcelain", m.root, timeout_s=60)
    if st.error or not st.ok:
        findings.append(Finding(
            check=NAME, title="Work is committed, not sitting in the tree",
            verdict=Verdict.UNKNOWN, severity=Severity.LOW,
            detail="git status failed", evidence=(st.error or st.output)[:400],
            remedy="Run sentinel inside a git repository."))
        return
    dirty = [l for l in st.stdout.splitlines() if l.strip()]
    if dirty:
        findings.append(Finding(
            check=NAME, title="Work is committed, not sitting in the tree",
            verdict=Verdict.WARN, severity=Severity.LOW,
            detail=f"{len(dirty)} uncommitted change(s)",
            evidence="\n".join(dirty[:15]),
            remedy="Commit or discard them. Uncommitted work is not backed up."))
    else:
        findings.append(Finding(
            check=NAME, title="Work is committed, not sitting in the tree",
            verdict=Verdict.PASS, severity=Severity.LOW,
            detail="clean tree"))

    ahead = run("git rev-list --count @{u}..HEAD", m.root, timeout_s=60)
    if ahead.error or not ahead.ok:
        findings.append(Finding(
            check=NAME, title="Committed work is pushed to the remote",
            verdict=Verdict.UNKNOWN, severity=Severity.LOW,
            detail="no upstream branch, or git could not compare",
            evidence=(ahead.error or ahead.output)[:300],
            remedy="Set an upstream: git push -u origin <branch>."))
        return
    n = int(ahead.stdout.strip() or 0)
    if n:
        findings.append(Finding(
            check=NAME, title="Committed work is pushed to the remote",
            verdict=Verdict.WARN, severity=Severity.LOW,
            detail=f"{n} commit(s) exist only on this machine",
            evidence=ahead.stdout.strip(), remedy="git push"))
    else:
        findings.append(Finding(
            check=NAME, title="Committed work is pushed to the remote",
            verdict=Verdict.PASS, severity=Severity.LOW,
            detail="up to date with the remote"))


def _improvements(m: Manifest, findings: list[Finding]) -> None:
    """Opportunities, never failures. These are prompts for a human, and the
    verdict reflects that: nothing here is broken."""
    root = m.root
    notes: list[str] = []

    if not any((root / n).is_file() for n in ("README.md", "README.rst", "README")):
        notes.append("no README — a project nobody can pick up is a project "
                     "only its author can maintain")

    todos = run("git grep -nEI '(TODO|FIXME|XXX|HACK)' -- . | head -400",
                root, timeout_s=60)
    if todos.ok and todos.stdout.strip():
        n = len([l for l in todos.stdout.splitlines() if l.strip()])
        if n > 30:
            notes.append(f"{n} TODO/FIXME markers — enough that they have "
                         f"stopped being a list and become wallpaper")

    if not m.purpose:
        notes.append("the manifest has no `purpose` — the report cannot say "
                     "what this project is for")

    if notes:
        findings.append(Finding(
            check=NAME, title="Improvement opportunities",
            verdict=Verdict.WARN, severity=Severity.LOW,
            detail=f"{len(notes)} suggestion(s)",
            evidence="\n".join(f"- {n}" for n in notes),
            remedy="None of these is broken; they are worth a look when there "
                   "is time."))
    else:
        findings.append(Finding(
            check=NAME, title="Improvement opportunities",
            verdict=Verdict.PASS, severity=Severity.LOW,
            detail="nothing obvious"))


def check(m: Manifest) -> CheckResult:
    findings: list[Finding] = []
    with timer() as t:
        for step in (_tests, _ci, _ci_status, _git, _improvements):
            try:
                step(m, findings)
            except Exception as ex:                        # noqa: BLE001
                findings.append(Finding(
                    check=NAME, title=f"health step {step.__name__}",
                    verdict=Verdict.UNKNOWN, severity=Severity.MEDIUM,
                    detail=f"the check raised {type(ex).__name__}: {ex}",
                    remedy="This is a bug in sentinel, not in the project."))
    return CheckResult(name=NAME, findings=findings, duration_s=t.seconds)
