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

from .. import history
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
            check=NAME, title="The project has an automated test suite", title_he="לפרויקט יש חבילת טסטים אוטומטית",
            verdict=Verdict.WARN, severity=Severity.HIGH,
            detail="no [commands].tests in the manifest, so nothing here can "
                   "run or count them",
            remedy='Add `tests = "..."` under [commands] in SENTINEL.toml.'))
        return

    r = run(str(cmd), m.root, timeout_s=int(m.commands.get("tests_timeout_s", 900)))
    if r.error:
        findings.append(Finding(
            check=NAME, title="The test suite runs and passes", title_he="חבילת הטסטים רצה ועוברת",
            verdict=Verdict.UNKNOWN, severity=Severity.CRITICAL,
            detail=f"could not run the suite: {r.error}", evidence=r.output,
            remedy=f"Check that `{cmd}` works from the project root."))
        return

    count = _test_count(r.output)
    if not r.ok:
        findings.append(Finding(
            check=NAME, title="The test suite runs and passes", title_he="חבילת הטסטים רצה ועוברת",
            verdict=Verdict.FAIL, severity=Severity.CRITICAL,
            detail=f"`{cmd}` exited {r.exit_code}",
            evidence=r.output[-2000:],
            remedy="Fix the failures before anything else in this report."))
    else:
        findings.append(Finding(
            check=NAME, title="The test suite runs and passes", title_he="חבילת הטסטים רצה ועוברת",
            verdict=Verdict.PASS, severity=Severity.CRITICAL,
            detail=f"{count if count is not None else 'an unknown number of'} "
                   f"tests, all green"))

    # A green run that collected nothing is the trap this exists for: both
    # `unittest discover` and `pytest` exit 0 when they find no tests, so a
    # broken collection reports success forever.
    floor = m.commands.get("min_tests")
    if floor is None:
        findings.append(Finding(
            check=NAME, title="The suite is actually collecting its tests", title_he="החבילה באמת אוספת את הטסטים שלה",
            verdict=Verdict.WARN, severity=Severity.MEDIUM,
            detail="no [commands].min_tests, so a collection that silently "
                   "drops to zero would still report success",
            remedy="Set min_tests to a floor comfortably below the real count."))
    elif count is None:
        findings.append(Finding(
            check=NAME, title="The suite is actually collecting its tests", title_he="החבילה באמת אוספת את הטסטים שלה",
            verdict=Verdict.UNKNOWN, severity=Severity.MEDIUM,
            detail="could not find a test count in the output",
            evidence=r.output[-800:],
            remedy="Use a runner that prints 'Ran N tests' or 'N passed'."))
    elif count < int(floor):
        findings.append(Finding(
            check=NAME, title="The suite is actually collecting its tests", title_he="החבילה באמת אוספת את הטסטים שלה",
            verdict=Verdict.FAIL, severity=Severity.HIGH,
            detail=f"collected {count}, floor is {floor} — collection is broken, "
                   f"and a suite that collects nothing still exits 0",
            evidence=r.output[-800:],
            remedy="Fix discovery. A green pipeline running zero tests is worse "
                   "than no pipeline."))
    else:
        findings.append(Finding(
            check=NAME, title="The suite is actually collecting its tests", title_he="החבילה באמת אוספת את הטסטים שלה",
            verdict=Verdict.PASS, severity=Severity.MEDIUM,
            detail=f"collected {count} (floor {floor})"))


def _ci(m: Manifest, findings: list[Finding]) -> None:
    wf_dir = m.root / ".github" / "workflows"
    workflows = sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml")) \
        if wf_dir.is_dir() else []
    if not workflows:
        findings.append(Finding(
            check=NAME, title="CI runs the test suite automatically", title_he="ה-CI מריץ את הטסטים אוטומטית",
            verdict=Verdict.WARN, severity=Severity.HIGH,
            detail="no GitHub Actions workflows at all",
            remedy="Add a workflow that runs the suite on every push."))
        return

    runner = re.compile(r"pytest|unittest|npm (run )?test|go test|cargo test")
    running = [w.name for w in workflows
               if runner.search(w.read_text(encoding="utf-8", errors="ignore"))]
    if running:
        findings.append(Finding(
            check=NAME, title="CI runs the test suite automatically", title_he="ה-CI מריץ את הטסטים אוטומטית",
            verdict=Verdict.PASS, severity=Severity.HIGH,
            detail=f"{', '.join(running)}"))
    else:
        findings.append(Finding(
            check=NAME, title="CI runs the test suite automatically", title_he="ה-CI מריץ את הטסטים אוטומטית",
            verdict=Verdict.FAIL, severity=Severity.HIGH,
            detail=f"{len(workflows)} workflow(s), none of which runs tests",
            evidence=", ".join(w.name for w in workflows),
            remedy="A suite nobody runs automatically only protects whoever "
                   "remembered to run it."))


def _ci_status(m: Manifest, findings: list[Finding]) -> None:
    if not which("gh"):
        findings.append(Finding(
            check=NAME, title="The latest CI run is green", title_he="ההרצה האחרונה של ה-CI ירוקה",
            verdict=Verdict.UNKNOWN, severity=Severity.MEDIUM,
            detail="the `gh` CLI is not installed, so the real run status "
                   "cannot be read",
            detail_he="ה-CLI של gh לא מותקן, אז אי אפשר לקרוא את מצב ההרצה",
            remedy="Install and authenticate the GitHub CLI.",
            remedy_he="התקן ואמת את ה-CLI של GitHub."))
        return
    # THE RUN THAT ASKS IS NOT THE RUN TO JUDGE. `--limit 1` returns the most
    # recent run, which — when this check runs inside CI — is the audit
    # currently executing. It has no conclusion yet, so the check reported
    # "has not finished" every single time: a question that could never be
    # answered, asked twice a day. It was 9 of the first 10 reports, and the
    # recurring-finding warning is what surfaced it.
    #
    # So: ask for FINISHED runs only, and skip anything still in progress.
    # `--status completed` is the server-side filter; the client-side skip
    # covers a run that finishes between the two.
    r = run("gh run list --limit 10 --status completed "
            "--json conclusion,workflowName,url,status "
            "--jq '[.[] | select(.status == \"completed\")][0] "
            "| \"\\(.conclusion)|\\(.workflowName)|\\(.url)\"'",
            m.root, timeout_s=60)
    if r.error or not r.ok or not r.stdout.strip():
        findings.append(Finding(
            check=NAME, title="The latest CI run is green", title_he="ההרצה האחרונה של ה-CI ירוקה",
            verdict=Verdict.UNKNOWN, severity=Severity.MEDIUM,
            detail="could not read run history from GitHub",
            detail_he="לא הצלחתי לקרוא את היסטוריית ההרצות מ-GitHub",
            evidence=(r.error or r.output)[:400],
            remedy="Check `gh auth status`, that this repo has a remote, and "
                   "that GH_TOKEN is available if this is running in CI.",
            remedy_he="בדוק gh auth status, שיש remote לריפו, ושיש GH_TOKEN אם זה רץ ב-CI."))
        return
    parts = r.stdout.strip().split("|")
    conclusion = parts[0] if parts else ""

    # A run still in progress has no conclusion yet, and `gh --jq` renders that
    # as the string "null". Calling it a failure is wrong twice over: it is not
    # broken, and the audit itself is usually what triggered the run it is now
    # judging. UNKNOWN is the honest answer — nobody knows yet.
    if conclusion in ("null", "", "unknown", "None"):
        findings.append(Finding(
            check=NAME, title="The latest CI run is green", title_he="ההרצה האחרונה של ה-CI ירוקה",
            verdict=Verdict.UNKNOWN, severity=Severity.MEDIUM,
            detail="the latest run has not finished, so there is no result yet",
            evidence=r.stdout.strip(),
            remedy="Re-run the audit once CI settles."))
        return

    if conclusion == "success":
        findings.append(Finding(
            check=NAME, title="The latest CI run is green", title_he="ההרצה האחרונה של ה-CI ירוקה",
            verdict=Verdict.PASS, severity=Severity.MEDIUM,
            detail=f"{parts[1] if len(parts) > 1 else 'workflow'} succeeded"))
    else:
        findings.append(Finding(
            check=NAME, title="The latest CI run is green", title_he="ההרצה האחרונה של ה-CI ירוקה",
            verdict=Verdict.FAIL, severity=Severity.HIGH,
            detail=f"latest run concluded '{conclusion or 'unknown'}'",
            evidence=r.stdout.strip(),
            remedy="Open the run and fix it."))


def _git(m: Manifest, findings: list[Finding]) -> None:
    st = run("git status --porcelain", m.root, timeout_s=60)
    if st.error or not st.ok:
        findings.append(Finding(
            check=NAME, title="Work is committed, not sitting in the tree", title_he="העבודה מקובעת, לא יושבת בעץ",
            verdict=Verdict.UNKNOWN, severity=Severity.LOW,
            detail="git status failed", evidence=(st.error or st.output)[:400],
            remedy="Run sentinel inside a git repository."))
        return
    dirty = [l for l in st.stdout.splitlines() if l.strip()]
    if dirty:
        findings.append(Finding(
            check=NAME, title="Work is committed, not sitting in the tree", title_he="העבודה מקובעת, לא יושבת בעץ",
            verdict=Verdict.WARN, severity=Severity.LOW,
            detail=f"{len(dirty)} uncommitted change(s)",
            evidence="\n".join(dirty[:15]),
            remedy="Commit or discard them. Uncommitted work is not backed up."))
    else:
        findings.append(Finding(
            check=NAME, title="Work is committed, not sitting in the tree", title_he="העבודה מקובעת, לא יושבת בעץ",
            verdict=Verdict.PASS, severity=Severity.LOW,
            detail="clean tree"))

    ahead = run("git rev-list --count @{u}..HEAD", m.root, timeout_s=60)
    if ahead.error or not ahead.ok:
        findings.append(Finding(
            check=NAME, title="Committed work is pushed to the remote", title_he="העבודה המקובעת נדחפה לשרת",
            verdict=Verdict.UNKNOWN, severity=Severity.LOW,
            detail="no upstream branch, or git could not compare",
            evidence=(ahead.error or ahead.output)[:300],
            remedy="Set an upstream: git push -u origin <branch>."))
        return
    n = int(ahead.stdout.strip() or 0)
    if n:
        findings.append(Finding(
            check=NAME, title="Committed work is pushed to the remote", title_he="העבודה המקובעת נדחפה לשרת",
            verdict=Verdict.WARN, severity=Severity.LOW,
            detail=f"{n} commit(s) exist only on this machine",
            evidence=ahead.stdout.strip(), remedy="git push"))
    else:
        findings.append(Finding(
            check=NAME, title="Committed work is pushed to the remote", title_he="העבודה המקובעת נדחפה לשרת",
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
            check=NAME, title="Improvement opportunities", title_he="הזדמנויות לשיפור",
            verdict=Verdict.WARN, severity=Severity.LOW,
            detail=f"{len(notes)} suggestion(s)",
            evidence="\n".join(f"- {n}" for n in notes),
            remedy="None of these is broken; they are worth a look when there "
                   "is time."))
    else:
        findings.append(Finding(
            check=NAME, title="Improvement opportunities", title_he="הזדמנויות לשיפור",
            verdict=Verdict.PASS, severity=Severity.LOW,
            detail="nothing obvious"))


def _recurring(m: Manifest, findings: list[Finding]) -> None:
    """What the owner has now been told several times, and is still true.

    The audit that ran an hour ago cannot tell you it is the fourteenth time it
    said the same thing. This can, and that sequence is the most valuable
    signal the system produces: a finding repeated for a week is a failure of
    the SYSTEM — either nobody is acting on it, or it is not really a problem
    and the report has been crying wolf daily. Both are worth knowing.
    """
    # Only what THIS audit still reports. A finding fixed yesterday would
    # otherwise keep being warned about for another month, from history alone.
    open_now = {(f.check, f.title) for f in findings
                if f.verdict in (Verdict.FAIL, Verdict.UNKNOWN)}
    repeats = history.recurring(m.root, still_open=open_now)
    # Carry each finding's Hebrew title across, so the warning names them in
    # the language the report is written in.
    for r in repeats:
        for report in history.load(m.root, limit=5):
            for f in report.get("findings") or []:
                if (f.get("check"), f.get("title")) == (r["check"], r["title"]):
                    r["title_he"] = f.get("title_he") or ""
                    break
    if not repeats:
        findings.append(Finding(
            check=NAME, title="No finding keeps being reported unresolved",
            title_he="אין ממצא שחוזר שוב ושוב בלי שנפתר",
            verdict=Verdict.PASS, severity=Severity.MEDIUM,
            detail="nothing has been reported five times running",
            detail_he="שום דבר לא דווח חמש פעמים ברציפות"))
        return

    # NAME THEM. The first live warning said only "1 finding reported 5+ times"
    # and left the reader to go and look — which is the same defect the warning
    # exists to catch, one level up: a message that costs work to act on gets
    # skipped. The Hebrew title is preferred, since that is the report's
    # language.
    lines = [f"{r.get('title_he') or r['title']} — דווח {r['count']} פעמים"
             for r in repeats]
    findings.append(Finding(
        check=NAME, title="No finding keeps being reported unresolved",
        title_he="אין ממצא שחוזר שוב ושוב בלי שנפתר",
        verdict=Verdict.WARN, severity=Severity.HIGH,
        detail=f"{len(repeats)} finding(s) reported 5+ times and still open",
        detail_he=f"{len(repeats)} ממצאים דווחו 5 פעמים או יותר ועדיין פתוחים",
        evidence="\n".join(lines[:8]),
        remedy="Either fix them, or decide they are not problems and stop "
               "reporting them. A finding repeated daily and never acted on "
               "trains the reader to ignore the whole report.",
        remedy_he="או לתקן אותם, או להחליט שהם לא בעיה ולהפסיק לדווח עליהם. "
                  "ממצא שחוזר כל יום ואף אחד לא נוגע בו מלמד את הקורא "
                  "להתעלם מכל הדוח."))


def _never_passed(m: Manifest, findings: list[Finding]) -> None:
    """Checks that have run and never once passed — a symptom of the CHECK.

    Different question from `_recurring`. That one asks "is this still open",
    and a long-standing real problem answers yes honestly. This asks "has this
    ever worked at all", and a no points at the check rather than the project.
    """
    stuck = history.never_passed(m.root)
    if not stuck:
        findings.append(Finding(
            check=NAME, title="Every check has passed at least once",
            title_he="כל בדיקה עברה לפחות פעם אחת",
            verdict=Verdict.PASS, severity=Severity.MEDIUM,
            detail="no check is permanently stuck",
            detail_he="אין בדיקה שתקועה לצמיתות"))
        return
    findings.append(Finding(
        check=NAME, title="Every check has passed at least once",
        title_he="כל בדיקה עברה לפחות פעם אחת",
        verdict=Verdict.WARN, severity=Severity.HIGH,
        detail=f"{len(stuck)} check(s) have never passed — suspect the check, "
               f"not the project",
        detail_he=f"{len(stuck)} בדיקות מעולם לא עברו — החשד הוא על הבדיקה, "
                  f"לא על הפרויקט",
        evidence="\n".join(
            f"{s.get('title_he') or s['title']} — {s['runs']} הרצות, אפס מעברים"
            for s in stuck[:6]),
        remedy="A check that never passes is usually asking a question that "
               "cannot be answered in the environment it runs in. Check what "
               "it looks like THERE, not where you are testing it from.",
        remedy_he="בדיקה שאף פעם לא עוברת בדרך כלל שואלת שאלה שאי אפשר לענות "
                  "עליה בסביבה שבה היא רצה. בדוק איך היא נראית שם, לא מהמקום "
                  "שממנו אתה בודק אותה."))


# Secrets GitHub provides on its own; a workflow naming these has nothing to
# configure.
_BUILTIN_SECRETS = {"GITHUB_TOKEN"}

_SECRET_REF = re.compile(r"secrets\.([A-Z_][A-Z0-9_]*)")

# What a run says when a credential a workflow asked for turned out to be
# empty. Checked only when the secret list itself cannot be read.
_MISSING_CREDENTIAL_SIGNS = (
    "Environment variable validation failed",
    "is required when using direct Anthropic API",
    "not installed on this repository",
)


def _secrets(m: Manifest, findings: list[Finding]) -> None:
    """Does every secret the workflows ask for actually exist here?

    A NEW REPOSITORY INHERITS NOTHING, and this is the second half of that
    lesson. sentinel's own improvement pass failed for three days on a missing
    GitHub App grant; the grant was given, and the very next run failed again
    because the repository had no secrets at all — the token the workflow reads
    lived in the other project, and secrets are per-repository too.

    The second failure was invisible while the first one stood. That is the
    shape worth naming: fixing one layer reveals the next, and a check that
    reads configuration rather than waiting for a run finds both at once.

    Secrets are write-only through the API, so nothing here ever sees a value —
    only whether a name is present.
    """
    title = "Every secret the workflows ask for exists in this repository"
    title_he = "כל סוד שהתהליכים מבקשים קיים בריפו הזה"

    wf_dir = m.root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return                      # no workflows, nothing to configure

    wanted: dict[str, list[str]] = {}
    for wf in sorted(wf_dir.glob("*.y*ml")):
        for name in _SECRET_REF.findall(wf.read_text(encoding="utf-8",
                                                     errors="ignore")):
            if name not in _BUILTIN_SECRETS:
                wanted.setdefault(name, []).append(wf.name)
    if not wanted:
        return

    if not which("gh"):
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he,
            verdict=Verdict.UNKNOWN, severity=Severity.HIGH,
            detail=f"{len(wanted)} secret(s) are referenced, and without the "
                   f"`gh` CLI there is no way to see whether they are set",
            detail_he=f"{len(wanted)} סודות נדרשים, ובלי ה-CLI של gh אין דרך "
                      f"לראות אם הם מוגדרים",
            evidence=", ".join(sorted(wanted)),
            remedy="Install and authenticate the GitHub CLI.",
            remedy_he="התקן ואמת את ה-CLI של GitHub."))
        return

    r = run("gh secret list --json name --jq '.[].name'", m.root, timeout_s=60)
    if r.ok and r.stdout.strip():
        have = set(r.stdout.split())
    elif r.ok:
        have = set()                # authenticated, and the list is empty
    else:
        # Listing secrets needs admin on the repository, which the token
        # inside CI does not have. Fall back to what a run can still show:
        # whether the latest completed run died complaining about one.
        _secrets_from_run_history(m, findings, wanted, title, title_he,
                                  r.output)
        return

    # A secret the project has DECLARED optional is a different thing from one
    # it forgot. stock-predictor reads two newsletters over IMAP and works
    # without them by falling back to the public RSS feed — it says so in the
    # prompt. Reporting that as a high-severity failure every day would be the
    # false positive this tool is least able to afford: a scanner that cries
    # wolf gets muted, and a muted scanner looks like coverage.
    #
    # So the declaration is honoured, and the cost is still printed. PASS with
    # what is degraded named in the detail, rather than a warning nobody can
    # close or a silence that hides it.
    optional = {str(n) for n in (m.security.get("optional_secrets") or [])}
    missing = sorted(n for n in wanted if n not in have)
    absent_optional = sorted(n for n in missing if n in optional)
    missing = [n for n in missing if n not in optional]

    if not missing:
        detail = f"all {len(wanted) - len(absent_optional)} required "
        detail += "secret(s) are set"
        detail_he = f"כל {len(wanted) - len(absent_optional)} הסודות הנדרשים מוגדרים"
        if absent_optional:
            detail += (f"; {len(absent_optional)} declared optional and unset, "
                       f"so whatever they feed is running degraded: "
                       + ", ".join(absent_optional))
            detail_he += (f"; {len(absent_optional)} מוצהרים כאופציונליים "
                          f"ואינם מוגדרים, אז מה שהם מזינים פועל חלקית: "
                          + ", ".join(absent_optional))
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he, verdict=Verdict.PASS,
            severity=Severity.HIGH, detail=detail, detail_he=detail_he))
        return

    findings.append(Finding(
        check=NAME, title=title, title_he=title_he, verdict=Verdict.FAIL,
        severity=Severity.HIGH,
        detail=f"{len(missing)} secret(s) a workflow reads are not set here",
        detail_he=f"{len(missing)} סודות שתהליך קורא אינם מוגדרים כאן",
        evidence="\n".join(f"{n} — read by {', '.join(sorted(set(wanted[n])))}"
                           for n in missing),
        remedy="Set each one with `gh secret set <NAME>`. Secrets do not "
               "travel between repositories, and a workflow reading one that "
               "is unset fails at the step that needs it, not at startup.",
        remedy_he="הגדר כל אחד עם gh secret set <שם>. סודות לא עוברים בין "
                  "ריפואים, ותהליך שקורא סוד שאינו מוגדר נכשל בשלב שצריך "
                  "אותו ולא בהתחלה."))


def _secrets_from_run_history(m: Manifest, findings: list[Finding],
                              wanted: dict[str, list[str]], title: str,
                              title_he: str, why_not: str) -> None:
    """Second best: did the last completed run complain about a credential?

    Reactive rather than preventive — it needs a failure to have happened —
    but it is what remains when the secret list is unreadable, which is the
    case inside CI where this check usually runs.
    """
    r = run("gh run list --limit 1 --status completed "
            "--json databaseId,conclusion "
            "--jq '.[0] | select(.conclusion == \"failure\") | .databaseId'",
            m.root, timeout_s=60)
    if r.ok and not r.stdout.strip():
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he,
            verdict=Verdict.UNKNOWN, severity=Severity.MEDIUM,
            detail="the secret list needs repository admin, which this token "
                   "does not have; the latest run did not fail, so nothing "
                   "contradicts the secrets being set — which is not the same "
                   "as having checked them",
            detail_he="רשימת הסודות דורשת הרשאת אדמין שאין לטוקן הזה; ההרצה "
                      "האחרונה לא נכשלה, אז שום דבר לא סותר שהסודות מוגדרים — "
                      "וזה לא אותו דבר כמו לבדוק אותם",
            evidence=why_not[:300],
            remedy="Run the audit from a machine whose `gh` is authenticated "
                   "as the repository owner to check this properly.",
            remedy_he="הרץ את הביקורת ממכונה שה-gh שלה מאומת כבעל הריפו."))
        return
    if not r.ok or not r.stdout.strip():
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he,
            verdict=Verdict.UNKNOWN, severity=Severity.HIGH,
            detail="could not read the secret list or the run history",
            detail_he="לא הצלחתי לקרוא את רשימת הסודות ולא את היסטוריית ההרצות",
            evidence=why_not[:300],
            remedy="Check `gh auth status` and that this repo has a remote.",
            remedy_he="בדוק gh auth status ושיש remote לריפו."))
        return

    run_id = r.stdout.strip().splitlines()[0]
    log = run(f"gh run view {run_id} --log-failed", m.root, timeout_s=120)
    hit = next((s for s in _MISSING_CREDENTIAL_SIGNS if s in log.output), None)
    if hit:
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he, verdict=Verdict.FAIL,
            severity=Severity.HIGH,
            detail="the latest run failed complaining that a credential it "
                   "needed was not available",
            detail_he="ההרצה האחרונה נכשלה בטענה שסוד שהיא צריכה אינו זמין",
            evidence=f"run {run_id}: {hit}\nreferenced: "
                     + ", ".join(sorted(wanted)),
            remedy="Set the secret with `gh secret set <NAME>`. Secrets and "
                   "app grants are both per-repository — a new repo inherits "
                   "neither.",
            remedy_he="הגדר את הסוד עם gh secret set <שם>. גם סודות וגם "
                      "הרשאות אפליקציה הם לכל ריפו בנפרד — ריפו חדש לא יורש "
                      "אף אחד מהם."))
        return
    findings.append(Finding(
        check=NAME, title=title, title_he=title_he,
        verdict=Verdict.UNKNOWN, severity=Severity.MEDIUM,
        detail="the secret list needs repository admin, which this token does "
               "not have, and the latest failure was about something else",
        detail_he="רשימת הסודות דורשת הרשאת אדמין שאין לטוקן הזה, והכשל "
                  "האחרון היה על משהו אחר",
        evidence=why_not[:300],
        remedy="Run the audit from a machine whose `gh` is authenticated as "
               "the repository owner to check this properly.",
        remedy_he="הרץ את הביקורת ממכונה שה-gh שלה מאומת כבעל הריפו."))


# ── claude-code-action: three ways to get it wrong ─────────────────────
#
# WHY THESE LIVE HERE AND NOT IN A MANIFEST. They started as expectations in
# stock-predictor's SENTINEL.toml, written after each mistake was made there.
# sentinel runs the same action, in a workflow written later, and was covered
# by NONE of them — so the project whose job is catching repeated mistakes was
# the one repeating them unguarded.
#
# L020 says a mistake that recurs across files is one to check rather than
# remember. Recurring across PROJECTS is the same lesson one level up, and the
# answer is the same: the check moves to where every project gets it.

_ACTION = "claude-code-action"
_GIT_WRITE = re.compile(r"^\s*git (add|commit|push)\b", re.M)


def _claude_action(m: Manifest, findings: list[Finding]) -> None:
    wf_dir = m.root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return
    users = []
    for wf in sorted(wf_dir.glob("*.y*ml")):
        text = wf.read_text(encoding="utf-8", errors="ignore")
        if _ACTION in text:
            users.append((wf.name, text))
    if not users:
        return

    # 1. OIDC. The action authenticates with a GitHub OIDC token, so a job that
    #    cannot mint one fails BEFORE Claude starts — after installing every
    #    dependency, with an error naming OIDC and nothing about what is
    #    missing. Made twice: improve.yml, then market-news.yml.
    no_oidc = [name for name, text in users
               if not re.search(r"^\s*id-token:\s*write", text, re.M)]
    findings.append(_action_finding(
        no_oidc, "Every workflow using claude-code-action grants id-token: write",
        "כל תהליך שמשתמש ב-claude-code-action מעניק id-token: write",
        len(users),
        "Add `id-token: write` to that workflow's `permissions:` block.",
        "הוסף id-token: write לבלוק ה-permissions של התהליך."))

    # 2. CREDENTIALS. The action revokes its own app token when it finishes, so
    #    every later git step fails with "Authentication failed" — after the
    #    work is done, throwing away a finished run's output at the last
    #    moment. Made three times. It only matters if the workflow writes with
    #    git afterwards, so that is the condition.
    no_restore = [name for name, text in users
                  if _GIT_WRITE.search(text)
                  and "Restore git credentials" not in text]
    findings.append(_action_finding(
        no_restore,
        "Every workflow running claude-code-action then using git restores its credentials",
        "כל תהליך שמריץ את claude-code-action ואז משתמש ב-git משחזר את האישורים",
        len(users),
        "Add a step after the action that resets origin's URL with "
        "x-access-token and secrets.GITHUB_TOKEN, and give it `if: always()` "
        "so a failed pass still commits what it had.",
        "הוסף שלב אחרי הפעולה שמאפס את כתובת origin עם x-access-token "
        "ו-secrets.GITHUB_TOKEN, עם if: always()."))

    # 3. THE MODEL. Nothing failed here — which is the point. An undeclared
    #    model means whatever the account default happens to be does the work,
    #    so a change of default silently changes what writes a daily message or
    #    edits this repository, with no diff recording it.
    no_model = [name for name, text in users if "--model" not in text]
    findings.append(_action_finding(
        no_model, "Every claude-code-action step declares which model runs it",
        "כל שלב של claude-code-action מצהיר איזה מודל מריץ אותו",
        len(users),
        "Add `--model <name>` to that step's `claude_args`. An undeclared "
        "model is an undeclared dependency: it works until the default moves, "
        "and then the output changes for no reason anyone can find.",
        "הוסף --model <שם> ל-claude_args של השלב. מודל לא מוצהר הוא תלות לא "
        "מוצהרת — הוא עובד עד שברירת המחדל זזה, ואז הפלט משתנה בלי סיבה "
        "שאפשר לאתר.",
        severity=Severity.MEDIUM))


def _action_finding(offenders, title, title_he, total, remedy, remedy_he,
                    severity=Severity.HIGH) -> Finding:
    if not offenders:
        return Finding(
            check=NAME, title=title, title_he=title_he, verdict=Verdict.PASS,
            severity=severity,
            detail=f"all {total} workflow(s) using the action",
            detail_he=f"כל {total} התהליכים שמשתמשים בפעולה")
    return Finding(
        check=NAME, title=title, title_he=title_he, verdict=Verdict.FAIL,
        severity=severity,
        detail=f"{len(offenders)} of {total} workflow(s) using the action do not",
        detail_he=f"{len(offenders)} מתוך {total} תהליכים לא",
        evidence="\n".join(offenders),
        remedy=remedy, remedy_he=remedy_he)


def check(m: Manifest) -> CheckResult:
    findings: list[Finding] = []
    with timer() as t:
        # _recurring reads `findings` as it goes, so every check whose result
        # it filters against must already have run. Order is load-bearing here.
        for step in (_tests, _ci, _ci_status, _secrets, _claude_action, _git,
                     _recurring, _never_passed, _improvements):
            try:
                step(m, findings)
            except Exception as ex:                        # noqa: BLE001
                findings.append(Finding(
                    check=NAME, title=f"health step {step.__name__}",
                    verdict=Verdict.UNKNOWN, severity=Severity.MEDIUM,
                    detail=f"the check raised {type(ex).__name__}: {ex}",
                    remedy="This is a bug in sentinel, not in the project."))
    return CheckResult(name=NAME, findings=findings, duration_s=t.seconds)
