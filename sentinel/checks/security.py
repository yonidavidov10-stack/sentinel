"""
security.py
-----------
The holes that actually cost people: secrets committed to a repo, and a few
patterns that turn a bug into a breach.

DELIBERATELY NARROW. A scanner that cries wolf gets muted, and a muted scanner
is worse than none because it looks like coverage. So it checks TRACKED files
only — what git actually carries is what leaks — and every pattern here is one
with a low false-positive rate and a real consequence.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from ..manifest import Manifest
from ..verdict import CheckResult, Finding, Severity, Verdict
from .base import run, timer, which

NAME = "security"

# Shapes that are almost never anything but a live credential.
SECRET_PATTERNS = [
    (r"sk-ant-[A-Za-z0-9_\-]{20,}", "Anthropic API key"),
    (r"sk-[A-Za-z0-9]{32,}", "OpenAI-style API key"),
    (r"gh[pousr]_[A-Za-z0-9]{30,}", "GitHub token"),
    (r"github_pat_[A-Za-z0-9_]{30,}", "GitHub fine-grained PAT"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    (r"\b[0-9]{8,10}:AA[A-Za-z0-9_\-]{30,}", "Telegram bot token"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "private key"),
    (r"xox[baprs]-[A-Za-z0-9\-]{10,}", "Slack token"),
]

# Files that should never be tracked, whatever else is going on.
NEVER_TRACK = [".env", ".env.local", ".env.production", "secrets.toml",
               ".streamlit/secrets.toml", "id_rsa", "credentials.json",
               "service-account.json"]

# Code patterns with a real consequence. Each carries WHY, because a finding
# whose reason a reader has to guess gets dismissed.
RISKY_CODE = [
    # `(?<![.\w])` — NOT a method call. `model.eval()` and `self.eval()` are
    # PyTorch's inference-mode switch and appear in every torch codebase; the
    # first real audit flagged two of them, which is exactly how a scanner
    # earns its way into a mute filter. The builtin is never preceded by a dot.
    (r"(?<![.\w])eval\s*\(", "eval() executes whatever reaches it", Severity.HIGH),
    (r"(?<![.\w])exec\s*\(", "exec() executes whatever reaches it", Severity.HIGH),
    (r"pickle\.loads?\s*\(", "pickle deserialisation is arbitrary code execution",
     Severity.HIGH),
    (r"verify\s*=\s*False", "TLS verification disabled — the connection is "
     "encrypted but unauthenticated, so it can be intercepted", Severity.HIGH),
    (r"debug\s*=\s*True", "a debug server exposes an interactive console",
     Severity.MEDIUM),
    (r"host\s*=\s*[\"']0\.0\.0\.0[\"']", "binds every interface, not just "
     "localhost", Severity.MEDIUM),
]

TEXT_SUFFIXES = {".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".bash", ".zsh",
                 ".yml", ".yaml", ".toml", ".json", ".md", ".txt", ".cfg",
                 ".ini", ".env", ".html", ".css", ".sql", ".rb", ".go", ".rs"}


# ── threat 1: someone else gets in ─────────────────────────────────────

_USES = re.compile(r"^\s*-?\s*uses:\s*([^\s@]+)@([^\s#]+)", re.M)
_SHA = re.compile(r"^[0-9a-f]{40}$")
# GitHub's own namespaces. Still a pointer, still movable, but a different risk
# class from a community action, and worth saying separately.
_FIRST_PARTY = ("actions/", "github/", "anthropics/")

# A workflow that interpolates attacker-controllable text straight into a shell
# is the classic Actions RCE: a branch or issue title becomes a command.
_UNTRUSTED = re.compile(
    r"\$\{\{\s*github\.(event\.|head_ref)[^}]*\}\}")


def _actions_are_pinned(m: Manifest, findings: list[Finding]) -> None:
    """A tag is a pointer its owner can move. A SHA is a version.

    `uses: actions/checkout@v4` does not name code. It names a label that the
    action's owner can repoint at any commit, which then runs inside the job
    holding `contents: write` and every secret that job has.

    This REPORTS rather than demands. Pinning to a SHA stops security patches
    arriving on their own, so something must update them — a real trade, and
    the owner's to make. A finding that names the cost is honest; one that
    insists on a default is not.
    """
    title = "Third-party actions are pinned to a commit, not a movable tag"
    title_he = "פעולות צד-שלישי מוצמדות לקומיט, לא לתגית שאפשר להזיז"

    wf = m.root / ".github" / "workflows"
    if not wf.is_dir():
        return
    tagged_third, tagged_first = [], []
    for f in sorted(wf.glob("*.y*ml")):
        for action, ref in _USES.findall(f.read_text(encoding="utf-8",
                                                     errors="ignore")):
            if _SHA.match(ref):
                continue
            where = f"{f.name}: {action}@{ref}"
            (tagged_first if action.startswith(_FIRST_PARTY)
             else tagged_third).append(where)

    if not tagged_third and not tagged_first:
        # PINNING WITHOUT AN UPDATE PATH MAKES THINGS WORSE, not better. A
        # pinned action stays exactly as it was, including its
        # vulnerabilities, and "we will remember to update it" is not a
        # control — it is the absence of one, wearing the costume.
        #
        # So a fully pinned project only PASSES if something is watching for
        # new versions. Otherwise the finding flips: the tags are gone and so
        # is every future security patch.
        dependabot = any((m.root / ".github" / n).is_file()
                         for n in ("dependabot.yml", "dependabot.yaml"))
        if dependabot:
            findings.append(Finding(
                check=NAME, title=title, title_he=title_he,
                verdict=Verdict.PASS, severity=Severity.MEDIUM,
                detail="every action is pinned to a commit SHA, and "
                       "dependabot watches for new versions",
                detail_he="כל פעולה מוצמדת ל-SHA, ו-dependabot עוקב אחרי "
                          "גרסאות חדשות"))
            return
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he, verdict=Verdict.WARN,
            severity=Severity.MEDIUM,
            detail="every action is pinned to a commit SHA, and nothing is "
                   "watching for updates — so these versions, and their "
                   "vulnerabilities, are now frozen indefinitely",
            detail_he="כל פעולה מוצמדת ל-SHA, ושום דבר לא עוקב אחרי עדכונים — "
                      "כלומר הגרסאות האלה, והפגיעויות שבהן, קפואות ללא הגבלה",
            remedy="Add `.github/dependabot.yml` with the `github-actions` "
                   "ecosystem. It opens a pull request when a new version "
                   "appears, so the SHA is changed by a person reading a "
                   "changelog instead of by a tag moving underneath.",
            remedy_he="הוסף .github/dependabot.yml עם github-actions. הוא "
                      "פותח PR כשיוצאת גרסה חדשה, כך שה-SHA משתנה על ידי אדם "
                      "שקורא changelog ולא על ידי תגית שזזה מתחתיך."))
        return

    if tagged_third:
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he, verdict=Verdict.WARN,
            severity=Severity.HIGH,
            detail=f"{len(tagged_third)} third-party action(s) run from a tag "
                   f"their author can repoint at any commit",
            detail_he=f"{len(tagged_third)} פעולות צד-שלישי רצות מתגית "
                      f"שהמחבר שלהן יכול להזיז לכל קומיט",
            evidence="\n".join(tagged_third[:10]),
            remedy="Replace the tag with the commit SHA it currently points "
                   "at, and add the version as a comment. Note the cost: a "
                   "pinned action stops receiving security patches, so "
                   "something has to update it.",
            remedy_he="החלף את התגית ב-SHA שהיא מצביעה אליו כרגע, עם הגרסה "
                      "בהערה. שים לב למחיר: פעולה מוצמדת מפסיקה לקבל עדכוני "
                      "אבטחה, אז מישהו צריך לעדכן אותה.",
        needs_owner=True,
        owner_reason_he="עריכת .github/workflows אסורה לפאס — אחרת הוא יכול להרחיב לעצמו הרשאות"))
        return

    findings.append(Finding(
        check=NAME, title=title, title_he=title_he, verdict=Verdict.WARN,
        severity=Severity.LOW,
        detail=f"{len(tagged_first)} first-party action(s) run from a tag — a "
               f"smaller risk than a community action, and still a pointer "
               f"rather than a version",
        detail_he=f"{len(tagged_first)} פעולות של הבית רצות מתגית — סיכון קטן "
                  f"מפעולה קהילתית, ועדיין מצביע ולא גרסה",
        evidence="\n".join(tagged_first[:10]),
        remedy="Worth pinning if these jobs hold secrets that matter. Decide "
               "once, and write the decision down rather than leaving it to "
               "whoever edits the workflow next.",
        remedy_he="שווה להצמיד אם למשימות האלה יש סודות שחשובים. תחליט פעם "
                  "אחת, ותכתוב את ההחלטה.",
        needs_owner=True,
        owner_reason_he="עריכת .github/workflows אסורה לפאס — אחרת הוא יכול להרחיב לעצמו הרשאות"))


def _no_untrusted_input_in_shell(m: Manifest, findings: list[Finding]) -> None:
    """A branch name or issue title reaching a `run:` block is a shell command.

    Measured clean on 2026-09-13 across both projects. It stays checked because
    the day it stops being true is the day someone adds a workflow that reacts
    to a pull request, and that is exactly when nobody is looking for this.
    """
    title = "No attacker-controllable text is interpolated into a shell"
    title_he = "שום טקסט שתוקף שולט בו לא מוזרק לתוך shell"

    wf = m.root / ".github" / "workflows"
    if not wf.is_dir():
        return
    # BLOCK DETECTION BY INDENTATION, and the first version got it wrong in a
    # way that matters: it looked for a line starting with `run:`, and a step
    # is written `- run: |` — the dash comes first. So the opening line never
    # matched, the body lines were never inside a block, and the check reported
    # PASS on a workflow written to be vulnerable. It passed on both real
    # projects too, for the same reason: it was testing nothing.
    #
    # Only writing the failing case found it, which is the third time that has
    # been the only thing that would.
    hits = []
    for f in sorted(wf.glob("*.y*ml")):
        run_indent = None
        for lineno, line in enumerate(
                f.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())

            if run_indent is not None and stripped and indent <= run_indent:
                run_indent = None          # dedented out of the block

            opens = stripped.startswith("run:") or stripped.startswith("- run:")
            if opens:
                run_indent = indent
                if _UNTRUSTED.search(line):      # single-line `run: echo ...`
                    hits.append(f"{f.name}:{lineno}: {stripped[:120]}")
                continue

            if run_indent is not None and _UNTRUSTED.search(line):
                hits.append(f"{f.name}:{lineno}: {stripped[:120]}")

    if not hits:
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he, verdict=Verdict.PASS,
            severity=Severity.HIGH,
            detail="no workflow puts event data directly into a command",
            detail_he="אף תהליך לא מכניס נתוני אירוע ישירות לפקודה"))
        return

    findings.append(Finding(
        check=NAME, title=title, title_he=title_he, verdict=Verdict.FAIL,
        severity=Severity.CRITICAL,
        detail=f"{len(hits)} place(s) interpolate event data into a shell "
               f"command, where the text becomes part of the command itself",
        detail_he=f"{len(hits)} מקומות מזריקים נתוני אירוע לפקודת shell, "
                  f"והטקסט הופך לחלק מהפקודה",
        evidence="\n".join(hits[:10]),
        remedy="Pass it through `env:` and reference it as \"$VAR\" inside "
               "the script. The shell then treats it as a value; interpolation "
               "makes it code.",
        remedy_he="העבר דרך env: והשתמש ב-\"$VAR\" בתוך הסקריפט. אז ה-shell "
                  "מתייחס לזה כערך; הזרקה הופכת את זה לקוד.",
        needs_owner=True,
        owner_reason_he="עריכת .github/workflows אסורה לפאס — אחרת הוא יכול להרחיב לעצמו הרשאות"))


def _irreplaceable_has_a_second_copy(m: Manifest,
                                     findings: list[Finding]) -> None:
    """What cannot be recreated, and whether it exists in more than one place.

    THE MOST VALUABLE CONTROL AVAILABLE TO THESE PROJECTS, and not a firewall.

    stock-predictor's record — seventy predictions, forty-four lessons, months
    of daily snapshots — is a log of what happened on particular days at
    particular prices. Re-running the code does not reproduce it. It exists
    only in the GitHub repository, `main` cannot be branch-protected on a free
    private repo, and several unattended workflows hold `contents: write`.

    A project declares what is irreplaceable; nothing here guesses. Silence
    means the project has not answered the question, which is reported as
    UNKNOWN rather than passed over — "nobody said" is not "nothing matters".
    """
    title = "What cannot be recreated exists in more than one place"
    title_he = "מה שאי אפשר לשחזר קיים ביותר ממקום אחד"

    # `or []` HERE MADE THE REMEDY A LIE. It collapsed an absent key and a
    # declared empty list into the same falsy value, so a project that did
    # exactly what the remedy asks — write `irreplaceable = []`, meaning
    # "everything here regenerates" — was told again, every audit, that it had
    # not answered. Found 2026-09-24 on the first project where the honest
    # answer was genuinely nothing.
    #
    # It is this tool's own central distinction, broken in its own code:
    # "nobody looked" and "we looked and the answer is none" are different
    # facts, and only the first is actionable.
    declared = m.security.get("irreplaceable")
    if declared is not None and not declared:
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he,
            verdict=Verdict.SKIP, severity=Severity.HIGH,
            detail="declared: nothing here is irreplaceable — all of it "
                   "rebuilds from the code",
            detail_he="הוצהר: אין כאן דבר בלתי ניתן לשחזור — הכל נבנה מחדש "
                      "מהקוד"))
        return

    if not declared:
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he,
            verdict=Verdict.UNKNOWN, severity=Severity.HIGH,
            detail="the manifest does not say what in this project could not "
                   "be rebuilt from the code, so nothing can check whether it "
                   "would survive losing the remote",
            detail_he="המניפסט לא אומר מה בפרויקט הזה לא ניתן לבנות מחדש מהקוד, "
                      "אז אי אפשר לבדוק אם זה ישרוד אובדן של ה-remote",
            remedy="Add `irreplaceable = [...]` to [security], listing paths "
                   "whose loss would be permanent. An empty list is a valid "
                   "answer and means 'everything here regenerates' — say it "
                   "explicitly rather than by omission.",
            remedy_he="הוסף irreplaceable = [...] ל-[security], עם נתיבים "
                      "שאובדנם בלתי הפיך. רשימה ריקה היא תשובה תקפה ומשמעה "
                      "'הכל כאן נבנה מחדש' — אמור זאת במפורש."))
        return

    missing = [str(rel) for rel in declared if not (m.root / str(rel)).exists()]
    if missing:
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he, verdict=Verdict.FAIL,
            severity=Severity.CRITICAL,
            detail="a path declared irreplaceable is not here at all",
            detail_he="נתיב שהוצהר כבלתי ניתן לשחזור לא נמצא כאן בכלל",
            evidence="\n".join(missing),
            remedy="Either it moved and the manifest is stale, or it is gone. "
                   "Find out which before anything else.",
            remedy_he="או שהוא עבר והמניפסט מיושן, או שהוא אבד. ברר מה משניהם "
                      "לפני כל דבר אחר."))
        return

    copies = m.security.get("second_copy") or ""
    if not copies:
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he, verdict=Verdict.WARN,
            severity=Severity.CRITICAL,
            detail=f"{len(declared)} irreplaceable path(s), and no second copy "
                   f"declared — they exist only in this repository and in "
                   f"whatever it was cloned from",
            detail_he=f"{len(declared)} נתיבים בלתי ניתנים לשחזור, ואין עותק "
                      f"שני מוצהר — הם קיימים רק בריפו הזה ובמה שממנו שוכפל",
            evidence="\n".join(str(r) for r in declared[:10]),
            remedy="Decide where a second copy lives and record it as "
                   "`second_copy` in [security]. The point is not the file "
                   "format — it is a location a bad force-push cannot reach.",
            remedy_he="החלט איפה יושב עותק שני ורשום אותו כ-second_copy תחת "
                      "[security]. העיקר אינו הפורמט — אלא מקום שדחיפה כוחנית "
                      "שגויה לא מגיעה אליו.",
        needs_owner=True,
        owner_reason_he="החלטה איפה יישמר עותק שני — זו בחירה שלך, לא של כלי"))
        return

    # A second copy that is a PATH can be checked; one that is prose can only
    # be taken on trust. Both are accepted, and they are not the same finding.
    dest = Path(str(copies)).expanduser()
    if not dest.is_absolute():
        dest = m.root / dest
    max_age = int(m.security.get("second_copy_max_age_days", 45))

    if not any(ch in str(copies) for ch in "/\\"):
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he, verdict=Verdict.PASS,
            severity=Severity.HIGH,
            detail=f"{len(declared)} irreplaceable path(s), second copy: "
                   f"{copies} — described, not a path, so its freshness is "
                   f"taken on trust",
            detail_he=f"{len(declared)} נתיבים בלתי ניתנים לשחזור, עותק שני: "
                      f"{copies} — מתואר ולא נתיב, אז הטריות שלו בהנחה"))
        return

    # IN CI, A LOCAL PATH CAN NEVER BE REACHED, so the answer is SKIP, not
    # UNKNOWN. This is L037 applied to a sibling it should have covered on the
    # day it was written: the secrets check was moved to SKIP for exactly this
    # reason — a question a CI runner structurally cannot answer — and this one
    # was left reporting UNKNOWN from a machine that will never have the owner's
    # SSD plugged into it. Ten runs, zero passes, one line of noise in every
    # report.
    #
    # On the owner's machine an unplugged drive is still UNKNOWN below, because
    # there it genuinely might have been checked and was not.
    import os
    if os.environ.get("GITHUB_ACTIONS") == "true" and dest.is_absolute() \
            and not dest.exists():
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he,
            verdict=Verdict.SKIP, severity=Severity.MEDIUM,
            detail=f"the second copy is a local path ({copies}), which a CI "
                   f"runner can never reach — this is checked from the owner's "
                   f"machine",
            detail_he=f"העותק השני הוא נתיב מקומי ({copies}) ששרת CI לעולם לא "
                      f"יגיע אליו — זה נבדק מהמחשב של הבעלים"))
        return

    # AN UNPLUGGED DRIVE IS NOT A MISSING BACKUP. Reporting FAIL whenever the
    # SSD is not connected would fire on most days, mean nothing on any of
    # them, and teach its reader that this line is noise — which is how the one
    # finding that matters gets skimmed past.
    if not dest.exists():
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he,
            verdict=Verdict.UNKNOWN, severity=Severity.MEDIUM,
            detail=f"the second copy lives at {copies}, which is not reachable "
                   f"from here — an external drive that is not plugged in "
                   f"looks exactly like a backup that was never made, and this "
                   f"cannot tell them apart",
            detail_he=f"העותק השני נמצא ב-{copies}, שלא נגיש מכאן — כונן "
                      f"חיצוני שלא מחובר נראה בדיוק כמו גיבוי שמעולם לא נעשה, "
                      f"ואי אפשר להבחין ביניהם",
            remedy="Connect it and re-run to confirm. This is expected most "
                   "days; it is reported rather than hidden because 'I could "
                   "not look' is not 'it is fine'.",
            remedy_he="חבר אותו והרץ שוב. זה צפוי ברוב הימים; זה מדווח ולא "
                      "מוסתר כי 'לא יכולתי להסתכל' זה לא 'הכל בסדר'.",
        needs_owner=True,
        owner_reason_he="דיסק פיזי: אף תוכנה לא יכולה לחבר אותו בשבילך"))
        return

    entries = [d for d in dest.iterdir() if not d.name.startswith(".")]
    if not entries:
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he, verdict=Verdict.FAIL,
            severity=Severity.CRITICAL,
            detail=f"{copies} is reachable and empty — the destination exists "
                   f"and holds nothing",
            detail_he=f"{copies} נגיש וריק — היעד קיים ואין בו כלום",
            remedy="Take a snapshot now. An empty backup directory is the one "
                   "state worse than no directory, because it reads as "
                   "configured.",
            remedy_he="עשה תצלום עכשיו. תיקיית גיבוי ריקה היא המצב היחיד "
                      "שגרוע מאין תיקייה, כי היא נראית מוגדרת."))
        return

    newest = max(entries, key=lambda d: d.stat().st_mtime)
    age_days = (datetime.now(timezone.utc)
                - datetime.fromtimestamp(newest.stat().st_mtime, timezone.utc)
                ).days

    if age_days > max_age:
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he, verdict=Verdict.WARN,
            severity=Severity.HIGH,
            detail=f"the newest copy at {copies} is {age_days} days old, past "
                   f"the {max_age} declared — everything since exists in one "
                   f"place again",
            detail_he=f"העותק החדש ביותר ב-{copies} בן {age_days} ימים, מעבר "
                      f"ל-{max_age} שהוצהרו — כל מה שמאז קיים שוב במקום אחד",
            evidence=f"newest: {newest.name}",
            remedy="Take a fresh one. The gap between the last copy and now is "
                   "exactly what would be lost.",
            remedy_he="עשה חדש. הפער בין העותק האחרון לעכשיו הוא בדיוק מה "
                      "שיאבד."))
        return

    findings.append(Finding(
        check=NAME, title=title, title_he=title_he, verdict=Verdict.PASS,
        severity=Severity.HIGH,
        detail=f"{len(declared)} irreplaceable path(s); newest copy at "
               f"{copies} is {age_days} day(s) old ({newest.name})",
        detail_he=f"{len(declared)} נתיבים בלתי ניתנים לשחזור; העותק החדש "
                  f"ביותר ב-{copies} בן {age_days} ימים ({newest.name})"))


LEDGER = ".security/history.json"


def _history_is_append_only(m: Manifest, findings: list[Finding]) -> None:
    """Has anything rewritten history since the last audit?

    THE CONTROL THAT REPLACES BRANCH PROTECTION, which is not available here:
    GitHub refuses `required_status_checks` and force-push blocking on a
    private repository on a free plan, and these repositories hold a record
    that cannot be recreated. Several unattended workflows carry
    `contents: write`.

    It serves both threats at once, which is rare and is why it was built
    first. An intruder covering their tracks and an owner typing
    `git push --force` on the wrong branch produce the same evidence: a commit
    that used to be reachable from main no longer is.

    HOW STRONG THIS ACTUALLY IS, stated plainly. The ledger lives in the
    repository it describes, so anyone who can rewrite history can also rewrite
    the ledger and leave no trace. That makes it:

      * COMPLETE against accident — the overwhelmingly likely case, and the one
        with four days of evidence behind it in this project;
      * PARTIAL against an attacker — they must know to forge it, and the
        forgery is itself a commit in a file whose only job is to be boring.

    Real tamper-evidence needs a witness outside the repository. That is worth
    building and is not what this is.
    """
    title = "Nothing has rewritten the history of this repository"
    title_he = "שום דבר לא שכתב את ההיסטוריה של הריפו הזה"

    if not (m.root / ".git").exists():
        return

    ledger = m.root / LEDGER
    head = run("git rev-parse HEAD", m.root, timeout_s=30)
    count = run("git rev-list --count HEAD", m.root, timeout_s=60)
    if not head.ok or not count.ok:
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he,
            verdict=Verdict.UNKNOWN, severity=Severity.HIGH,
            detail="could not read this repository's history",
            detail_he="לא הצלחתי לקרוא את ההיסטוריה של הריפו",
            evidence=(head.error or count.error or head.output)[:300],
            remedy="Check that `git` is available and this is a repository.",
            remedy_he="בדוק ש-git זמין ושזה ריפו."))
        return

    now_sha = head.stdout.strip()
    now_count = int(count.stdout.strip() or 0)

    if not ledger.is_file():
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he,
            verdict=Verdict.UNKNOWN, severity=Severity.MEDIUM,
            detail=f"no history ledger yet, so there is no earlier state to "
                   f"compare against — the first audit can only record where "
                   f"things stand ({now_count} commits)",
            detail_he=f"אין עדיין יומן היסטוריה, אז אין מצב קודם להשוות אליו — "
                      f"הביקורת הראשונה רק רושמת את המצב ({now_count} קומיטים)",
            remedy=f"Run `python -m sentinel.cli record {m.root}` (or let the "
                   f"audit workflow do it) to write {LEDGER}, then commit it.",
            remedy_he=f"הרץ את פקודת הרישום כדי לכתוב {LEDGER}, ואז קומיט."))
        return

    try:
        was = json.loads(ledger.read_text(encoding="utf-8"))
        prev_sha = str(was["head"])
        prev_count = int(was["count"])
    except (OSError, ValueError, KeyError) as e:
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he,
            verdict=Verdict.UNKNOWN, severity=Severity.HIGH,
            detail=f"the history ledger is unreadable: {type(e).__name__}",
            detail_he=f"יומן ההיסטוריה לא קריא: {type(e).__name__}",
            remedy="Repair or regenerate it. An unreadable ledger checks "
                   "nothing, and is indistinguishable from a deleted one.",
            remedy_he="תקן או צור מחדש. יומן לא קריא לא בודק כלום, והוא נראה "
                      "בדיוק כמו יומן שנמחק."))
        return

    # THE QUESTION. Is the commit we last saw still reachable from HEAD? A
    # normal push only ever adds; a rewrite orphans what was there.
    reachable = run(f"git merge-base --is-ancestor {prev_sha} HEAD",
                    m.root, timeout_s=60)

    if reachable.exit_code == 0:
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he, verdict=Verdict.PASS,
            severity=Severity.HIGH,
            detail=f"the commit recorded last time is still in this history; "
                   f"{now_count - prev_count} commit(s) added since",
            detail_he=f"הקומיט שנרשם בפעם הקודמת עדיין בהיסטוריה; נוספו "
                      f"{now_count - prev_count} קומיטים מאז"))
        return

    # `git merge-base --is-ancestor` exits 1 for "no" and 128 for "I cannot
    # even look" — which happens once the orphaned commit has been garbage
    # collected and there is nothing left to compare against. Both are the same
    # verdict; only the wording differs, and the difference tells the reader
    # whether the old commits are still recoverable locally.
    #
    # The exact message was read out of git rather than guessed at: it is
    # "fatal: Not a valid commit name <sha>". Matching on a phrase invented
    # from memory is how a branch like this quietly stops being reached.
    unknown_object = (reachable.exit_code == 128
                      or "not a valid commit" in reachable.output.lower())
    findings.append(Finding(
        check=NAME, title=title, title_he=title_he, verdict=Verdict.FAIL,
        severity=Severity.CRITICAL,
        detail="a commit that was on this branch at the last audit is no "
               "longer reachable from it — history was rewritten, not extended"
               + (" (the commit no longer exists at all)" if unknown_object
                  else ""),
        detail_he="קומיט שהיה על הענף בביקורת הקודמת כבר לא ניתן להגעה ממנו — "
                  "ההיסטוריה שוכתבה, לא הורחבה"
                  + (" (הקומיט כבר לא קיים בכלל)" if unknown_object else ""),
        evidence=f"last seen: {prev_sha} ({prev_count} commits)\n"
                 f"now:       {now_sha} ({now_count} commits)",
        remedy="Find out which before doing anything else — a force-push by "
               "hand and an intruder covering tracks look identical here. "
               "`git reflog` on any clone that has not fetched since still "
               "holds the old commits, and that clone is the recovery path. "
               "Do NOT pull into it first.",
        remedy_he="ברר מה קרה לפני כל דבר אחר — דחיפה כוחנית ידנית ותוקף "
                  "שמטשטש עקבות נראים כאן זהים. git reflog בכל שכפול שלא עשה "
                  "fetch מאז עדיין מחזיק את הקומיטים הישנים, וזו דרך השחזור. "
                  "אל תעשה שם pull קודם.",
        needs_owner=True,
        owner_reason_he="שכתוב היסטוריה מתוקן רק ממחשב שמחזיק את הקומיטים הישנים"))


def _owner_commits_are_signed(m: Manifest, findings: list[Finding]) -> None:
    """Are the commits that claim to be the owner's actually the owner's?

    WHAT THIS BUYS, PRECISELY, because it is easy to oversell. Anyone with
    write access can author a commit under any name and address they like —
    `git commit --author` takes a string, and nothing verifies it. Signing is
    what makes that forgery visible: a commit claiming to be the owner and
    carrying no signature stands out from every one that does.

    WHAT IT DOES NOT BUY. The automation commits under its own names —
    "market-news bot", "sentinel audit bot", "claude[bot]" — from runners that
    hold no key, so those commits are unsigned and must be exempt or this check
    would fire on every scheduled run forever. Which means an attacker who
    steals a workflow token simply commits as a bot and is not caught here.
    What stands against THAT is the workflow definitions being in git and
    `_history_is_append_only` noticing a rewrite. Signing narrows the hole; it
    does not close it, and saying otherwise would be the more dangerous error.

    The bar is the RECENT past, not all history. Commits made before signing
    was set up cannot be signed retroactively, and a check that can never pass
    is one people turn off.
    """
    title = "Commits attributed to the owner are signed"
    title_he = "קומיטים שמיוחסים לבעלים חתומים"

    if not (m.root / ".git").exists():
        return
    owner = str(m.security.get("owner_email") or "").strip()
    if not owner:
        return          # nothing declared, nothing to hold anyone to

    look_back = int(m.security.get("signing_lookback", 30))

    # READ THE RAW COMMIT HEADER, NOT `%G?`.
    #
    # `%G?` VERIFIES, and verification depends on the machine asking. On the
    # owner's laptop — with gpg.format=ssh and an allowedSignersFile — a signed
    # commit reads G. In CI, with neither, git prints
    #   "gpg.ssh.allowedSignersFile needs to be configured and exist"
    # and reports the SAME commit as N. So this check counted every signed
    # commit as unsigned wherever the audit actually runs: nine runs, zero
    # passes, a count that never fell no matter how much was signed.
    # `_never_passed` flagged it; the place a check runs is part of the check.
    #
    # The question here was only ever "is a signature PRESENT" — verifying it
    # needs the owner's key list, which CI does not and should not have. A
    # `gpgsig` header answers presence identically on every machine.
    r = run(f"git log -{look_back} --pretty=raw", m.root, timeout_s=60,
            clip=False)
    if not r.ok:
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he,
            verdict=Verdict.UNKNOWN, severity=Severity.MEDIUM,
            detail="could not read the commit log",
            detail_he="לא הצלחתי לקרוא את יומן הקומיטים",
            evidence=(r.error or r.output)[:200]))
        return

    commits, cur = [], None
    for line in r.stdout.splitlines():
        if line.startswith("commit "):
            if cur:
                commits.append(cur)
            cur = {"sha": line.split()[1], "email": "", "signed": False,
                   "subject": ""}
        elif cur is None:
            continue
        elif line.startswith("author "):
            lt, gt = line.find("<"), line.find(">")
            cur["email"] = line[lt + 1:gt] if lt != -1 < gt else ""
        elif line.startswith(("gpgsig ", "gpgsig-sha256 ")):
            cur["signed"] = True
        elif line.startswith("    ") and not cur["subject"]:
            cur["subject"] = line.strip()
    if cur:
        commits.append(cur)

    unsigned, signed = [], 0
    for c in commits:
        if c["email"].lower() != owner.lower():
            continue                         # a bot, or someone else
        if c["signed"]:
            signed += 1
        else:
            unsigned.append(f"{c['sha'][:9]} {c['subject'][:70]}")

    if not unsigned:
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he, verdict=Verdict.PASS,
            severity=Severity.MEDIUM,
            detail=f"{signed} of the last {look_back} commit(s) are the "
                   f"owner's, and all carry a signature"
                   if signed else
                   f"none of the last {look_back} commits are the owner's — "
                   f"nothing to verify",
            detail_he=(f"{signed} מתוך {look_back} הקומיטים האחרונים הם של "
                       f"הבעלים, וכולם חתומים") if signed else
                      f"אף אחד מ-{look_back} הקומיטים האחרונים אינו של הבעלים"))
        return

    findings.append(Finding(
        check=NAME, title=title, title_he=title_he, verdict=Verdict.WARN,
        severity=Severity.MEDIUM,
        detail=f"{len(unsigned)} of the last {look_back} commit(s) claim the "
               f"owner's address and carry no signature — indistinguishable "
               f"from a forgery, whichever they are",
        detail_he=f"{len(unsigned)} מתוך {look_back} הקומיטים האחרונים טוענים "
                  f"לכתובת של הבעלים ואינם חתומים — לא ניתנים להבחנה מזיוף",
        evidence="\n".join(unsigned[:8]),
        remedy="`git config --global commit.gpgsign true` with an ssh signing "
               "key, and upload the public key to GitHub as a SIGNING key — "
               "an authentication key is a different list and will not verify "
               "anything. Commits made before signing was set up cannot be "
               "fixed; they age out of the window.",
        remedy_he="הגדר commit.gpgsign true עם מפתח SSH, והעלה את המפתח "
                  "הציבורי ל-GitHub כמפתח חתימה — מפתח אימות הוא רשימה אחרת "
                  "ולא יאמת כלום. קומיטים שנעשו לפני ההגדרה לא ניתנים לתיקון "
                  "והם יוצאים מהחלון מעצמם.",
        needs_owner=True,
        owner_reason_he="מפתח החתימה הפרטי שלך — הדמון אין לו גישה אליו ואסור שתהיה"))


def _dependencies_are_pinned(m: Manifest, findings: list[Finding]) -> None:
    """Does `pip install` in CI get the same packages every time?

    THE SHAPE OF THIS RISK IS DIFFERENT FROM THE OTHERS HERE, and worse. A
    package's install hooks execute as the job installing it — a job holding
    every secret the workflow has. So `yfinance>=1.6.0` means an upstream
    account compromise, anywhere in the transitive tree, runs code beside the
    prediction book and the deploy key. **It needs no mistake on our part and
    no access to this account at all**, which is what separates it from every
    other finding in this file.

    A floor (`>=`) is not a version. It is an instruction to take whatever was
    published most recently, evaluated fresh on every CI run.

    NOT asking for hashes. `--require-hashes` also defeats a compromised index
    serving a different artifact under a version already used, and it needs a
    full transitive lock regenerated per platform. Worth doing and a much
    bigger change; demanding it here would make this finding unactionable, and
    an unactionable finding is one people learn to skip.
    """
    title = "CI installs the same dependencies every time"
    title_he = "ה-CI מתקין את אותן תלויות בכל פעם"

    req = m.root / "requirements.txt"
    if not req.is_file():
        return

    floors, unconstrained = [], []
    for raw in req.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        if "==" in line:
            continue
        if any(op in line for op in (">=", ">", "~=", "<", "!=")):
            floors.append(line)
        else:
            unconstrained.append(line)

    # A HASH-LOCKED FILE IS A STRONGER ANSWER THAN A PINNED ONE, and the check
    # must be able to see the difference or there is no reason to do the harder
    # thing. A pin trusts the index to serve the same artifact under a known
    # version, and says nothing about the transitive tree — six pinned names
    # here resolve to 220 packages.
    lock = next((m.root / n for n in ("requirements.lock", "requirements.txt.lock")
                 if (m.root / n).is_file()), None)
    if lock is not None and "--hash=" in lock.read_text(encoding="utf-8",
                                                        errors="ignore"):
        wf = m.root / ".github" / "workflows"
        used = wf.is_dir() and any(
            "--require-hashes" in f.read_text(encoding="utf-8", errors="ignore")
            for f in wf.glob("*.y*ml"))
        text = lock.read_text(encoding="utf-8", errors="ignore")
        n_hashes = text.count("--hash=")
        if used:
            findings.append(Finding(
                check=NAME, title=title, title_he=title_he,
                verdict=Verdict.PASS, severity=Severity.HIGH,
                detail=f"{lock.name} carries {n_hashes} hashes and CI installs "
                       f"with --require-hashes, so a tampered artifact is "
                       f"refused rather than trusted",
                detail_he=f"{lock.name} מכיל {n_hashes} hash-ים וה-CI מתקין עם "
                          f"--require-hashes, אז artifact שהוחלף נדחה"))
            return
        # A LOCK NOBODY INSTALLS FROM IS DECORATION. This is the same shape as
        # a history ledger nothing advances: the artefact exists, looks right,
        # and protects nothing.
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he, verdict=Verdict.WARN,
            severity=Severity.HIGH,
            detail=f"{lock.name} exists with {n_hashes} hashes and no workflow "
                   f"installs with `--require-hashes` — the lock is not being "
                   f"enforced anywhere",
            detail_he=f"{lock.name} קיים עם {n_hashes} hash-ים ואף תהליך לא "
                      f"מתקין עם --require-hashes — הנעילה לא נאכפת",
            remedy="Change the install step to "
                   "`pip install --require-hashes -r requirements.lock`. "
                   "Generating a lock and installing from something else is "
                   "the same shape as a ledger nothing advances.",
            remedy_he="שנה את שלב ההתקנה ל--require-hashes. לייצר נעילה "
                      "ולהתקין ממשהו אחר זו אותה צורה כמו יומן שאף אחד לא מקדם."))
        return

    loose = floors + unconstrained
    if not loose:
        pinned = sum(1 for r in req.read_text(encoding="utf-8",
                                              errors="ignore").splitlines()
                     if "==" in r.split("#", 1)[0])
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he, verdict=Verdict.PASS,
            severity=Severity.HIGH,
            detail=f"all {pinned} direct dependenc(ies) name an exact version",
            detail_he=f"כל {pinned} התלויות הישירות נוקבות בגרסה מדויקת"))
        return

    findings.append(Finding(
        check=NAME, title=title, title_he=title_he, verdict=Verdict.WARN,
        severity=Severity.HIGH,
        detail=f"{len(loose)} dependenc(ies) are not pinned, so CI installs "
               f"whatever was published most recently — and a package's "
               f"install hooks run inside the job holding every secret",
        detail_he=f"{len(loose)} תלויות אינן מוצמדות, אז ה-CI מתקין את מה "
                  f"שפורסם אחרון — וקוד ההתקנה של חבילה רץ בתוך המשימה "
                  f"שמחזיקה את כל הסודות",
        evidence="\n".join(loose[:10]),
        remedy="Pin each to the version the suite actually passes against "
               "(`pip freeze` on the working environment), and add the `pip` "
               "ecosystem to dependabot so pinning does not freeze the "
               "vulnerabilities in place as well.",
        remedy_he="הצמד כל אחת לגרסה שהסוויטה באמת עוברת מולה, והוסף את pip "
                  "ל-dependabot כדי שההצמדה לא תקפיא גם את הפגיעויות."))


def _history_holds_no_credential(m: Manifest, findings: list[Finding]) -> None:
    """Was a secret ever committed, even if it is gone from the working tree?

    THE GAP THE OTHER SCANNER LEAVES, and it is the one that matters most:
    `_tracked_files` reads the CURRENT tree. A token committed in June and
    deleted in July is absent from every file it looks at and present in every
    clone of the repository, forever. Deleting a secret from a file does not
    delete it — that is the single most common way credentials leak from
    repositories, and a working-tree scanner reports a clean bill of health
    the whole time.

    Scans the diffs of recent commits rather than every blob ever written:
    a full history walk is slow enough that it would be run once and then
    turned off, and recent history is where an accident is still fixable —
    rotate the credential, and consider the older one already public.
    """
    title = "No credential was committed and later deleted"
    title_he = "לא הוקמט אישור גישה שנמחק אחר כך"

    if not (m.root / ".git").exists():
        return

    depth = int(m.security.get("history_scan_commits", 200))
    allow = [str(a) for a in (m.security.get("allow_patterns") or [])]

    # SCANNED IN PYTHON, NOT BY `git log -G`. The first version passed each
    # pattern to git, which uses POSIX regex — a different dialect. `\b` and
    # `{8,10}` are PCRE/Python spellings, so the Telegram-token pattern matched
    # nothing there while matching correctly in the working-tree scanner. Two
    # scanners claiming to use "the same shapes" and quietly disagreeing about
    # what a shape IS is worse than having one.
    #
    # Reading the diffs and applying the SAME compiled patterns makes that
    # impossible by construction. `--unified=0` keeps only changed lines, which
    # is the question anyway: was this ever written down.
    r = run(f"git log -{depth} -p --unified=0 --format='commit %h %s'",
            m.root, timeout_s=180, clip=False)
    if not r.ok:
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he,
            verdict=Verdict.UNKNOWN, severity=Severity.HIGH,
            detail="could not read the commit history",
            detail_he="לא הצלחתי לקרוא את היסטוריית הקומיטים",
            evidence=(r.error or r.output)[:200],
            remedy="Check that `git` is available and this is a repository.",
            remedy_he="בדוק ש-git זמין ושזה ריפו."))
        return

    compiled = [(re.compile(pat), label) for pat, label in SECRET_PATTERNS]
    hits, subject = [], ""
    for line in r.stdout.splitlines():
        if line.startswith("commit "):
            subject = line[len("commit "):]
            continue
        # Only added or removed lines. A credential sitting unchanged in
        # context lines was already found by the working-tree scanner.
        if not (line.startswith("+") or line.startswith("-")):
            continue
        if line.startswith(("+++", "---")):
            continue
        if any(a and a in line for a in allow) or any(a and a in subject
                                                      for a in allow):
            continue
        for rx, label in compiled:
            if rx.search(line):
                hits.append(f"{label} in {subject[:60]}")
                break

    # One entry per commit: a token written and then removed matches twice, and
    # reporting it twice makes one accident look like two.
    hits = list(dict.fromkeys(hits))

    if not hits:
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he, verdict=Verdict.PASS,
            severity=Severity.HIGH,
            detail=f"no credential shape appears in the last {depth} commits, "
                   f"added or removed",
            detail_he=f"שום צורת אישור לא מופיעה ב-{depth} הקומיטים האחרונים"))
        return

    findings.append(Finding(
        check=NAME, title=title, title_he=title_he, verdict=Verdict.FAIL,
        severity=Severity.CRITICAL,
        detail=f"{len(hits)} commit(s) added or removed something shaped like a "
               f"credential — deleting it from the file did not delete it from "
               f"the repository",
        detail_he=f"{len(hits)} קומיטים הוסיפו או הסירו משהו בצורת אישור גישה — "
                  f"מחיקה מהקובץ לא מחקה אותו מהריפו",
        evidence="\n".join(hits[:8]),
        remedy="ROTATE THE CREDENTIAL FIRST. Rewriting history is secondary "
               "and often impossible — every existing clone already has it. "
               "Treat anything that reached a commit as public. If the match "
               "is documentation quoting a token SHAPE, add the distinguishing "
               "text to [security].allow_patterns.",
        remedy_he="החלף את האישור קודם. שכתוב היסטוריה משני ולעתים בלתי אפשרי — "
                  "כל שכפול קיים כבר מחזיק אותו. התייחס לכל מה שהגיע לקומיט "
                  "כאל ציבורי. אם זו דוקומנטציה שמצטטת צורה, הוסף את הטקסט "
                  "המבחין ל-[security].allow_patterns.",
        needs_owner=True,
        owner_reason_he="החלפת סוד שדלף: רק לך יש גישה לחשבון שמנפיק אותו"))


_PERMS_BLOCK = re.compile(r"^\s*permissions:\s*$|^\s*permissions:\s*\S", re.M)
_WRITE_ALL = re.compile(r"permissions:\s*write-all", re.M)
_PR_TARGET = re.compile(r"^\s*pull_request_target:", re.M)


def _workflow_permissions_are_declared(m: Manifest,
                                       findings: list[Finding]) -> None:
    """Does each workflow say what it is allowed to do, or inherit whatever?

    A WORKFLOW WITH NO `permissions:` BLOCK INHERITS THE REPOSITORY DEFAULT,
    and that default is a repository-wide setting nothing in the source
    records. On many repositories it is read AND WRITE across every scope —
    contents, packages, issues, pull requests, deployments. A test workflow
    that only needs to read code can be running with the right to rewrite it.

    The danger is not that the default is necessarily wrong. It is that the
    source does not say, so nobody reviewing a workflow can tell what it can
    do, and a change to that setting silently re-permissions every workflow
    that never declared.

    Also flagged:
      * `write-all`, which is the default made explicit and no better for it;
      * `pull_request_target`, which runs with repository secrets against code
        from a fork. Combined with checking out the pull request's head it is
        the best-known way to hand an attacker a repository's secrets, and it
        appears in no workflow here — which is why it is worth keeping checked.
    """
    title = "Every workflow declares what it is allowed to do"
    title_he = "כל תהליך מצהיר מה מותר לו לעשות"

    wf = m.root / ".github" / "workflows"
    if not wf.is_dir():
        return

    silent, write_all, pr_target = [], [], []
    total = 0
    for f in sorted(wf.glob("*.y*ml")):
        total += 1
        text = f.read_text(encoding="utf-8", errors="ignore")
        if _WRITE_ALL.search(text):
            write_all.append(f.name)
        elif not _PERMS_BLOCK.search(text):
            silent.append(f.name)
        if _PR_TARGET.search(text):
            pr_target.append(f.name)

    if write_all or pr_target:
        detail = []
        if write_all:
            detail.append(f"{len(write_all)} use `write-all`")
        if pr_target:
            detail.append(f"{len(pr_target)} use `pull_request_target`, which "
                          f"runs with this repository's secrets against code "
                          f"from a fork")
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he, verdict=Verdict.FAIL,
            severity=Severity.CRITICAL,
            detail="; ".join(detail),
            detail_he="תהליך משתמש ב-write-all או ב-pull_request_target",
            evidence="\n".join(write_all + pr_target),
            remedy="Replace `write-all` with the scopes actually needed. For "
                   "`pull_request_target`, never check out the pull request's "
                   "head — that is the combination that hands a fork the "
                   "repository's secrets.",
            remedy_he="החלף write-all בסקופים שבאמת נחוצים. עם "
                      "pull_request_target אל תעשה checkout ל-head של ה-PR."))
        return

    if silent:
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he, verdict=Verdict.WARN,
            severity=Severity.HIGH,
            detail=f"{len(silent)} of {total} workflow(s) declare no "
                   f"`permissions:` at all, so they inherit a repository-wide "
                   f"setting that nothing in the source records — often read "
                   f"AND write across every scope",
            detail_he=f"{len(silent)} מתוך {total} תהליכים לא מצהירים "
                      f"permissions כלל, אז הם יורשים הגדרה ברמת הריפו ששום "
                      f"דבר בקוד לא מתעד — לעתים קרובות קריאה וכתיבה בכל סקופ",
            evidence="\n".join(silent),
            remedy="Add a `permissions:` block naming only what the workflow "
                   "needs — `contents: read` for one that only runs tests. A "
                   "declared permission is reviewable in a diff; an inherited "
                   "one changes under you when someone edits a repository "
                   "setting.",
            remedy_he="הוסף בלוק permissions שנוקב רק במה שהתהליך צריך — "
                      "contents: read למי שרק מריץ בדיקות. הרשאה מוצהרת ניתנת "
                      "לביקורת ב-diff; מוירשת משתנה מתחתיך.",
        needs_owner=True,
        owner_reason_he="עריכת .github/workflows אסורה לפאס — אחרת הוא יכול להרחיב לעצמו הרשאות"))
        return

    findings.append(Finding(
        check=NAME, title=title, title_he=title_he, verdict=Verdict.PASS,
        severity=Severity.HIGH,
        detail=f"all {total} workflow(s) name their own scopes",
        detail_he=f"כל {total} התהליכים נוקבים בסקופים שלהם"))


def _visibility_matches_the_declaration(m: Manifest,
                                        findings: list[Finding]) -> None:
    """Is this repository as public as the project says it is?

    A PRIVATE REPOSITORY MADE PUBLIC BY ACCIDENT IS SILENT AND TOTAL. Nothing
    breaks, no test fails, no workflow turns red — the code, the history and
    every secret ever committed to it are simply readable by everyone, and the
    first sign is someone else finding them.

    It cannot be checked from the source, because visibility is not IN the
    source. So the project declares what it intends and this asks GitHub.

    The asymmetry is deliberate: declared private and actually public is
    CRITICAL, while declared public and actually private is a WARNING. One
    exposes everything; the other just means a collaborator cannot read it.
    """
    title = "The repository is as public as this project says it is"
    title_he = "הריפו ציבורי בדיוק כפי שהפרויקט מצהיר"

    want = str(m.security.get("visibility") or "").strip().lower()
    if not want:
        return              # nothing declared, nothing to hold it to
    if want not in ("public", "private", "internal"):
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he,
            verdict=Verdict.UNKNOWN, severity=Severity.MEDIUM,
            detail=f"the manifest declares visibility {want!r}, which is not "
                   f"one of public/private/internal",
            detail_he=f"המניפסט מצהיר על נראות {want!r} שאינה מוכרת",
            remedy="Use `public`, `private` or `internal`.",
            remedy_he="השתמש ב-public, private או internal."))
        return

    if not which("gh"):
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he,
            verdict=Verdict.UNKNOWN, severity=Severity.HIGH,
            detail=f"declared {want}, and without the `gh` CLI there is no way "
                   f"to see what GitHub actually has",
            detail_he=f"מוצהר {want}, ובלי gh אין דרך לראות מה ב-GitHub בפועל",
            remedy="Install and authenticate the GitHub CLI.",
            remedy_he="התקן ואמת את ה-CLI של GitHub."))
        return

    r = run("gh repo view --json visibility --jq .visibility", m.root,
            timeout_s=60)
    actual = r.stdout.strip().lower()
    if not r.ok or not actual:
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he,
            verdict=Verdict.UNKNOWN, severity=Severity.HIGH,
            detail=f"declared {want}, and GitHub could not be asked",
            detail_he=f"מוצהר {want}, ולא הצלחתי לשאול את GitHub",
            evidence=(r.error or r.output)[:200],
            remedy="Check `gh auth status` and that this repo has a remote.",
            remedy_he="בדוק gh auth status ושיש remote לריפו."))
        return

    if actual == want:
        findings.append(Finding(
            check=NAME, title=title, title_he=title_he, verdict=Verdict.PASS,
            severity=Severity.HIGH,
            detail=f"declared {want}, and GitHub agrees",
            detail_he=f"מוצהר {want}, ו-GitHub מסכים"))
        return

    exposed = want == "private" and actual == "public"
    findings.append(Finding(
        check=NAME, title=title, title_he=title_he, verdict=Verdict.FAIL,
        severity=Severity.CRITICAL if exposed else Severity.MEDIUM,
        detail=(f"declared {want}, and GitHub says {actual} — the code, the "
                f"full history and every secret ever committed are readable by "
                f"anyone" if exposed else
                f"declared {want}, and GitHub says {actual}"),
        detail_he=(f"מוצהר {want} ו-GitHub אומר {actual} — הקוד, כל ההיסטוריה "
                   f"וכל סוד שאי פעם הוקמט קריאים לכל אחד" if exposed else
                   f"מוצהר {want} ו-GitHub אומר {actual}"),
        remedy=("Make it private again FIRST, then treat every credential this "
                "repository has ever held as public and rotate it. History is "
                "readable for as long as it is exposed, and clones taken "
                "meanwhile keep it." if exposed else
                "Either change the repository or change the declaration — but "
                "decide which is right rather than making them agree."),
        remedy_he=("החזר לפרטי קודם, ואז התייחס לכל אישור גישה שהריפו הזה אי "
                   "פעם החזיק כאל ציבורי והחלף אותו." if exposed else
                   "שנה את הריפו או את ההצהרה — אבל תחליט מה נכון."),
        needs_owner=True,
        owner_reason_he="נראות הריפו היא הגדרת חשבון ב-GitHub, לא שורת קוד"))


def _tracked_files(root: Path) -> tuple[list[Path], str]:
    """Files git actually carries. Returns ([], reason) when git cannot answer."""
    r = run("git ls-files -z", root, timeout_s=60)
    if r.error or not r.ok:
        return [], (r.error or r.output or "git ls-files failed")
    names = [n for n in r.stdout.split("\0") if n]
    return [root / n for n in names], ""


def check(m: Manifest) -> CheckResult:
    findings: list[Finding] = []
    root = m.root
    allow = set(m.security.get("allow_patterns") or [])

    with timer() as t:
        files, why_not = _tracked_files(root)
        if why_not:
            findings.append(Finding(
                check=NAME, title="Tracked files can be enumerated", title_he="אפשר לרשום את הקבצים שבמעקב",
                verdict=Verdict.UNKNOWN, severity=Severity.HIGH,
                detail=f"could not list tracked files: {why_not}",
                remedy="Run sentinel inside a git repository."))
            # `t.seconds` only exists once the `with` block has EXITED — the
            # timer sets it in __exit__. Reading it on an early return inside
            # the block raised AttributeError, so auditing anything that is not
            # a git repository crashed the entire security check instead of
            # reporting the UNKNOWN two lines above.
            #
            # The error path had never been exercised: every project audited so
            # far was a git repo. Found 2026-09-13 by a test that used a bare
            # temp directory for something unrelated.
            return CheckResult(name=NAME, findings=findings, duration_s=0.0)

        # 1. Files that must never be tracked.
        tracked_names = {str(p.relative_to(root)) for p in files}
        leaked = sorted(n for n in tracked_names
                        if n in NEVER_TRACK or Path(n).name in NEVER_TRACK)
        if leaked:
            findings.append(Finding(
                check=NAME, title="No secret-bearing file is tracked by git", title_he="אף קובץ שמכיל סודות אינו במעקב git",
                verdict=Verdict.FAIL, severity=Severity.CRITICAL,
                detail=f"{len(leaked)} file(s) that should never be committed",
                evidence="\n".join(leaked),
                remedy="git rm --cached <file>, add it to .gitignore, and "
                       "ROTATE whatever it contained — it is in the history."))
        else:
            findings.append(Finding(
                check=NAME, title="No secret-bearing file is tracked by git", title_he="אף קובץ שמכיל סודות אינו במעקב git",
                verdict=Verdict.PASS, severity=Severity.CRITICAL,
                detail=f"{len(files)} tracked files, none of them .env or a key"))

        # 2. Secret-shaped strings inside tracked files.
        hits: list[str] = []
        for f in files:
            if f.suffix.lower() not in TEXT_SUFFIXES:
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if any(a in line for a in allow):
                    continue
                for pattern, what in SECRET_PATTERNS:
                    if re.search(pattern, line):
                        rel = f.relative_to(root)
                        # The finding names the file and the KIND, never the
                        # value: a report that quotes the secret leaks it again,
                        # into wherever the report goes.
                        hits.append(f"{rel}:{lineno}: {what}")
                        break
        if hits:
            findings.append(Finding(
                check=NAME, title="No credential is committed in the source", title_he="אין אישור גישה מקובע בקוד",
                verdict=Verdict.FAIL, severity=Severity.CRITICAL,
                detail=f"{len(hits)} credential-shaped string(s) in tracked files",
                evidence="\n".join(sorted(set(hits))[:20]),
                remedy="Remove it, rotate the credential, and move it to an "
                       "environment variable or a secret store. Assume it is "
                       "compromised: it is in the git history."))
        else:
            findings.append(Finding(
                check=NAME, title="No credential is committed in the source", title_he="אין אישור גישה מקובע בקוד",
                verdict=Verdict.PASS, severity=Severity.CRITICAL,
                detail="no credential-shaped strings in tracked text files"))

        # 3. .gitignore covers the usual suspects.
        gi = root / ".gitignore"
        if not gi.is_file():
            findings.append(Finding(
                check=NAME, title=".gitignore protects the usual secret paths", title_he=".gitignore מכסה את נתיבי הסודות הרגילים",
                verdict=Verdict.WARN, severity=Severity.MEDIUM,
                detail="there is no .gitignore",
                remedy="Add one covering .env, secrets, and virtualenvs."))
        else:
            body = gi.read_text(encoding="utf-8", errors="ignore")
            missing = [p for p in (".env", "*.pem", "secrets")
                       if p not in body]
            if missing:
                findings.append(Finding(
                    check=NAME, title=".gitignore protects the usual secret paths", title_he=".gitignore מכסה את נתיבי הסודות הרגילים",
                    verdict=Verdict.WARN, severity=Severity.MEDIUM,
                    detail=f"not covered: {', '.join(missing)}",
                    evidence=str(gi.relative_to(root)),
                    remedy="Add those lines to .gitignore."))
            else:
                findings.append(Finding(
                    check=NAME, title=".gitignore protects the usual secret paths", title_he=".gitignore מכסה את נתיבי הסודות הרגילים",
                    verdict=Verdict.PASS, severity=Severity.MEDIUM,
                    detail="covers .env, keys and secrets"))

        # 4. Risky code patterns.
        risky: dict[Severity, list[str]] = {}
        for f in files:
            if f.suffix.lower() not in {".py", ".js", ".ts", ".sh"}:
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                # Comments and docstring prose describe these patterns far more
                # often than code uses them; flagging prose is how a scanner
                # earns its way into a mute filter.
                if stripped.startswith(("#", "//", "*", '"""', "'''")):
                    continue
                if any(a in line for a in allow):
                    continue
                for pattern, why, sev in RISKY_CODE:
                    if re.search(pattern, line):
                        risky.setdefault(sev, []).append(
                            f"{f.relative_to(root)}:{lineno}: {why}")
                        break
        if risky:
            worst = min(risky, key=lambda s: s.rank)
            flat = [x for sev in sorted(risky, key=lambda s: s.rank)
                    for x in risky[sev]]
            findings.append(Finding(
                check=NAME, title="No high-risk code patterns in tracked source", title_he="אין דפוסי קוד בסיכון גבוה בקוד שבמעקב",
                verdict=Verdict.WARN, severity=worst,
                detail=f"{len(flat)} occurrence(s) worth a human's eye",
                evidence="\n".join(flat[:15]),
                remedy="Each may be fine in context — confirm, then add it to "
                       "[security].allow_patterns in the manifest to silence it."))
        else:
            findings.append(Finding(
                check=NAME, title="No high-risk code patterns in tracked source", title_he="אין דפוסי קוד בסיכון גבוה בקוד שבמעקב",
                verdict=Verdict.PASS, severity=Severity.MEDIUM,
                detail="none found"))

        # The two threats, side by side because they are NOT the same threat:
        # the first two keep other people out, the third keeps us from
        # destroying something we cannot rebuild. SECURITY.md says why they
        # need different machinery.
        for step in (_actions_are_pinned, _no_untrusted_input_in_shell,
                     _irreplaceable_has_a_second_copy,
                     _history_is_append_only, _owner_commits_are_signed,
                     _dependencies_are_pinned, _history_holds_no_credential,
                     _workflow_permissions_are_declared,
                     _visibility_matches_the_declaration):
            try:
                step(m, findings)
            except Exception as ex:                        # noqa: BLE001
                findings.append(Finding(
                    check=NAME, title=f"security step {step.__name__}",
                    verdict=Verdict.UNKNOWN, severity=Severity.MEDIUM,
                    detail=f"the check raised {type(ex).__name__}: {ex}",
                    remedy="This is a bug in sentinel, not in the project."))

    return CheckResult(name=NAME, findings=findings, duration_s=t.seconds)
