"""
test_secrets_check.py
---------------------
Pins `health._secrets` — the check built from the second half of one lesson.

A NEW REPOSITORY INHERITS NOTHING. sentinel's own improvement pass failed for
three days on a missing GitHub App grant. The grant was given, and the very
next run failed again: the repository had no secrets at all, because the token
its workflow reads lived in the other project and secrets are per-repository
too. The second failure was invisible while the first one stood.

What gets the most attention here is the OPPOSITE risk. This check reads
configuration rather than waiting for a run, so it is cheap to make it shout —
and the first version did, at high severity, about two secrets stock-predictor
deliberately works without. A scanner that cries wolf gets muted, and a muted
scanner looks like coverage.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.checks import health          # noqa: E402
from sentinel.manifest import Manifest      # noqa: E402
from sentinel.verdict import Severity, Verdict        # noqa: E402


def _project(tmp_path, workflow_text: str, security: dict | None = None):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "w.yml").write_text(workflow_text, encoding="utf-8")
    return Manifest(path=tmp_path / "SENTINEL.toml", name="t", purpose="p",
                    security=security or {})


def _with_secrets(monkeypatch, names, ok=True):
    """Make `gh secret list` answer with `names`."""
    from sentinel.checks import base

    class R:
        def __init__(self):
            self.ok = ok
            self.error = ""
            self.stdout = "\n".join(names)
            self.output = self.stdout

    monkeypatch.setattr(health, "which", lambda _: "/usr/bin/gh")
    monkeypatch.setattr(health, "run", lambda *a, **k: R())
    return base


WORKFLOW = """
jobs:
  j:
    steps:
      - env:
          A: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
          B: ${{ secrets.IMAP_USER }}
          C: ${{ secrets.GITHUB_TOKEN }}
"""


def test_a_missing_secret_fails_and_names_the_workflow(tmp_path, monkeypatch):
    _with_secrets(monkeypatch, ["IMAP_USER"])
    findings = []
    health._secrets(_project(tmp_path, WORKFLOW), findings)
    assert len(findings) == 1
    f = findings[0]
    assert f.verdict is Verdict.FAIL
    assert "CLAUDE_CODE_OAUTH_TOKEN" in f.evidence
    assert "w.yml" in f.evidence, "a reader needs to know which workflow"


def test_the_builtin_token_is_never_reported(tmp_path, monkeypatch):
    """GITHUB_TOKEN is provided by Actions. Asking the owner to set it would
    send them looking for something that does not exist."""
    _with_secrets(monkeypatch, ["CLAUDE_CODE_OAUTH_TOKEN", "IMAP_USER"])
    findings = []
    health._secrets(_project(tmp_path, WORKFLOW), findings)
    assert findings[0].verdict is Verdict.PASS
    assert "GITHUB_TOKEN" not in findings[0].detail


def test_a_declared_optional_secret_passes_but_says_what_is_degraded(
        tmp_path, monkeypatch):
    _with_secrets(monkeypatch, ["CLAUDE_CODE_OAUTH_TOKEN"])
    findings = []
    health._secrets(
        _project(tmp_path, WORKFLOW,
                 security={"optional_secrets": ["IMAP_USER"]}),
        findings)
    f = findings[0]
    assert f.verdict is Verdict.PASS, "a declared choice is not a defect"
    assert "IMAP_USER" in f.detail, "but the cost must still be printed"
    assert "degraded" in f.detail


def test_declaring_a_secret_optional_does_not_excuse_the_others(
        tmp_path, monkeypatch):
    """The hole this could open: one declaration silencing the whole check."""
    _with_secrets(monkeypatch, [])
    findings = []
    health._secrets(
        _project(tmp_path, WORKFLOW,
                 security={"optional_secrets": ["IMAP_USER"]}),
        findings)
    assert findings[0].verdict is Verdict.FAIL
    assert "CLAUDE_CODE_OAUTH_TOKEN" in findings[0].evidence
    assert "IMAP_USER" not in findings[0].evidence


def test_a_project_with_no_workflows_says_nothing(tmp_path):
    findings = []
    health._secrets(
        Manifest(path=tmp_path / "SENTINEL.toml", name="t", purpose="p"),
        findings)
    assert findings == []


def test_a_workflow_naming_no_secrets_says_nothing(tmp_path, monkeypatch):
    findings = []
    health._secrets(_project(tmp_path, "jobs:\n  j:\n    steps: []\n"),
                    findings)
    assert findings == []


def test_no_gh_is_unknown_not_a_pass(tmp_path, monkeypatch):
    monkeypatch.setattr(health, "which", lambda _: None)
    findings = []
    health._secrets(_project(tmp_path, WORKFLOW), findings)
    assert findings[0].verdict is Verdict.UNKNOWN
    assert "CLAUDE_CODE_OAUTH_TOKEN" in findings[0].evidence


def test_an_empty_but_readable_secret_list_means_none_are_set(
        tmp_path, monkeypatch):
    """`gh secret list` on a repo with no secrets exits 0 with no output —
    which must read as "none set", never as "could not check"."""
    _with_secrets(monkeypatch, [])
    findings = []
    health._secrets(_project(tmp_path, WORKFLOW), findings)
    assert findings[0].verdict is Verdict.FAIL


# ── the path that actually runs in CI ──────────────────────────────────
#
# Listing secrets needs repository admin, and the token inside Actions does
# not have it. So in the environment the daemon audits from, the branch above
# never executes — only this one does. A check tested solely from a laptop is
# a check tested in the wrong place, which is the exact mistake recorded as
# "a check that never passes is probably broken, not vigilant".

class _Seq:
    """Answers successive `run()` calls with queued results."""

    def __init__(self, *results):
        self.results = list(results)
        self.calls = []

    def __call__(self, cmd, *a, **k):
        self.calls.append(cmd)
        ok, out = self.results.pop(0)

        class R:
            pass
        r = R()
        r.ok, r.stdout, r.output, r.error = ok, out, out, "" if ok else out
        return r


def test_when_the_secret_list_is_forbidden_it_reads_the_failed_run(
        tmp_path, monkeypatch):
    seq = _Seq(
        (False, "HTTP 403: Resource not accessible by integration"),
        (True, "34705563008"),
        (True, "Environment variable validation failed: "
               "CLAUDE_CODE_OAUTH_TOKEN is required"),
    )
    monkeypatch.setattr(health, "which", lambda _: "/usr/bin/gh")
    monkeypatch.setattr(health, "run", seq)
    findings = []
    health._secrets(_project(tmp_path, WORKFLOW), findings)
    f = findings[0]
    assert f.verdict is Verdict.FAIL
    assert "34705563008" in f.evidence
    assert "per-repository" in f.remedy


def test_a_failed_run_that_died_of_something_else_is_skip_not_a_pass(
        tmp_path, monkeypatch):
    """Not every red run is a missing secret — claiming one would be a false
    positive built on an unrelated failure.

    SKIP rather than UNKNOWN, changed deliberately: `gh secret list` is refused
    with 403 inside Actions, so this branch is the one CI always takes. Left as
    UNKNOWN it was unanswerable forever — thirteen runs, zero passes, the top
    line of `_never_passed`. L037 had moved the empty-list branch to SKIP and
    missed this one, which is the branch that actually runs.

    What must not change: it is not a PASS. Nothing was verified."""
    seq = _Seq(
        (False, "HTTP 403"),
        (True, "999"),
        (True, "AssertionError: expected 3 got 4"),
    )
    monkeypatch.setattr(health, "which", lambda _: "/usr/bin/gh")
    monkeypatch.setattr(health, "run", seq)
    findings = []
    health._secrets(_project(tmp_path, WORKFLOW), findings)
    assert findings[0].verdict is Verdict.SKIP
    assert findings[0].verdict is not Verdict.PASS, "silence must never read as verified"


def test_a_green_latest_run_is_skip_not_a_pass(tmp_path, monkeypatch):
    """SKIP, and the change from UNKNOWN was deliberate.

    UNKNOWN means "this applies here and I could not check it" — actionable,
    because something is unverified. SKIP means "this does not apply here",
    which is a decision rather than an omission.

    Listing secrets needs repository admin, and a workflow token structurally
    cannot have it. Reported as UNKNOWN it was permanently unanswerable: six
    audits, zero passes, and sentinel's own `_never_passed` warning flagged it
    as a check asking a question that cannot be answered where it runs. An
    unactionable line in every report teaches its reader to skim the section
    the real unknowns live in.

    What must never change: it is not a PASS. Nothing here verified anything.
    """
    seq = _Seq((False, "HTTP 403"), (True, ""))
    monkeypatch.setattr(health, "which", lambda _: "/usr/bin/gh")
    monkeypatch.setattr(health, "run", seq)
    findings = []
    health._secrets(_project(tmp_path, WORKFLOW), findings)
    f = findings[0]
    assert f.verdict is Verdict.SKIP
    assert f.verdict is not Verdict.PASS, "silence must never read as verified"


def test_the_app_grant_error_is_recognised_too(tmp_path, monkeypatch):
    """The first half of the same lesson, from the run that produced it."""
    seq = _Seq(
        (False, "HTTP 403"),
        (True, "34597608039"),
        (True, "401 Unauthorized - Claude Code is not installed on this "
               "repository"),
    )
    monkeypatch.setattr(health, "which", lambda _: "/usr/bin/gh")
    monkeypatch.setattr(health, "run", seq)
    findings = []
    health._secrets(_project(tmp_path, WORKFLOW), findings)
    assert findings[0].verdict is Verdict.FAIL


# ── claude-code-action: the three mistakes, and the failing case of each ──
#
# These began as expectations in stock-predictor's manifest, each written after
# the mistake was made there. sentinel runs the same action in a workflow
# written later and was covered by none of them — the project whose job is
# catching repeated mistakes, repeating them unguarded.
#
# Every case below is tested in BOTH directions. A check verified only on the
# state it wants is a check that has never been shown to fail, and this file
# already contains one lesson about that.

GOOD = """
on:
  workflow_dispatch:
permissions:
  contents: write
  id-token: write
jobs:
  j:
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: --model sonnet --allowedTools "Read"
          allowed_bots: "x"
      - name: Restore git credentials for the steps below
        run: git remote set-url origin ...
      - name: Keep it
        run: |
          git add data
          git commit -q -m x
          git push -q origin main
"""


def _findings(tmp_path, text, name="w.yml"):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / name).write_text(text, encoding="utf-8")
    out = []
    health._claude_action(
        Manifest(path=tmp_path / "SENTINEL.toml", name="t", purpose="p"), out)
    return {f.title: f for f in out}


def _verdict(fs, needle):
    for title, f in fs.items():
        if needle in title:
            return f
    raise AssertionError(f"no finding matching {needle!r} in {list(fs)}")


def test_a_correct_workflow_passes_every_check(tmp_path):
    fs = _findings(tmp_path, GOOD)
    assert len(fs) == 4
    for f in fs.values():
        assert f.verdict is Verdict.PASS, f.title


SUMMONER = "jobs:\n  s:\n    steps:\n      - run: gh workflow run w.yml\n"


def _summoned(tmp_path, text):
    """`text` as w.yml, plus a second workflow that dispatches it."""
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "audit.yml").write_text(SUMMONER, encoding="utf-8")
    return _findings(tmp_path, text)


def test_a_dispatchable_workflow_nobody_summons_is_not_flagged(tmp_path):
    """THE FALSE POSITIVE. The first version flagged every workflow with a
    `workflow_dispatch` trigger — every workflow a person might run by hand.
    market-news.yml was reported though nothing has ever dispatched it, and the
    only "fix" was to widen what a bot may trigger, for no reason."""
    fs = _findings(tmp_path, GOOD.replace('          allowed_bots: "x"\n', ""))
    assert _verdict(fs, "bot summon").verdict is Verdict.PASS


def test_a_summon_in_a_comment_is_not_a_summon(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "audit.yml").write_text(
        "jobs:\n  s:\n    steps:\n      # once ran: gh workflow run w.yml\n"
        "      - run: echo hi\n", encoding="utf-8")
    fs = _findings(tmp_path, GOOD.replace('          allowed_bots: "x"\n', ""))
    assert _verdict(fs, "bot summon").verdict is Verdict.PASS


def test_a_dispatchable_workflow_must_let_a_bot_summon_it(tmp_path):
    """THE BUG THAT MADE THE WHOLE FIXING LOOP LOOK LIKE A REPORTING LOOP.

    claude-code-action refuses a non-human actor by default, and the audit
    summons the improvement pass with `gh workflow run`, which runs as
    github-actions[bot]:

        Workflow initiated by non-human actor: github-actions (type: Bot)

    Every summoned pass died before Claude started. The audit said "something
    here a pass can act on", dispatched, and the pass refused — leaving
    findings that never got fixed and an owner reasonably concluding the
    system only reports. It hid behind the scheduled passes, which worked.
    """
    fs = _summoned(tmp_path, GOOD.replace('          allowed_bots: "x"\n', ""))
    f = _verdict(fs, "bot summon")
    assert f.verdict is Verdict.FAIL
    assert "allowed_bots" in f.remedy


def test_the_check_does_not_trip_over_its_own_documentation(tmp_path):
    """The first version searched for the bare word `allowed_bots`, which
    appears in the comment explaining the setting — so it passed on a file with
    the setting deleted. Third time that shape has appeared in this project: a
    grep for a config key must anchor to the key."""
    commented = GOOD.replace(
        '          allowed_bots: "x"\n',
        "          # allowed_bots is why this works\n")
    f = _verdict(_summoned(tmp_path, commented), "bot summon")
    assert f.verdict is Verdict.FAIL, "a comment is not a setting"


def test_missing_oidc_fails_and_names_the_file(tmp_path):
    fs = _findings(tmp_path, GOOD.replace("  id-token: write\n", ""),
                   name="broken.yml")
    f = _verdict(fs, "id-token")
    assert f.verdict is Verdict.FAIL
    assert "broken.yml" in f.evidence


def test_missing_credential_restore_fails(tmp_path):
    fs = _findings(
        tmp_path,
        GOOD.replace("      - name: Restore git credentials for the steps below\n"
                     "        run: git remote set-url origin ...\n", ""))
    assert _verdict(fs, "restores its credentials").verdict is Verdict.FAIL


def test_a_workflow_that_never_writes_with_git_needs_no_restore(tmp_path):
    """The condition matters. Demanding a credential restore from a workflow
    that only reads would be a false positive with a confusing remedy."""
    text = GOOD.replace(
        "      - name: Restore git credentials for the steps below\n"
        "        run: git remote set-url origin ...\n", "")
    text = text.replace("          git add data\n", "") \
               .replace("          git commit -q -m x\n", "") \
               .replace("          git push -q origin main\n", "          echo done\n")
    assert _verdict(_findings(tmp_path, text),
                    "restores its credentials").verdict is Verdict.PASS


def test_git_verbs_are_found_inside_a_run_block(tmp_path):
    """The bug this regex was born from: the first version looked for `run:`
    and a git verb on ONE line, and shell blocks are written `run: |` with the
    commands indented beneath. It matched nothing and passed while checking
    nothing."""
    assert health._GIT_WRITE.search("        run: |\n          git push -q origin main\n")
    assert not health._GIT_WRITE.search("        # git push happens later\n")


def test_an_undeclared_model_fails(tmp_path):
    fs = _findings(tmp_path, GOOD.replace("--model sonnet ", ""))
    f = _verdict(fs, "declares which model")
    assert f.verdict is Verdict.FAIL
    assert "undeclared dependency" in f.remedy


def test_the_model_check_does_not_care_which_model(tmp_path):
    """It is about the declaration, not the choice. Which model is right is the
    owner's call; leaving it unstated is what makes the output undebuggable."""
    for name in ("opus", "haiku", "claude-sonnet-5"):
        fs = _findings(tmp_path, GOOD.replace("sonnet", name))
        assert _verdict(fs, "declares which model").verdict is Verdict.PASS


def test_a_project_that_does_not_use_the_action_is_silent(tmp_path):
    """Three permanent passes about a tool a project never touches is noise,
    and noise trains a reader to skim the section real findings live in."""
    assert _findings(tmp_path, "jobs:\n  j:\n    steps: []\n") == {}


def test_only_the_offending_workflow_is_named(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "fine.yml").write_text(GOOD, encoding="utf-8")
    (wf / "bad.yml").write_text(GOOD.replace("--model sonnet ", ""),
                                encoding="utf-8")
    out = []
    health._claude_action(
        Manifest(path=tmp_path / "SENTINEL.toml", name="t", purpose="p"), out)
    f = _verdict({x.title: x for x in out}, "declares which model")
    assert f.verdict is Verdict.FAIL
    assert "bad.yml" in f.evidence and "fine.yml" not in f.evidence
    assert "1 of 2" in f.detail


# ── a workflow that never once works ───────────────────────────────────

def _runs(monkeypatch, by_workflow: dict[str, list[str]]):
    class R:
        def __init__(self, out):
            self.ok, self.stdout, self.output, self.error = True, out, out, ""

    def fake(cmd, *a, **k):
        for name, conclusions in by_workflow.items():
            if f"--workflow={name}" in cmd:
                return R("\n".join(conclusions))
        return R("")

    monkeypatch.setattr(health, "which", lambda _: "/usr/bin/gh")
    monkeypatch.setattr(health, "run", fake)


def _wfs(tmp_path, *names):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    for n in names:
        (wf / n).write_text("on: push\n", encoding="utf-8")
    return Manifest(path=tmp_path / "SENTINEL.toml", name="t", purpose="p")


def test_a_workflow_that_always_fails_is_critical(tmp_path, monkeypatch):
    """THE MISS THIS EXISTS FOR. sentinel's improvement pass failed on every
    run for four days — an empty token secret — while every audit said the
    project was healthy, because the latest run of ANY workflow was always a
    green test or audit run."""
    _runs(monkeypatch, {"improve.yml": ["failure"] * 4,
                        "tests.yml": ["success"] * 4})
    out = []
    health._no_workflow_always_fails(_wfs(tmp_path, "improve.yml", "tests.yml"), out)
    f = out[0]
    assert f.verdict is Verdict.FAIL
    assert f.severity is Severity.CRITICAL
    assert "improve.yml" in f.evidence
    assert "tests.yml" not in f.evidence


def test_one_success_among_failures_is_not_always(tmp_path, monkeypatch):
    _runs(monkeypatch, {"a.yml": ["failure", "failure", "success", "failure"]})
    out = []
    health._no_workflow_always_fails(_wfs(tmp_path, "a.yml"), out)
    assert out[0].verdict is Verdict.PASS


def test_cancelled_runs_do_not_count_either_way(tmp_path, monkeypatch):
    """A superseded run is not a verdict on the workflow. Counting it as a
    failure would condemn anything pushed twice in a minute."""
    _runs(monkeypatch, {"a.yml": ["cancelled", "cancelled", "failure",
                                  "failure"]})
    out = []
    health._no_workflow_always_fails(_wfs(tmp_path, "a.yml"), out)
    assert out == [], "two real verdicts is too few to judge"


def test_a_young_workflow_is_not_judged(tmp_path, monkeypatch):
    _runs(monkeypatch, {"a.yml": ["failure"]})
    out = []
    health._no_workflow_always_fails(_wfs(tmp_path, "a.yml"), out)
    assert out == []


def test_a_disabled_workflow_is_a_decision_not_a_failure(tmp_path, monkeypatch):
    """Its last runs stay failed forever — nothing new will ever run — so
    without this the check reports a deliberate choice as a broken promise
    every day, with no way to ever clear it. sentinel's own improvement pass
    was disabled on 2026-09-22 after seven attempts to give it a usable token.
    """
    class R:
        def __init__(self, out, ok=True):
            self.ok, self.stdout, self.output, self.error = ok, out, out, ""

    def fake(cmd, *a, **k):
        if "gh workflow list" in cmd:
            return R(".github/workflows/improve.yml")
        if "--workflow=improve.yml" in cmd:
            return R("\n".join(["failure"] * 4))
        if "--workflow=tests.yml" in cmd:
            return R("\n".join(["success"] * 4))
        return R("")

    monkeypatch.setattr(health, "which", lambda _: "/usr/bin/gh")
    monkeypatch.setattr(health, "run", fake)
    out = []
    health._no_workflow_always_fails(
        _wfs(tmp_path, "improve.yml", "tests.yml"), out)
    assert out[0].verdict is Verdict.PASS
    assert "improve.yml" not in (out[0].evidence or "")


# ── the fixer itself ───────────────────────────────────────────────────
#
# THE MISS THESE EXIST FOR. The owner said the system only ever reports, and
# the message archive agreed: four findings repeated across 23 consecutive
# reports over nine days. Nothing was broken in the audit. The pass that acts
# on what it finds had failed all eleven of its runs and was then disabled —
# and disabling it is what removed the last alarm, because a disabled workflow
# is correctly a SKIP everywhere else.

def _fixer(tmp_path, monkeypatch, *, summons="improve.yml",
           listed=("improve.yml", "active"), runs=("success",) * 4,
           list_ok=True):
    class R:
        def __init__(self, out, ok=True, err=""):
            self.ok, self.stdout, self.output, self.error = ok, out, out, ""
            self.stderr = err

    def fake(cmd, *a, **k):
        if "gh workflow list" in cmd:
            if not list_ok:
                return R("", ok=False, err="gh: not authenticated")
            if listed is None:
                return R("")
            return R(f".github/workflows/{listed[0]} {listed[1]}")
        if "gh run list" in cmd:
            return R("\n".join(runs))
        return R("")

    monkeypatch.setattr(health, "which", lambda _: "/usr/bin/gh")
    monkeypatch.setattr(health, "run", fake)

    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    body = "on: schedule\n"
    if summons:
        body += f"        run: gh workflow run {summons}\n"
    (wf / "audit.yml").write_text(body, encoding="utf-8")
    out = []
    health._the_fixer_can_act(
        Manifest(path=tmp_path / "SENTINEL.toml", name="t", purpose="p"), out)
    return out[0]


def test_a_disabled_fixer_is_a_fail_not_a_skip(tmp_path, monkeypatch):
    """The whole point. Turning off an ordinary workflow stops one job;
    turning off the fixer strands every finding the audit will ever produce,
    while the report keeps arriving twice a day as if someone were acting."""
    f = _fixer(tmp_path, monkeypatch, listed=("improve.yml", "disabled_manually"))
    assert f.verdict is Verdict.FAIL
    assert f.severity is Severity.CRITICAL
    assert f.needs_owner is True          # only a person can re-enable it
    assert "disabled_manually" in f.detail


def test_an_active_fixer_passes(tmp_path, monkeypatch):
    assert _fixer(tmp_path, monkeypatch).verdict is Verdict.PASS


def test_an_audit_that_summons_nobody_skips(tmp_path, monkeypatch):
    """THE BRANCH NO PROJECT HERE TAKES. Reporting to a person is a real
    design, not an omission — but it is a decision, so it is a SKIP, and it
    has to be exercised somewhere or it is untested code (L041)."""
    f = _fixer(tmp_path, monkeypatch, summons=None)
    assert f.verdict is Verdict.SKIP
    assert "person" in f.detail


def test_summoning_a_workflow_that_does_not_exist_fails(tmp_path, monkeypatch):
    f = _fixer(tmp_path, monkeypatch, listed=None)
    assert f.verdict is Verdict.FAIL
    assert f.needs_owner is True


def test_a_fixer_that_fails_every_run_fails(tmp_path, monkeypatch):
    """Enabled is not the same as working: eleven runs, all refused in 82ms."""
    f = _fixer(tmp_path, monkeypatch, runs=("failure",) * 4)
    assert f.verdict is Verdict.FAIL
    assert f.needs_owner is True
    assert "token" in f.remedy


def test_the_target_is_read_from_the_code_not_assumed(tmp_path, monkeypatch):
    """A check that hardcodes `improve.yml` passes on a project that renamed
    its pass and silently stopped fixing anything."""
    f = _fixer(tmp_path, monkeypatch, summons="repair.yml",
               listed=("repair.yml", "disabled_inactivity"))
    assert f.verdict is Verdict.FAIL
    assert "repair.yml" in f.detail


def test_unknown_when_github_cannot_be_asked(tmp_path, monkeypatch):
    """UNKNOWN is never a pass — and never needs_owner either, since asking
    GitHub again is something the daemon can do."""
    f = _fixer(tmp_path, monkeypatch, list_ok=False)
    assert f.verdict is Verdict.UNKNOWN
    assert f.needs_owner is False


def test_the_fixer_is_reported_by_exactly_one_check(tmp_path, monkeypatch):
    """Two checks naming the same workflow is the pattern `_recurring`
    punishes: it trains the reader to skim the section that matters."""
    _runs(monkeypatch, {"improve.yml": ["failure"] * 4})
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "improve.yml").write_text("on: workflow_dispatch\n", encoding="utf-8")
    (wf / "audit.yml").write_text(
        "on: schedule\n        run: gh workflow run improve.yml\n",
        encoding="utf-8")
    out = []
    health._no_workflow_always_fails(
        Manifest(path=tmp_path / "SENTINEL.toml", name="t", purpose="p"), out)
    assert all("improve.yml" not in (f.evidence or "") for f in out)


def test_a_summon_in_a_comment_is_not_a_summon(tmp_path, monkeypatch):
    """The step that documents a REMOVED summon quotes the command it removed.
    Reading that as live would report a fixer this project no longer has."""
    class R:
        ok, stdout, output, error, stderr = True, "", "", "", ""
    monkeypatch.setattr(health, "which", lambda _: "/usr/bin/gh")
    monkeypatch.setattr(health, "run", lambda *a, **k: R())
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "audit.yml").write_text(
        "on: schedule\n"
        "      # TO REVERSE: restore `gh workflow run improve.yml` here.\n"
        "      - run: echo done   # was: gh workflow run improve.yml\n",
        encoding="utf-8")
    out = []
    health._the_fixer_can_act(
        Manifest(path=tmp_path / "SENTINEL.toml", name="t", purpose="p"), out)
    assert out[0].verdict is Verdict.SKIP
