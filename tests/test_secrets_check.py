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
from sentinel.verdict import Verdict        # noqa: E402


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


def test_a_failed_run_that_died_of_something_else_is_unknown(
        tmp_path, monkeypatch):
    """Not every red run is a missing secret. Claiming one would be a false
    positive built on top of an unrelated failure."""
    seq = _Seq(
        (False, "HTTP 403"),
        (True, "999"),
        (True, "AssertionError: expected 3 got 4"),
    )
    monkeypatch.setattr(health, "which", lambda _: "/usr/bin/gh")
    monkeypatch.setattr(health, "run", seq)
    findings = []
    health._secrets(_project(tmp_path, WORKFLOW), findings)
    assert findings[0].verdict is Verdict.UNKNOWN


def test_a_green_latest_run_is_still_unknown_not_a_pass(
        tmp_path, monkeypatch):
    """The distinction this whole tool rests on. "The last run did not fail"
    is not "the secrets are set" — it is "nothing contradicts it", and folding
    the two together is how an auditor becomes worse than none."""
    seq = _Seq((False, "HTTP 403"), (True, ""))
    monkeypatch.setattr(health, "which", lambda _: "/usr/bin/gh")
    monkeypatch.setattr(health, "run", seq)
    findings = []
    health._secrets(_project(tmp_path, WORKFLOW), findings)
    f = findings[0]
    assert f.verdict is Verdict.UNKNOWN
    assert f.verdict.is_actionable, "an unchecked promise must stay visible"


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
