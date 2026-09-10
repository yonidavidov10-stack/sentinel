"""The summary must never hide an unknown, and a report must never leak a key."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.manifest import Manifest              # noqa: E402
from sentinel.report import Audit, to_dict, to_markdown, to_terminal  # noqa: E402
from sentinel.notify import telegram                # noqa: E402
from sentinel.verdict import CheckResult, Finding, Verdict  # noqa: E402


def audit(*findings) -> Audit:
    m = Manifest(path=Path("SENTINEL.toml"), name="demo", purpose="a demo")
    return Audit(manifest=m,
                 results=[CheckResult(name="intent", findings=list(findings))])


PASS = Finding(check="intent", title="ok", verdict=Verdict.PASS)
FAIL = Finding(check="intent", title="broken", verdict=Verdict.FAIL,
               detail="it broke", evidence="stack trace", remedy="fix it")
UNKNOWN = Finding(check="intent", title="unchecked", verdict=Verdict.UNKNOWN,
                  detail="no credential")


def test_the_headline_names_unknowns():
    """"18 passed" when three checks could not run is a lie of omission, and it
    is the lie an auditor is most tempted to tell."""
    a = audit(PASS, PASS, UNKNOWN)
    assert "unknown" in a.headline


def test_exit_code_separates_broken_from_unchecked():
    """A scheduler must be able to tell "it is broken" from "I could not look":
    different problems, different fixes."""
    assert audit(PASS).exit_code == 0
    assert audit(PASS, UNKNOWN).exit_code == 2
    assert audit(PASS, FAIL).exit_code == 1
    assert audit(FAIL, UNKNOWN).exit_code == 1     # failure outranks unknown


def test_markdown_warns_at_the_top_when_something_was_not_checked():
    md = to_markdown(audit(PASS, UNKNOWN))
    assert "could not be run" in md
    assert "not a pass" in md


def test_markdown_carries_evidence_and_remedy_for_a_failure():
    md = to_markdown(audit(FAIL))
    assert "stack trace" in md and "fix it" in md


def test_a_passing_finding_does_not_dump_evidence():
    noisy = Finding(check="intent", title="fine", verdict=Verdict.PASS,
                    evidence="a wall of output")
    assert "a wall of output" not in to_markdown(audit(noisy))


def test_terminal_and_dict_render_without_raising():
    a = audit(PASS, FAIL, UNKNOWN)
    assert to_terminal(a)
    d = to_dict(a)
    assert d["counts"]["unknown"] == 1 and d["exit_code"] == 1


# ── the Telegram reporter ──────────────────────────────────────────────
def test_nothing_actionable_means_no_message():
    """A bot that says "all clear" every morning is wallpaper within a week,
    and then nobody reads the morning it is not clear."""
    assert telegram.format_audit(audit(PASS, PASS)) is None


def test_an_actionable_finding_produces_a_message():
    msg = telegram.format_audit(audit(FAIL))
    assert msg and "broken" in msg and "fix it" in msg


def test_unknowns_are_explained_in_the_message():
    msg = telegram.format_audit(audit(UNKNOWN))
    assert "אף אחד לא בדק" in msg


def test_the_heartbeat_says_why_it_exists():
    """Its job is to make a GAP visible: a bot that only speaks about problems
    cannot be told apart from one that has stopped running."""
    msg = telegram.format_heartbeat(audit(PASS), clean_days=7)
    assert "שתיקה" in msg


# ASSEMBLED AT RUNTIME, never written out whole. A complete token-shaped
# literal in a source file poisons every credential scanner that reads the
# repo — including this project's own, which flagged it — and "it is only a
# fixture" is exactly what someone says about a real one too. There is no
# reason for a token-shaped string to exist in source, fake or not.
@pytest.mark.parametrize("secret,kind", [
    ("1234567890:" + "AA" + "b" * 34, "telegram"),
    ("sk-" + "ant-oat01-" + "a" * 40, "anthropic"),
    ("gh" + "p_" + "b" * 36, "github"),
    ("AKIA" + "IOSFODNN7EXAMPLE", "aws"),
])
def test_credentials_are_scrubbed_before_sending(secret, kind):
    """A command expectation's stdout is arbitrary. A report that repeats a
    secret leaks it again, into wherever the report goes."""
    out = telegram.scrub(f"before {secret} after")
    assert secret not in out
    assert "before" in out and "after" in out


def test_scrubbing_survives_a_finding_that_quotes_a_token():
    fake = "1234567890:" + "AA" + "x" * 34
    leaky = Finding(check="intent", title="leaky", verdict=Verdict.FAIL,
                    detail="d", evidence=f"token {fake}")
    assert fake not in telegram.scrub(telegram.format_audit(audit(leaky)))


def test_html_is_escaped_so_a_finding_cannot_break_the_message():
    assert telegram._esc("<b>x</b> & y") == "&lt;b&gt;x&lt;/b&gt; &amp; y"


def test_long_messages_split_under_the_limit():
    chunks = telegram._split("a" * 9000)
    assert len(chunks) > 1
    assert all(len(c) <= telegram.LIMIT for c in chunks)


def test_splitting_prefers_paragraph_boundaries():
    text = "\n\n".join(["block " + "x" * 1000 for _ in range(6)])
    chunks = telegram._split(text)
    assert all(len(c) <= telegram.LIMIT for c in chunks)
    assert "".join(chunks).count("block") == 6, "no block was lost"


def test_send_without_a_token_fails_cleanly_rather_than_raising():
    r = telegram.send("hi", "", ["1"])
    assert not r.ok and r.messages_sent == 0


# ── a run in progress is not a failed run ──────────────────────────────
def test_a_ci_run_still_in_progress_is_unknown_not_failed(monkeypatch, tmp_path):
    """It is not broken, and the audit is often what triggered the run it is
    now judging. `gh --jq` renders a null conclusion as the string "null"."""
    from sentinel.checks import base, health
    from sentinel.manifest import Manifest

    monkeypatch.setattr(health, "which", lambda b: True)
    monkeypatch.setattr(
        health, "run",
        lambda *a, **k: base.Run(ok=True, exit_code=0,
                                 stdout="null|tests|https://example/1",
                                 stderr=""))
    findings = []
    health._ci_status(Manifest(path=tmp_path / "m", name="n", purpose="p"),
                      findings)
    assert findings[0].verdict is Verdict.UNKNOWN
    assert "not finished" in findings[0].detail


def test_a_genuinely_failed_ci_run_still_fails(monkeypatch, tmp_path):
    from sentinel.checks import base, health
    from sentinel.manifest import Manifest

    monkeypatch.setattr(health, "which", lambda b: True)
    monkeypatch.setattr(
        health, "run",
        lambda *a, **k: base.Run(ok=True, exit_code=0,
                                 stdout="failure|tests|https://example/1",
                                 stderr=""))
    findings = []
    health._ci_status(Manifest(path=tmp_path / "m", name="n", purpose="p"),
                      findings)
    assert findings[0].verdict is Verdict.FAIL


def test_the_message_names_the_sender_not_only_the_subject():
    """The first live message said only "stock-predictor", which reads as a
    message FROM that project rather than a bug report ABOUT it."""
    msg = telegram.format_audit(audit(FAIL))
    assert "Bug Fixer" in msg and "demo" in msg


def test_the_heartbeat_names_the_sender_too():
    assert "Bug Fixer" in telegram.format_heartbeat(audit(PASS), 7)


def test_hebrew_titles_are_preferred_when_present():
    f = Finding(check="intent", title="English", title_he="עברית",
                verdict=Verdict.FAIL, detail="d", detail_he="פרט",
                remedy="fix", remedy_he="תקן")
    msg = telegram.format_audit(audit(f))
    assert "עברית" in msg and "פרט" in msg and "תקן" in msg
    assert "English" not in msg


def test_an_untranslated_finding_still_reads_in_english():
    """A missing translation must degrade to a readable line, never a blank
    one — a finding with no title is a finding nobody can act on."""
    msg = telegram.format_audit(audit(FAIL))
    assert "broken" in msg


# ── the run that asks is not the run to judge ──────────────────────────
def test_the_ci_check_ignores_runs_still_in_progress(monkeypatch, tmp_path):
    """Found live: `gh run list --limit 1` returns the most recent run, which
    inside CI is the audit currently executing. It has no conclusion, so the
    check reported "has not finished" every single time — a question that could
    never be answered, asked twice a day, 9 of the first 10 reports.

    The fix asks only for finished runs, so the command must carry that filter.
    """
    from sentinel.checks import base, health
    from sentinel.manifest import Manifest

    seen = {}

    def fake_run(cmd, *a, **k):
        seen["cmd"] = cmd
        return base.Run(ok=True, exit_code=0,
                        stdout="success|tests|https://example/1", stderr="")

    monkeypatch.setattr(health, "which", lambda b: True)
    monkeypatch.setattr(health, "run", fake_run)
    findings = []
    health._ci_status(Manifest(path=tmp_path / "m", name="n", purpose="p"),
                      findings)

    assert "--status completed" in seen["cmd"], \
        "must ask only for finished runs, or it judges itself"
    assert "--limit 1 " not in seen["cmd"], \
        "limit 1 is the run currently asking"
    assert findings[0].verdict is Verdict.PASS


def test_the_recurring_warning_names_what_is_recurring(tmp_path, monkeypatch):
    """The first live warning said only "1 finding reported 5+ times" and left
    the reader to go and look — the same defect it exists to catch, one level
    up: a message that costs work to act on gets skipped."""
    from sentinel.checks import health
    from sentinel.manifest import Manifest

    monkeypatch.setattr(
        health, "history",
        type("H", (), {
            "recurring": staticmethod(lambda root, **kw: [
                {"check": "health", "title": "The latest CI run is green",
                 "verdict": "unknown", "count": 9, "remedy": "r"}]),
            "load": staticmethod(lambda root, limit=5: [
                {"findings": [{"check": "health",
                               "title": "The latest CI run is green",
                               "title_he": "ההרצה האחרונה של ה-CI ירוקה"}]}]),
        })(),
        raising=False)
    findings = []
    health._recurring(Manifest(path=tmp_path / "m", name="n", purpose="p"),
                      findings)
    assert "ההרצה האחרונה" in findings[0].evidence
    assert "9" in findings[0].evidence


def test_a_high_severity_warning_carries_its_list():
    """The recurring-finding warning said "1 finding reported 5+ times" and
    withheld WHICH — the exact defect it exists to catch, one level up. A
    warning that names a list is not a code dump; it is the finding itself."""
    from sentinel.verdict import Severity
    w = Finding(check="health", title="recurring", title_he="ממצא חוזר",
                verdict=Verdict.WARN, severity=Severity.HIGH,
                detail="1 finding", detail_he="ממצא אחד",
                evidence="ההרצה האחרונה של ה-CI ירוקה — דווח 9 פעמים")
    msg = telegram.format_audit(audit(w))
    assert "ההרצה האחרונה" in msg


def test_a_low_severity_warning_stays_quiet():
    """An untidy .gitignore does not need its file list in the message."""
    from sentinel.verdict import Severity
    w = Finding(check="security", title="tidy", verdict=Verdict.WARN,
                severity=Severity.LOW, detail="d",
                evidence="a.py\nb.py\nc.py")
    assert "a.py" not in telegram.format_audit(audit(w))
