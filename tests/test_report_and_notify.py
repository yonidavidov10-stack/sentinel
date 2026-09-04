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
