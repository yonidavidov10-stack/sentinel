"""The expectation kinds, and the rule that an unrunnable check is UNKNOWN."""
import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.manifest import Expectation, Manifest  # noqa: E402
from sentinel.checks import intent                    # noqa: E402
from sentinel.verdict import Verdict                  # noqa: E402


def exp(kind, **config):
    return Expectation(id="x", says="a promise", kind=kind, severity="high",
                       config=config)


@pytest.fixture
def root():
    return Path(tempfile.mkdtemp())


# ── command ────────────────────────────────────────────────────────────
def test_a_passing_command_passes(root):
    assert intent._check_command(exp("command", run="exit 0"), root).verdict \
        is Verdict.PASS


def test_a_failing_command_fails_with_its_output(root):
    f = intent._check_command(exp("command", run="echo boom; exit 3"), root)
    assert f.verdict is Verdict.FAIL
    assert "boom" in f.evidence


def test_a_command_with_no_run_key_is_unknown(root):
    assert intent._check_command(exp("command"), root).verdict is Verdict.UNKNOWN


def test_expected_output_that_is_missing_fails(root):
    f = intent._check_command(
        exp("command", run="echo hello", expect_stdout_contains=["goodbye"]), root)
    assert f.verdict is Verdict.FAIL


def test_forbidden_output_that_appears_fails(root):
    f = intent._check_command(
        exp("command", run="echo secret", expect_stdout_absent=["secret"]), root)
    assert f.verdict is Verdict.FAIL


def test_an_unknown_exit_code_reports_unknown_not_fail(root):
    """A check that cannot run WHERE it is running must not report a pass —
    and must not report a failure either. `launchctl list | grep -q` succeeds
    trivially on Linux, where there is no launchd at all."""
    f = intent._check_command(
        exp("command", run="exit 3", unknown_exit=3,
            unknown_reason="not a Mac"), root)
    assert f.verdict is Verdict.UNKNOWN
    assert "not a Mac" in f.detail


def test_a_timeout_is_unknown_not_a_failure(root):
    f = intent._check_command(exp("command", run="sleep 5", timeout_s=1), root)
    assert f.verdict is Verdict.UNKNOWN


# ── freshness ──────────────────────────────────────────────────────────
def _stamped(root: Path, hours_ago: float) -> str:
    ts = (datetime.now(timezone.utc) - timedelta(hours=hours_ago))
    (root / "s.json").write_text(
        json.dumps({"generated_at": ts.isoformat(timespec="seconds")}),
        encoding="utf-8")
    return "s.json"


def test_a_fresh_file_passes(root):
    p = _stamped(root, 2)
    assert intent._check_freshness(
        exp("freshness", path=p, field="generated_at", max_age_hours=30),
        root).verdict is Verdict.PASS


def test_a_stale_file_fails(root):
    """The check that would have caught 2026-08-29: nothing was broken in a way
    a test could see, a scheduled job just stopped producing output."""
    p = _stamped(root, 100)
    f = intent._check_freshness(
        exp("freshness", path=p, field="generated_at", max_age_hours=30), root)
    assert f.verdict is Verdict.FAIL
    assert "100" in f.detail or "99" in f.detail


def test_a_missing_file_fails(root):
    assert intent._check_freshness(
        exp("freshness", path="nope.json", max_age_hours=30),
        root).verdict is Verdict.FAIL


def test_an_unreadable_timestamp_is_unknown_not_stale(root):
    (root / "s.json").write_text(json.dumps({"generated_at": "yesterday"}),
                                 encoding="utf-8")
    assert intent._check_freshness(
        exp("freshness", path="s.json", field="generated_at", max_age_hours=30),
        root).verdict is Verdict.UNKNOWN


def test_freshness_without_max_age_is_unknown(root):
    _stamped(root, 1)
    assert intent._check_freshness(
        exp("freshness", path="s.json"), root).verdict is Verdict.UNKNOWN


# ── grep ───────────────────────────────────────────────────────────────
def test_a_required_pattern_that_is_present_passes(root):
    (root / "a.py").write_text("the guard is installed\n", encoding="utf-8")
    assert intent._check_grep(
        exp("grep", pattern="guard is installed", paths=["."], must_match=True),
        root).verdict is Verdict.PASS


def test_a_forbidden_pattern_that_appears_fails(root):
    (root / "a.py").write_text("hit_rate >= 0.70\n", encoding="utf-8")
    f = intent._check_grep(
        exp("grep", pattern=r">=\s*0\.70", paths=["."], must_match=False), root)
    assert f.verdict is Verdict.FAIL
    assert "a.py" in f.evidence


def test_comments_can_be_ignored(root):
    """An expectation that trips over its own documentation gets disabled, and
    a disabled expectation is a promise nobody is checking."""
    (root / "a.py").write_text("# the 0.70 target was retired\n", encoding="utf-8")
    e = exp("grep", pattern="0.70", paths=["."], must_match=False,
            ignore_comments=True)
    assert intent._check_grep(e, root).verdict is Verdict.PASS


def test_compiled_caches_are_not_scanned(root):
    """Reading a .pyc with errors='ignore' turns bytecode into a string that
    matches almost anything. A scanner that invents a match is worse than one
    that misses, because the false one gets investigated."""
    cache = root / "__pycache__"
    cache.mkdir()
    (cache / "a.pyc").write_bytes(b"\x00\x01needle\x02")
    assert intent._check_grep(
        exp("grep", pattern="needle", paths=["."], must_match=False),
        root).verdict is Verdict.PASS


def test_a_regex_python_warns_about_is_unknown_not_a_pass(root):
    """POSIX classes compile with only a warning and then match nothing. The
    expectation went green while checking nothing — passing for the wrong
    reason, which is the failure this whole tool exists to catch."""
    f = intent._check_grep(
        exp("grep", pattern="[[:space:]]x", paths=["."], must_match=False), root)
    assert f.verdict is Verdict.UNKNOWN
    assert "warns" in f.detail


def test_an_invalid_regex_is_unknown(root):
    assert intent._check_grep(
        exp("grep", pattern="(unclosed", paths=["."]), root).verdict \
        is Verdict.UNKNOWN


# ── the runner ─────────────────────────────────────────────────────────
def _manifest(root, expectations, errors=None):
    return Manifest(path=root / "SENTINEL.toml", name="t", purpose="p",
                    expectations=expectations, errors=errors or [])


def test_an_unknown_kind_reports_unknown_rather_than_vanishing(root):
    r = intent.check(_manifest(root, [exp("freshnes", path="x")]))
    assert any(f.verdict is Verdict.UNKNOWN for f in r.findings)


def test_a_manifest_error_becomes_a_finding(root):
    r = intent.check(_manifest(root, [exp("command", run="true")],
                               errors=["duplicate id 'x'"]))
    assert any("duplicate" in f.detail for f in r.findings)


def test_a_project_with_no_expectations_is_warned_about(root):
    r = intent.check(_manifest(root, []))
    assert any(f.verdict is Verdict.WARN for f in r.findings)


def test_a_crashing_handler_does_not_take_the_audit_down(root, monkeypatch):
    def boom(e, root):
        raise RuntimeError("handler exploded")
    monkeypatch.setitem(intent._HANDLERS, "command", boom)
    r = intent.check(_manifest(root, [exp("command", run="true")]))
    assert any(f.verdict is Verdict.UNKNOWN for f in r.findings)
