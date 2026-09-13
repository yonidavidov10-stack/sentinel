"""
test_backup.py
--------------
The second copy of what cannot be recreated, and the three states that are
easy to confuse:

  the drive is unplugged      -> UNKNOWN. Not a missing backup.
  the destination is empty    -> FAIL. Configured, and holding nothing.
  the newest copy is stale    -> WARN, naming how old.

The middle one is the trap. An empty backup directory is worse than no
directory at all, because it reads as configured to everyone who looks.

The first one is the one that decides whether this check survives contact with
reality: an external SSD is unplugged on most days, so reporting FAIL then
would fire constantly, mean nothing, and teach its reader to skim the line that
the one real finding will eventually appear on.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.checks import security                  # noqa: E402
from sentinel.manifest import Manifest                # noqa: E402
from sentinel.verdict import Severity, Verdict        # noqa: E402


def _m(tmp_path, **sec):
    (tmp_path / "book.db").write_bytes(b"x")
    return Manifest(path=tmp_path / "SENTINEL.toml", name="t", purpose="p",
                    security={"irreplaceable": ["book.db"], **sec})


def _one(m):
    out = []
    security._irreplaceable_has_a_second_copy(m, out)
    assert out
    return out[0]


def test_an_unplugged_drive_is_unknown_not_a_failure(tmp_path):
    f = _one(_m(tmp_path, second_copy="/Volumes/NotMounted/Backups"))
    assert f.verdict is Verdict.UNKNOWN
    assert "not plugged in" in f.detail
    assert f.verdict.is_actionable, \
        "'I could not look' must stay visible, just not alarming"


def test_a_reachable_but_empty_destination_is_critical(tmp_path):
    dest = tmp_path / "backups"
    dest.mkdir()
    f = _one(_m(tmp_path, second_copy=str(dest)))
    assert f.verdict is Verdict.FAIL
    assert f.severity is Severity.CRITICAL
    assert "reads as configured" in f.remedy


def test_a_fresh_copy_passes_and_names_its_age(tmp_path):
    dest = tmp_path / "backups"
    (dest / "2026-09-13").mkdir(parents=True)
    f = _one(_m(tmp_path, second_copy=str(dest)))
    assert f.verdict is Verdict.PASS
    assert "2026-09-13" in f.detail


def test_a_stale_copy_warns_with_the_number_of_days(tmp_path):
    dest = tmp_path / "backups"
    old = dest / "2026-06-01"
    old.mkdir(parents=True)
    hundred_days = time.time() - 100 * 86400
    os.utime(old, (hundred_days, hundred_days))
    f = _one(_m(tmp_path, second_copy=str(dest)))
    assert f.verdict is Verdict.WARN
    assert "100 days old" in f.detail
    assert "past the 45 declared" in f.detail


def test_the_threshold_is_the_projects_to_set(tmp_path):
    dest = tmp_path / "backups"
    old = dest / "2026-08-01"
    old.mkdir(parents=True)
    ten_days = time.time() - 10 * 86400
    os.utime(old, (ten_days, ten_days))
    assert _one(_m(tmp_path, second_copy=str(dest))).verdict is Verdict.PASS
    assert _one(_m(tmp_path, second_copy=str(dest),
                   second_copy_max_age_days=5)).verdict is Verdict.WARN


def test_macos_dotfiles_do_not_count_as_a_backup(tmp_path):
    """exFAT drives collect `._` AppleDouble files beside everything. Counting
    one as a snapshot would report a backup that does not exist."""
    dest = tmp_path / "backups"
    dest.mkdir()
    (dest / "._2026-09-13").write_bytes(b"\x00")
    f = _one(_m(tmp_path, second_copy=str(dest)))
    assert f.verdict is Verdict.FAIL, "only real entries count"


def test_a_described_location_is_trusted_and_says_so(tmp_path):
    """'monthly to the safe' is a legitimate answer that cannot be verified.
    It passes, and the detail admits the freshness is unchecked rather than
    implying it was confirmed."""
    f = _one(_m(tmp_path, second_copy="monthly, printed and filed"))
    assert f.verdict is Verdict.PASS
    assert "taken on trust" in f.detail
