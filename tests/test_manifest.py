"""A promise must never fall out of the audit silently.

The loader's job is not to be lenient. A typo in a `kind` that quietly drops an
expectation removes a promise from the report while the report stays green —
the same shape as a CI step that collects zero tests and exits 0.
"""
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel import manifest as mf  # noqa: E402


def write(text: str) -> Path:
    d = Path(tempfile.mkdtemp())
    (d / mf.MANIFEST_NAME).write_text(text, encoding="utf-8")
    return d


BASE = '''
[project]
name = "demo"
purpose = "a demo"
'''


def test_a_missing_manifest_raises():
    with pytest.raises(mf.ManifestError):
        mf.load(Path(tempfile.mkdtemp()))


def test_invalid_toml_raises_rather_than_half_loading():
    with pytest.raises(mf.ManifestError):
        mf.load(write("[project\nname = broken"))


def test_a_missing_project_table_raises():
    with pytest.raises(mf.ManifestError):
        mf.load(write('[[expectations]]\nid="a"\nsays="b"\nkind="command"'))


def test_an_unknown_kind_is_KEPT_not_dropped():
    """The heart of it. Dropping it would remove a promise from the audit and
    leave the report green."""
    m = mf.load(write(BASE + '''
[[expectations]]
id = "typo"
says = "something important"
kind = "freshnes"
'''))
    assert len(m.expectations) == 1
    assert not m.expectations[0].known
    assert any("unknown kind" in e for e in m.errors)


def test_an_expectation_missing_a_required_key_is_reported():
    m = mf.load(write(BASE + '\n[[expectations]]\nid = "x"\nkind = "command"\n'))
    assert m.expectations == []
    assert any("says" in e for e in m.errors)


def test_a_duplicate_id_is_reported_rather_than_overwriting():
    """Two promises with one id means a report keyed by id silently shows one
    of them, and the reader is short a promise without knowing."""
    m = mf.load(write(BASE + '''
[[expectations]]
id = "same"
says = "first"
kind = "command"

[[expectations]]
id = "same"
says = "second"
kind = "command"
'''))
    assert len(m.expectations) == 1
    assert any("duplicate" in e for e in m.errors)


def test_an_unknown_severity_falls_back_and_says_so():
    m = mf.load(write(BASE + '''
[[expectations]]
id = "x"
says = "y"
kind = "command"
severity = "apocalyptic"
'''))
    assert m.expectations[0].severity == "medium"
    assert any("severity" in e for e in m.errors)


def test_config_keeps_everything_that_is_not_a_known_field():
    m = mf.load(write(BASE + '''
[[expectations]]
id = "x"
says = "y"
kind = "freshness"
path = "data/x.json"
max_age_hours = 30
'''))
    assert m.expectations[0].config == {"path": "data/x.json",
                                        "max_age_hours": 30}


def test_a_manifest_with_no_expectations_loads_but_is_empty():
    m = mf.load(write(BASE))
    assert m.expectations == []
    assert m.name == "demo"


def test_discover_finds_nested_projects():
    root = Path(tempfile.mkdtemp())
    for sub in ("a", "b/c"):
        d = root / sub
        d.mkdir(parents=True)
        (d / mf.MANIFEST_NAME).write_text(BASE, encoding="utf-8")
    found = mf.discover(root)
    assert len(found) == 2
