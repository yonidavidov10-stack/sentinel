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


# ── a key the handler never reads ──────────────────────────────────────
#
# The defect: an expectation written with `path` and `expect` where the grep
# handler reads `paths` and `must_match`. Both were dropped into `config` and
# never looked at, so the check ran on its defaults — search everything,
# require a match — found a match in the manifest's own prose, and reported
# PASS while the line it existed to forbid sat in the workflow untouched.

load = mf.load


def _write(tmp_path, body: str):
    (tmp_path / "SENTINEL.toml").write_text(
        '[project]\nname = "t"\npurpose = "p"\n' + body, encoding="utf-8")
    return load(tmp_path)


def test_a_misspelled_key_makes_the_expectation_unknown(tmp_path):
    m = _write(tmp_path, '''
[[expectations]]
id = "x"
says = "the pattern is absent"
kind = "grep"
pattern = "nope"
path = "a.yml"
expect = "absent"
''')
    e = m.expectations[0]
    assert e.unknown_keys == ["expect", "path"]
    assert not e.known, "an expectation the handler cannot read is not checkable"


def test_the_error_names_the_nearest_real_key(tmp_path):
    """Naming the typo is the difference between a fix and a puzzle."""
    m = _write(tmp_path, '''
[[expectations]]
id = "x"
says = "s"
kind = "grep"
pattern = "p"
path = "a.yml"
''')
    joined = " ".join(m.errors)
    assert "'path'" in joined and "'paths'" in joined


def test_correct_keys_raise_nothing(tmp_path):
    m = _write(tmp_path, '''
[[expectations]]
id = "x"
says = "s"
kind = "grep"
pattern = "p"
paths = ["a.yml"]
must_match = false
ignore_comments = true
remedy = "r"
remedy_he = "ר"
''')
    assert m.expectations[0].unknown_keys == []
    assert m.expectations[0].known
    assert m.errors == []


def test_an_unknown_kind_is_not_also_reported_as_a_key_problem(tmp_path):
    """One promise, one finding. An unrecognised kind has no key list to
    check against, and inventing one would bury the real message."""
    m = _write(tmp_path, '''
[[expectations]]
id = "x"
says = "s"
kind = "telepathy"
whatever = 1
''')
    assert m.expectations[0].unknown_keys == []
    assert any("telepathy" in e for e in m.errors)


def test_config_keys_matches_what_the_handlers_read():
    """The table of legal keys is derived from the handlers, or it is fiction.

    Written from memory the first time, it invented `expect_output` and
    `forbid_output` and missed `expect_stdout_contains` and
    `expect_stdout_absent` — which the command handler genuinely reads. Four
    working expectations would have been reported broken: the same failure as
    the one this validation exists to catch, pointing the other way.

    So the truth is read out of the source. A new key in a handler, or one
    removed, fails here rather than months later in a report nobody can
    explain.
    """
    import ast

    src = Path(mf.__file__).parent / "checks" / "intent.py"
    tree = ast.parse(src.read_text(encoding="utf-8"))

    for fn in [n for n in tree.body
               if isinstance(n, ast.FunctionDef) and n.name.startswith("_check_")]:
        kind = fn.name.removeprefix("_check_")
        if kind not in mf.CONFIG_KEYS:
            continue
        read = set()
        for node in ast.walk(fn):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get"
                    and isinstance(node.func.value, ast.Attribute)
                    and node.func.value.attr == "config"
                    and node.args and isinstance(node.args[0], ast.Constant)):
                read.add(node.args[0].value)
        declared = mf.CONFIG_KEYS[kind] | mf.COMMON_CONFIG_KEYS
        assert read <= declared, (
            f"kind={kind!r} reads {sorted(read - declared)}, which CONFIG_KEYS "
            f"would reject as a typo")
        invented = mf.CONFIG_KEYS[kind] - read
        assert not invented, (
            f"CONFIG_KEYS[{kind!r}] allows {sorted(invented)}, which no handler "
            f"reads — an expectation using them would pass validation and still "
            f"be ignored")
