import pytest

from app.version_compare import (check_clauses, compare_versions, extract_version, parse_constraint, version_satisfies)


@pytest.mark.parametrize("a,b,expected", [
    ("8.3.10", "8.3.15", -1),
    ("8.3.15", "8.3.15", 0),
    ("10.0", "9.9", 1),
    ("1.0", "1.0.0", 0),
    ("1.0", "1.0rc1", 1),
    ("1.0rc1", "1.0rc2", -1),
    ("9.6p1", "9.6", 1),
    ("2.4.58", "2.4.6", 1),
])
def test_compare(a, b, expected):
    assert compare_versions(a, b) == expected


@pytest.mark.parametrize("raw,expected", [
    ("2.4.58 (Ubuntu)", "2.4.58"),
    ("9.6p1 Ubuntu 3ubuntu13", "9.6p1"),
    ("8.3.10", "8.3.10"),
    ("", None),
    (None, None),
    ("unknown", None),
    ("v1.24.0", "1.24.0"),
])
def test_extract_version(raw, expected):
    assert extract_version(raw) == expected


def test_parse_constraint():
    assert parse_constraint("< 8.3.15") == [("<", "8.3.15")]
    assert parse_constraint(">=8.0, <8.3.15") == [(">=", "8.0"), ("<", "8.3.15")]
    assert parse_constraint("==1.2.3") == [("==", "1.2.3")]
    assert parse_constraint("!=1.2.3") == [("!=", "1.2.3")]


@pytest.mark.parametrize("bad", ["", "8.3.15", "<", "~>1.0", "< 8.3.15 extra", "<=a b"])
def test_parse_constraint_invalid(bad):
    with pytest.raises(ValueError):
        parse_constraint(bad)


@pytest.mark.parametrize("version,constraint,expected", [
    ("8.3.10", "< 8.3.15", True),
    ("8.3.15", "< 8.3.15", False),
    ("8.3.15", "<= 8.3.15", True),
    ("7.4.33", ">=8.0,<8.3.15", False),
    ("8.2.0", ">=8.0,<8.3.15", True),
    ("8.4.1", ">=8.0,<8.3.15", False),
    ("1.2.3", "==1.2.3", True),
    ("1.2.3", "!=1.2.3", False),
    ("", "< 1", False),
    ("2.4.58 (Ubuntu)", "< 2.4.60", True),
])
def test_version_satisfies(version, constraint, expected):
    assert version_satisfies(version, constraint) is expected


def test_check_clauses_with_preparsed():
    clauses = parse_constraint("<8.3.15")
    assert check_clauses("8.3.14", clauses) is True
