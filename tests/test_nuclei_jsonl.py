from pathlib import Path

from app.parsers.nuclei_jsonl import parse_nuclei_jsonl

FIXTURE = Path(__file__).parent / "fixtures" / "nuclei_sample.jsonl"


def test_parses_findings_and_skips_non_json_lines():
    findings = parse_nuclei_jsonl(FIXTURE.read_text())
    assert len(findings) == 2
    first = findings[0]
    assert first["template_id"] == "php-detect"
    assert first["template_name"] == "PHP Detect"
    assert first["severity"] == "info"
    assert first["host"] == "http://192.168.1.10:8080"
    assert first["matched_at"] == "http://192.168.1.10:8080/"
    assert first["type"] == "http"
    assert first["extracted"] == "8.3.10"
    assert first["raw"]["template-id"] == "php-detect"


def test_missing_fields_default():
    findings = parse_nuclei_jsonl('{"template-id":"x"}\n')
    assert findings[0]["severity"] == "unknown"
    assert findings[0]["template_name"] == ""
    assert findings[0]["extracted"] == ""


def test_empty_input():
    assert parse_nuclei_jsonl("") == []
    assert parse_nuclei_jsonl("\n\n") == []
