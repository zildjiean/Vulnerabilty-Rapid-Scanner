import json

from app.db import Finding
from app.proof import PROOF_LIMIT, proof_from_finding


def finding(raw: dict, **cols) -> Finding:
    base = dict(id=7, job_id=3, template_id="CVE-2026-109619", template_name="PHP UAF", severity="critical",
                host="http://192.0.2.11:8080", matched_at="http://192.0.2.11:8080/index.php", type="http")
    base.update(cols)
    return Finding(raw_json=json.dumps(raw), **base)


def test_http_finding_has_request_response_curl_and_matcher():
    raw = {"request": "GET /index.php HTTP/1.1\r\nHost: x\r\n\r\n", "response": "HTTP/1.1 200 OK\r\n\r\nX-Powered-By: PHP/8.3.10",
           "curl-command": "curl -X GET http://192.0.2.11:8080/index.php", "matcher-name": "version", "matcher-status": True,
           "extracted-results": ["8.3.10"], "timestamp": "2026-10-31T09:00:00Z"}
    p = proof_from_finding(finding(raw))
    assert p["has_http"] is True
    assert p["request"]["text"].startswith("GET /index.php") and p["request"]["rest"] == ""
    assert "PHP/8.3.10" in p["response"]["text"]
    assert p["curl"].startswith("curl ") and p["matcher"] == "version" and p["extracted"] == ["8.3.10"]
    assert p["finding_id"] == 7 and p["job_id"] == 3 and p["timestamp"] == "2026-10-31T09:00:00Z"


def test_non_http_finding_only_has_metadata():
    p = proof_from_finding(finding({"matcher-status": True}, type="tcp", matched_at="203.0.113.40:6379"))
    assert p["has_http"] is False and p["request"] is None and p["response"] is None and p["curl"] == ""
    assert p["matched_at"] == "203.0.113.40:6379" and p["type"] == "tcp"


def test_long_response_is_split_at_the_limit_and_bad_json_is_tolerated():
    p = proof_from_finding(finding({"response": "A" * (PROOF_LIMIT + 10)}))
    assert len(p["response"]["text"]) == PROOF_LIMIT and p["response"]["rest"] == "A" * 10
    assert proof_from_finding(Finding(id=1, job_id=1, raw_json="{not json"))["has_http"] is False
    assert proof_from_finding(None) is None
