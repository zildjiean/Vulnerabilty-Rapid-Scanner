from markupsafe import Markup

from app.ai_redact import Redactor
from app.mdlite import render_markdown


def test_redaction_round_trip():
    r = Redactor(["web01.corp.example", "10.0.0.5", "honey.scanme.sh"])
    text = ("Apache 2.4.49 on 10.0.0.5:443 (web01.corp.example) and 192.168.1.20, "
            "also honey.scanme.sh, and IPv6 2001:db8::7; advisory https://nvd.nist.gov/vuln/detail/CVE-2021-41773")
    red = r.redact(text)
    for secret in ("10.0.0.5", "web01.corp.example", "192.168.1.20", "honey.scanme.sh", "2001:db8::7"):
        assert secret not in red
    assert "nvd.nist.gov" in red and "2.4.49" in red and "CVE-2021-41773" in red
    assert red.count("HOST-") == 5
    assert r.redact("again 10.0.0.5") == "again " + r.mapping["10.0.0.5"]   # stable tokens
    assert r.restore(red) == text
    assert r.restore_data({"a": [red, {"b": "HOST-1"}], "n": 3}) == {"a": [text, {"b": r.reverse["HOST-1"]}], "n": 3}


def test_restore_longest_token_first():
    r = Redactor([f"10.0.0.{i}" for i in range(1, 12)])
    red = r.redact("10.0.0.1 and 10.0.0.11")
    assert r.restore(red) == "10.0.0.1 and 10.0.0.11"


def test_disabled_redactor_is_identity():
    r = Redactor(["10.0.0.5"], enabled=False)
    assert r.redact("10.0.0.5") == "10.0.0.5" and r.restore("HOST-1") == "HOST-1"


def test_markdown_is_escaped_and_minimal():
    html = render_markdown("## Fix\n\n- Upgrade **Apache** to `2.4.51`\n- <script>alert(1)</script>\n\n1. one\n2. two\n\n```\nsudo apt upgrade\n```\nplain [link](javascript:alert(1))")
    assert isinstance(html, Markup)
    assert "<h4>Fix</h4>" in html and "<strong>Apache</strong>" in html and "<code>2.4.51</code>" in html
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "<ol>" in html and "<pre><code>sudo apt upgrade</code></pre>" in html
    assert "<a" not in html and "href" not in html  # links are never rendered, so javascript: URLs stay inert text
