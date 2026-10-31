from pathlib import Path

from app.db import Job
from app.scanners.nmap_runner import ingest_nmap_results

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_sample.xml"


def test_dashboard_counts(auth):
    with auth.app.state.SessionLocal() as db:
        job = Job(kind="nmap", status="done")
        db.add(job)
        db.commit()
        ingest_nmap_results(db, job, FIXTURE.read_text())
        db.commit()
    r = auth.get("/")
    assert r.status_code == 200
    assert 'data-stat="hosts">2<' in r.text
    assert 'data-stat="services">5<' in r.text
    assert "Quick start" in r.text


# ----------------------------------------------------------------- trends card
def _seed_trend(client):
    from datetime import timedelta

    from app.db import Issue, Scope, SurfaceChange, utcnow
    now = utcnow()
    with client.app.state.SessionLocal() as db:
        s = Scope(name="<script>alert(1)</script>", targets="192.0.2.0/24")
        db.add(s)
        db.flush()
        for n, (sev, status, first, res) in enumerate((("critical", "new", 40, None), ("high", "verified", 20, 5),
                                                        ("medium", "triaged", 10, None))):
            db.add(Issue(key=f"192.0.2.{n}:80|t{n}", asset=f"192.0.2.{n}:80", severity=sev, status=status,
                         first_seen=now - timedelta(days=first), resolved_at=now - timedelta(days=res) if res else None,
                         due_at=now - timedelta(days=first - 7), scope_id=s.id if n == 0 else None))
        db.add(SurfaceChange(kind="port_opened", address="192.0.2.9", port=8080, created_at=now - timedelta(days=2)))
        db.commit()
        return s.id


def test_dashboard_trends_card(auth):
    sid = _seed_trend(auth)
    r = auth.get("/")
    assert r.status_code == 200 and 'id="trends-card"' in r.text
    for title in ("Open exposure", "New vs resolved", "Mean time to remediate (days)", "SLA compliance (%)",
                  "Surface changes"):
        assert title in r.text
    assert r.text.count('class="chart-hit"') == 5 * 13                 # default 90 days → 13 weekly buckets
    assert '<option value="90" selected>' in r.text and 'name="trend_days"' in r.text and 'name="trend_scope"' in r.text
    assert r.text.count("<summary>Show data</summary>") == 5
    assert 'role="img"' in r.text and "<desc" in r.text
    r = auth.get("/?trend_days=30")
    assert r.text.count('class="chart-hit"') == 5 * 30 and '<option value="30" selected>' in r.text
    r = auth.get(f"/?trend_days=365&trend_scope={sid}")
    # the scope holds one open critical issue: MTTR, SLA and surface charts are empty for it
    assert r.text.count('class="chart-hit"') == 2 * 53 and f'<option value="{sid}" selected>' in r.text
    assert r.text.count("No data in this period") == 3


def test_dashboard_trends_bad_params_fall_back(auth):
    _seed_trend(auth)
    for q in ("trend_days=abc", "trend_days=7", "trend_scope=999", "trend_scope=x", "trend_days=&trend_scope=",
              "trend_scope=99999999999999999999999", "trend_scope=%C2%B2", "trend_scope=-1", "trend_days=99999999999999999999"):
        r = auth.get("/?" + q)
        assert r.status_code == 200 and r.text.count('class="chart-hit"') == 5 * 13, q


def test_dashboard_trends_escapes_scope_name(auth):
    _seed_trend(auth)
    r = auth.get("/")
    assert "<script>alert(1)</script>" not in r.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r.text


def test_dashboard_trends_viewer(auth):
    from tests.test_rbac import login_as, make_user
    _seed_trend(auth)
    make_user(auth, "vera", "viewer")
    login_as(auth, "vera")
    r = auth.get("/?trend_days=180")
    assert r.status_code == 200 and 'id="trends-card"' in r.text and r.text.count('class="chart-hit"') == 5 * 26


def test_dashboard_trends_empty_state(auth):
    r = auth.get("/")
    assert r.text.count("No data in this period") == 5 and 'class="chart-hit"' not in r.text
    assert r.text.count("<summary>Show data</summary>") == 5


def test_dashboard_trends_rendered_values(auth):
    import re

    from app import trends
    from app.db import utcnow
    _seed_trend(auth)
    r = auth.get("/")
    last = trends.buckets(90, utcnow())[-1]["range"]
    # the latest open-exposure bucket: issue 0 (critical) and issue 2 (medium) are open
    label = f"{last}: 1 critical, 0 high, 1 medium, 0 low (2 total)"
    assert f'aria-label="{label}" data-tip="{label}"' in r.text
    assert re.search(r'<rect class="chart-hit" role="img" tabindex="0"[^>]*aria-label="' + re.escape(label), r.text)
    cells = "".join(f'<td class="num">{v}</td>' for v in (1, 0, 1, 0, 0, 2))
    assert f'<th scope="row">{last}</th>{cells}' in r.text
    # one tab stop per chart (roving tabindex), the rest are reached with the arrow keys
    assert len(re.findall(r'class="chart-hit" role="img" tabindex="0"', r.text)) == 5
    assert len(re.findall(r'class="chart-hit" role="img" tabindex="-1"', r.text)) == 5 * 12
    assert 'role="group" aria-roledescription="chart"' in r.text and 'role="img" aria-labelledby' not in r.text
    assert '<g class="chart-marks" aria-hidden="true">' in r.text and '<g class="chart-axis" aria-hidden="true">' in r.text


def test_dashboard_trends_form(auth):
    r = auth.get("/")
    assert 'action="/#trends-card"' in r.text and "data-autosubmit" in r.text
    assert '<button type="submit" class="sm" data-trend-apply>Apply</button>' in r.text     # visible for keyboards
