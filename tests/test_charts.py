from datetime import datetime, timedelta

import pytest

from app import charts

SEV = ("low", "medium", "high", "critical")


def pts(values, key=None):
    """Points shaped like app.trends output; ``values`` are dicts (or scalars for ``key``)."""
    end = datetime(2026, 10, 31, 12, 0)
    out = []
    for n, v in enumerate(values):
        e = end - timedelta(days=7 * (len(values) - 1 - n))
        p = {"start": e - timedelta(days=7), "end": e, "label": f"Oct {n + 1}", "range": f"R{n}"}
        p.update(v if key is None else {key: v})
        out.append(p)
    return out


def sev(c=0, h=0, m=0, lo=0):
    return {"open": {"critical": c, "high": h, "medium": m, "low": lo}}


# ----------------------------------------------------------------- ticks
@pytest.mark.parametrize("vmax,expected", [
    (0, [0, 1]), (1, [0, 1]), (3, [0, 1, 2, 3]), (4, [0, 1, 2, 3, 4]), (5, [0, 2, 4, 6]), (7, [0, 2, 4, 6, 8]),
    (9, [0, 5, 10]), (40, [0, 10, 20, 30, 40]), (41, [0, 20, 40, 60]), (100, [0, 50, 100]), (230, [0, 100, 200, 300]),
])
def test_nice_ticks(vmax, expected):
    assert charts.nice_ticks(vmax) == expected


def test_nice_ticks_fractional_and_bounded():
    assert charts.nice_ticks(0.3, integer=False) == [0, 0.1, 0.2, 0.3]
    assert charts.nice_ticks(2.6, integer=False) == [0, 1, 2, 3]
    for v in (1, 2, 6, 11, 17, 99, 101, 999, 12345):
        t = charts.nice_ticks(v)
        assert len(t) <= 5 and t[0] == 0 and t[-1] >= v


# ----------------------------------------------------------------- stacked bars
def test_stacked_segments_sum_to_bar_height():
    c = charts.stacked_bars(pts([sev(1, 2, 3, 4), sev(0, 0, 0, 0), sev(5, 0, 0, 1)]), SEV)
    assert not c["empty"] and len(c["bars"]) == 3
    plot_bottom = charts.H - charts.MB
    for b in c["bars"]:
        assert sum(s["h"] for s in b["segments"]) == pytest.approx(b["h"])
        assert b["y"] + b["h"] == pytest.approx(plot_bottom)
        assert [s["key"] for s in b["segments"]] == [k for k in SEV if any(s["key"] == k for s in b["segments"])]
        if b["segments"]:
            assert b["segments"][0]["y"] + b["segments"][0]["h"] == pytest.approx(plot_bottom)
            assert b["segments"][-1]["top"] and not any(s["top"] for s in b["segments"][:-1])
    first = c["bars"][0]
    assert [s["key"] for s in first["segments"]] == ["low", "medium", "high", "critical"]   # bottom → top
    assert first["segments"][0]["h"] == pytest.approx(first["h"] * 0.4)
    assert c["bars"][1]["segments"] == [] and c["bars"][1]["total"] == 0
    assert c["total_label"]["text"] == "6" and c["total_label"]["y"] > charts.MT


def test_bars_stay_inside_the_plot_with_gaps():
    c = charts.stacked_bars(pts([sev(9, 9, 9, 9)] * 30), SEV)
    xs = [(b["x"], b["x"] + b["w"]) for b in c["bars"]]
    assert xs[0][0] >= charts.ML and xs[-1][1] <= charts.W - charts.MR
    assert all(b[0] - a[1] >= 2 for a, b in zip(xs, xs[1:]))
    assert all(s["d"].startswith("M") for b in c["bars"] for s in b["segments"])


def test_hit_rects_one_per_bucket_and_labelled():
    c = charts.stacked_bars(pts([sev(12, 1, 0, 0), sev(0, 0, 2, 0)]), SEV,
                            names={"critical": "critical", "high": "high", "medium": "medium", "low": "low"})
    assert len(c["hits"]) == 2
    h = c["hits"][0]
    assert h["label"].startswith("R0: 12 critical, 1 high, 0 medium, 0 low") and h["tip"] == h["label"]
    assert h["y"] == charts.MT and h["h"] == charts.H - charts.MT - charts.MB
    assert h["w"] > c["bars"][0]["w"]


def test_empty_chart():
    c = charts.stacked_bars(pts([sev()] * 4), SEV)
    assert c["empty"] and len(c["hits"]) == 4


def test_x_labels_at_most_six():
    assert len(charts.stacked_bars(pts([sev(1)] * 30), SEV)["xlabels"]) == 6
    labels = charts.stacked_bars(pts([sev(1)] * 3), SEV)["xlabels"]
    assert [x["label"] for x in labels] == ["Oct 1", "Oct 2", "Oct 3"]
    xs = [x["x"] for x in charts.stacked_bars(pts([sev(1)] * 53), SEV)["xlabels"]]
    assert all(b - a >= 60 for a, b in zip(xs, xs[1:]))          # no overlapping labels


# ----------------------------------------------------------------- grouped bars
def test_grouped_bars():
    c = charts.grouped_bars(pts([{"new": 4, "resolved": 2}, {"new": 0, "resolved": 1}]), ("new", "resolved"))
    assert len(c["groups"]) == 2 and len(c["hits"]) == 2
    a, b = c["groups"][0]["bars"]
    assert a["key"] == "new" and b["key"] == "resolved"
    assert b["x"] - (a["x"] + a["w"]) == pytest.approx(2)
    assert a["h"] == pytest.approx(2 * b["h"])
    assert c["groups"][1]["bars"][0]["h"] == 0
    assert c["hits"][0]["label"] == "R0: 4 new, 2 resolved"
    assert charts.grouped_bars(pts([{"new": 0, "resolved": 0}]), ("new", "resolved"))["empty"]


# ----------------------------------------------------------------- lines
def test_line_breaks_at_none():
    c = charts.line(pts([1.0, 2.0, None, 4.0, None, None, 3.0, 5.0], "mttr_days"), "mttr_days", integer=False)
    assert len(c["segments"]) == 3
    assert [len(s["points"]) for s in c["segments"]] == [2, 1, 2]
    assert len(c["markers"]) == 5 and all(m["r"] >= 4 for m in c["markers"])
    assert c["segments"][0]["d"].startswith("M") and "L" in c["segments"][0]["d"]
    assert len(c["hits"]) == 8 and "no data" in c["hits"][2]["label"]


def test_sla_line_y_max_is_100():
    c = charts.line(pts([20, 40], "sla_pct"), "sla_pct", ymax=100, unit="%")
    assert c["ticks"][-1]["value"] == 100
    plot_top = charts.MT
    assert all(m["cy"] > plot_top for m in c["markers"])
    c = charts.line(pts([100], "sla_pct"), "sla_pct", ymax=100, unit="%")
    assert c["markers"][0]["cy"] == pytest.approx(plot_top)
    assert c["hits"][0]["label"] == "R0: 100%"


def test_line_empty():
    assert charts.line(pts([None, None], "mttr_days"), "mttr_days")["empty"]


def test_x_labels_stay_inside_the_viewbox():
    for n in (3, 13, 30, 53):
        xs = [x["x"] for x in charts.stacked_bars(pts([sev(1)] * n), SEV)["xlabels"]]
        assert min(xs) - charts.XLABEL_HALF >= 0 and max(xs) + charts.XLABEL_HALF <= charts.W
