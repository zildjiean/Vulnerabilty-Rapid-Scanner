"""Chart geometry for server-rendered SVG (no JS chart library: the container must work offline).

Every function takes trend points (app.trends) and returns coordinates in a W x H viewBox; Jinja draws them
(templates/_chart_macros.html). Text is never placed here as markup, only as strings Jinja escapes.
"""
from __future__ import annotations

import math

W, H = 640, 220
ML, MR, MT, MB = 40, 12, 12, 28          # plot margins: left (y labels), right, top, bottom (x labels)
PW, PH = W - ML - MR, H - MT - MB
BOTTOM = MT + PH
GAP = 2                                  # surface-coloured gap between stacked segments and between bars
MAX_XLABELS = 6
RADIUS = 4                               # rounded top of the topmost segment
MARKER_R = 4                             # 8 px markers
XLABEL_HALF = 22                         # half the width of an 11 px "Mmm dd" label, plus a little room


def nice_ticks(vmax: float, max_ticks: int = 5, integer: bool = True) -> list:
    """Ticks from 0 in 1-2-5 steps reaching at least ``vmax``, at most ``max_ticks`` of them."""
    vmax = vmax if vmax and vmax > 0 else 1
    raw = vmax / (max_ticks - 1)
    mag = 10 ** math.floor(math.log10(raw))
    step = next(m * mag for m in (1, 2, 5, 10) if m * mag >= raw * (1 - 1e-9))
    if integer:
        step = max(1, step)
    n = math.ceil(vmax / step - 1e-9)
    return [_clean(round(k * step, 10)) for k in range(n + 1)]


def _clean(v: float):
    return int(v) if float(v).is_integer() else v


def _fmt(v) -> str:
    return f"{v:g}" if isinstance(v, float) else str(v)


def compact(v) -> str:
    """Axis label: 950, 1.2k, 2.5M."""
    for div, suffix in ((1_000_000, "M"), (1_000, "k")):
        if abs(v) >= div:
            return f"{round(v / div, 1):g}{suffix}"
    return _fmt(v)


def _slots(n: int) -> float:
    return PW / max(n, 1)


def _scale(top: float):
    return lambda v: PH * (v or 0) / top


def _axis(ticks: list) -> list[dict]:
    top = ticks[-1]
    return [{"value": t, "label": compact(t), "y": round(BOTTOM - PH * t / top, 2)} for t in ticks]


def _xlabels(points: list[dict]) -> list[dict]:
    n, sw = len(points), _slots(len(points))
    k = min(MAX_XLABELS, n)
    idx = sorted({round(i * (n - 1) / (k - 1)) for i in range(k)}) if k > 1 else [0] if n else []
    # centres are kept XLABEL_HALF inside the viewBox so "Oct 31" under a narrow last bucket is not cut off
    return [{"x": round(min(max(ML + sw * (i + .5), XLABEL_HALF), W - XLABEL_HALF), 2), "y": H - 9,
             "label": points[i]["label"]} for i in idx]


def _hits(points: list[dict], labels: list[str]) -> list[dict]:
    """One full-height target per bucket. Roving tabindex: only the latest bucket is a tab stop; app.js moves
    between buckets with the arrow keys."""
    sw, last = _slots(len(points)), len(points) - 1
    return [{"x": round(ML + sw * n, 2), "y": MT, "w": round(sw, 2), "h": PH, "label": lab, "tip": lab,
             "tabindex": 0 if n == last else -1} for n, lab in enumerate(labels)]


def _bar_path(x: float, y: float, w: float, h: float, r: float = 0) -> str:
    """A bar with only its top corners rounded by ``r``."""
    r = max(0.0, min(r, w / 2, h))
    if r == 0:
        return f"M{x:.2f},{y + h:.2f}V{y:.2f}H{x + w:.2f}V{y + h:.2f}Z"
    return (f"M{x:.2f},{y + h:.2f}V{y + r:.2f}Q{x:.2f},{y:.2f} {x + r:.2f},{y:.2f}"
            f"H{x + w - r:.2f}Q{x + w:.2f},{y:.2f} {x + w:.2f},{y + r:.2f}V{y + h:.2f}Z")


def _frame(points: list[dict], ticks: list, labels: list[str], empty: bool) -> dict:
    return {"w": W, "h": H, "left": ML, "right": W - MR, "bottom": BOTTOM, "ticks": _axis(ticks),
            "xlabels": _xlabels(points), "hits": _hits(points, labels), "empty": empty}


def stacked_bars(points: list[dict], keys: tuple, names: dict | None = None, field: str = "open") -> dict:
    """One bar per bucket stacked bottom → top in ``keys`` order, from ``point[field][key]``."""
    names = names or {k: k for k in keys}
    totals = [sum(p[field].get(k, 0) for k in keys) for p in points]
    ticks = nice_ticks(max(totals, default=0) * 1.1)       # headroom for the total label on the last bar
    sc, sw = _scale(ticks[-1]), _slots(len(points))
    bw = sw - max(GAP, sw * .25)
    bars = []
    for n, p in enumerate(points):
        x, y, segs = ML + sw * n + (sw - bw) / 2, BOTTOM, []
        for k in keys:
            v = p[field].get(k, 0)
            if not v:
                continue
            h = sc(v)
            y -= h
            segs.append({"key": k, "value": v, "x": round(x, 2), "y": y, "w": round(bw, 2), "h": h, "top": False})
        if segs:
            segs[-1]["top"] = True
        for i, s in enumerate(segs):
            # the gap is cut from the bottom of every segment above another one, so the bar keeps its height;
            # a segment no taller than the gap keeps its full height instead of vanishing (it never overlaps)
            s["dh"] = s["h"] - GAP if i and s["h"] > GAP else s["h"]
            s["d"] = _bar_path(s["x"], s["y"], s["w"], s["dh"], RADIUS if s["top"] else 0)
        bars.append({"x": round(x, 2), "w": round(bw, 2), "y": BOTTOM - sc(totals[n]), "h": sc(totals[n]),
                     "total": totals[n], "segments": segs})
    labels = [f"{p['range']}: " + ", ".join(f"{p[field].get(k, 0)} {names[k]}" for k in reversed(keys))
              + f" ({t} total)" for p, t in zip(points, totals)]
    out = _frame(points, ticks, labels, not any(totals))
    last = bars[-1] if bars else None
    out["bars"] = bars
    out["total_label"] = ({"x": round(last["x"] + last["w"] / 2, 2), "y": round(last["y"] - 6, 2),
                           "text": str(last["total"])} if last and last["total"] else None)
    return out


def grouped_bars(points: list[dict], keys: tuple, names: dict | None = None) -> dict:
    """Side-by-side bars per bucket (e.g. new vs resolved), ``GAP`` px apart."""
    names = names or {k: k for k in keys}
    peak = max((p[k] or 0 for p in points for k in keys), default=0)
    ticks = nice_ticks(peak)
    sc, sw = _scale(ticks[-1]), _slots(len(points))
    gw = sw - max(GAP, sw * .25)
    bw = (gw - GAP * (len(keys) - 1)) / len(keys)
    groups = []
    for n, p in enumerate(points):
        x0, bars = ML + sw * n + (sw - gw) / 2, []
        for j, k in enumerate(keys):
            h = sc(p[k])
            x = x0 + j * (bw + GAP)
            bars.append({"key": k, "value": p[k], "x": round(x, 2), "y": BOTTOM - h, "w": round(bw, 2), "h": h,
                         "d": _bar_path(x, BOTTOM - h, bw, h, 2) if h else ""})
        groups.append({"bars": bars})
    labels = [f"{p['range']}: " + ", ".join(f"{p[k]} {names[k]}" for k in keys) for p in points]
    out = _frame(points, ticks, labels, not peak)
    out["groups"] = groups
    return out


def line(points: list[dict], key: str, ymax: float | None = None, unit: str = "", integer: bool = True) -> dict:
    """A 2 px line through the non-null values, broken at gaps (None), with a marker on every value."""
    values = [p[key] for p in points]
    ticks = nice_ticks(ymax if ymax else max((v for v in values if v is not None), default=0), integer=integer)
    sc, sw = _scale(ticks[-1]), _slots(len(points))
    segments, markers, cur = [], [], []
    for n, v in enumerate(values):
        if v is None:
            if cur:
                segments.append(cur)
            cur = []
            continue
        pt = {"x": round(ML + sw * (n + .5), 2), "y": round(BOTTOM - sc(v), 2), "value": v}
        cur.append(pt)
        markers.append({"cx": pt["x"], "cy": pt["y"], "r": MARKER_R, "value": v})
    if cur:
        segments.append(cur)
    segs = [{"points": s, "d": "M" + " L".join(f"{q['x']},{q['y']}" for q in s)} for s in segments]
    labels = [f"{p['range']}: " + (f"{_fmt(v)}{unit}" if v is not None else "no data")
              for p, v in zip(points, values)]
    out = _frame(points, ticks, labels, all(v is None for v in values))
    out["segments"], out["markers"] = segs, markers
    return out


# ----------------------------------------------------------------- the trend charts
SEVERITY_STACK = ("low", "medium", "high", "critical")   # bottom → top


def _range_text(lo, hi, unit: str) -> str:
    return f"{_fmt(lo)}{unit}" if lo == hi else f"{_fmt(lo)}{unit} to {_fmt(hi)}{unit}"


def trend_charts(t: dict, surface: bool = True) -> list[dict]:
    """The Trends card: open exposure, new vs resolved, MTTR, SLA and (optionally) surface changes."""
    pts, per = t["points"], t["bucket"]
    period = "Period" if per == "week" else "Day"
    out = []

    out.append({
        "id": "open", "kind": "stacked", "title": "Open exposure",
        "subtitle": f"Open issues at the end of each {per}, by severity",
        "desc": f"Open issues went from {pts[0]['open_total']} to {pts[-1]['open_total']}.",
        "legend": [(f"c-{k}", k.capitalize()) for k in reversed(SEVERITY_STACK)],
        "g": stacked_bars(pts, SEVERITY_STACK),
        "head": [period, "Critical", "High", "Medium", "Low", "Other", "Total"],
        "rows": [[p["range"], *(p["open"][k] for k in reversed(SEVERITY_STACK)), p["other"], p["open_total"]]
                 for p in pts]})

    new, res = sum(p["new"] for p in pts), sum(p["resolved"] for p in pts)
    out.append({
        "id": "flow", "kind": "grouped", "title": "New vs resolved",
        "subtitle": f"Issues first seen and issues resolved per {per}",
        "desc": f"{new} new and {res} resolved issues in this period.",
        "legend": [("c-1", "New"), ("c-2", "Resolved")],
        "g": grouped_bars(pts, ("new", "resolved")),
        "head": [period, "New", "Resolved"], "rows": [[p["range"], p["new"], p["resolved"]] for p in pts]})

    vals = [p["mttr_days"] for p in pts if p["mttr_days"] is not None]
    out.append({
        "id": "mttr", "kind": "line", "title": "Mean time to remediate (days)",
        "subtitle": f"First seen to fixed, for issues remediated in each {per}",
        "desc": (f"Mean time to remediate ranged from {_range_text(min(vals), max(vals), ' days')}." if vals
                 else "No issues were remediated in this period."),
        "legend": [], "g": line(pts, "mttr_days", unit=" days", integer=False),
        "head": [period, "Days", "Remediated"],
        "rows": [[p["range"], "—" if p["mttr_days"] is None else _fmt(p["mttr_days"]), p["remediated"]] for p in pts]})

    vals = [p["sla_pct"] for p in pts if p["sla_pct"] is not None]
    out.append({
        "id": "sla", "kind": "line", "title": "SLA compliance (%)",
        "subtitle": "Remediated issues with a due date that were fixed on time",
        "desc": (f"SLA compliance ranged from {_range_text(min(vals), max(vals), '%')}." if vals
                 else "No issues with a due date were remediated in this period."),
        "legend": [], "g": line(pts, "sla_pct", ymax=100, unit="%"),
        "head": [period, "On time", "With due date"],
        "rows": [[p["range"], "—" if p["sla_pct"] is None else f"{p['sla_pct']}%", p["with_due"]] for p in pts]})

    if surface:
        add, oth = sum(p["surface_added"] for p in pts), sum(p["surface_other"] for p in pts)
        out.append({
            "id": "surface", "kind": "grouped", "title": "Surface changes",
            "subtitle": "New hosts and opened ports vs closed ports, changed services and hosts gone",
            "desc": f"{add} added and {oth} other attack-surface changes in this period.",
            "legend": [("c-1", "Added"), ("c-2", "Other")],
            "g": grouped_bars(pts, ("surface_added", "surface_other"),
                              {"surface_added": "added", "surface_other": "other"}),
            "head": [period, "Added", "Other"],
            "rows": [[p["range"], p["surface_added"], p["surface_other"]] for p in pts]})
    return out
