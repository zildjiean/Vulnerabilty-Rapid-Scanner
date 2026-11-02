"""User interface language: English (the source strings) and Thai (``app/i18n_th.py``).

The catalog key is the exact English source string; English is the fallback for anything without a Thai value.

- Templates: ``{{ t("Save") }}`` / ``{{ t("Deleted {n} service(s).", n=n) }}``. ``t`` is a Jinja global that reads
  the language of the request being rendered (``render()`` sets it), so it also works inside imported macros.
- Python: ``tr(request, "Saved")`` for flash messages, validation errors and other server-built UI text;
  ``flash(request, ...)`` returns the same text URL-encoded for a ``?msg=`` / ``?err=`` redirect.
- Messages raised from helper modules (``ValueError``) stay English in code; wrap the literal in ``Msg(...)`` so the
  text is known to the catalog checks and its placeholders survive: ``raise ValueError(Msg("Bad {x}", x=x))`` and
  ``tr(request, exc)`` where it is shown.
- Labels kept in Python dicts (status, role, preset, nav…) stay English and go through ``t()`` at display time.

Translations are plain text: Jinja autoescape escapes them like any other value. Never put markup in the catalog.
"""
from __future__ import annotations

import contextvars
import re
from urllib.parse import parse_qsl, quote_plus, urlencode, urlsplit, urlunsplit

from .i18n_th import CATALOG_TH

LANGS = ("en", "th")
LANG_NAMES = {"en": "English", "th": "ไทย"}
DEFAULT_LANG = "en"

# Thai lookups that found no catalog entry. Recorded only while RECORD_MISSING is on (the completeness tests turn it
# on), so free text that reaches tr() in production (provider errors etc.) cannot grow it.
RECORD_MISSING = False
MISSING: set[str] = set()

_current = contextvars.ContextVar("ui_lang", default=DEFAULT_LANG)


def _catalog() -> dict[str, str]:
    return CATALOG_TH


class Msg(str):
    """An English message plus its placeholders. ``str(m)`` is the English text, ``tr(request, m)`` translates the
    template and then fills the placeholders."""

    def __new__(cls, template: str, /, **params):
        try:
            text = template.format(**params) if params else template
        except (KeyError, IndexError, ValueError, AttributeError):
            text = template
        obj = super().__new__(cls, text)
        obj.template, obj.params = template, params
        return obj


def _format(text: str, params: dict) -> str:
    return text.format(**params)


def translate(lang: str, text, /, **params) -> str:
    """``text`` in ``lang`` (Thai catalog lookup, English fallback), then ``str.format(**params)``. Never raises."""
    if isinstance(text, BaseException):
        text = text.args[0] if text.args else str(text)
    if isinstance(text, Msg):
        params = {**text.params, **params}
        text = text.template
    if params:  # nested messages (e.g. "Targets: {error}" with a validator's Msg) are translated too
        params = {k: translate(lang, v) if isinstance(v, Msg) else v for k, v in params.items()}
    src = "" if text is None else str(text)
    out = src
    if lang == "th" and src:
        th = _catalog().get(src)
        if th:
            out = th
        elif RECORD_MISSING:
            MISSING.add(src)
    if not params:
        return out
    try:
        return _format(out, params)
    except (KeyError, IndexError, ValueError, AttributeError):
        try:
            return _format(src, params)
        except (KeyError, IndexError, ValueError, AttributeError):
            return src


# ----------------------------------------------------------------- request language
_TAG = re.compile(r"^\s*([A-Za-z]{1,8})(?:-[A-Za-z0-9]{1,8})*\s*$")


def lang_from_accept(header: str | None) -> str:
    """The UI language for an ``Accept-Language`` header: Thai when ``th`` is preferred over English, else English."""
    best: list[tuple[float, int, str]] = []
    for i, part in enumerate((header or "").split(",")[:32]):
        tag, _, rest = part.partition(";")
        m = _TAG.match(tag)
        if not m:
            continue
        q = 1.0
        for p in rest.split(";"):
            k, _, v = p.strip().partition("=")
            if k.strip().lower() == "q":
                try:
                    q = float(v)
                except ValueError:
                    q = 0.0
        primary = m.group(1).lower()
        if primary in LANGS and q > 0:
            best.append((-q, i, primary))
    return min(best)[2] if best else DEFAULT_LANG


def request_lang(request) -> str:
    """The signed-in user's language; before sign-in, the browser's ``Accept-Language``."""
    user = getattr(getattr(request, "state", None), "user", None)
    if user is not None:
        lang = getattr(user, "language", None)
        return lang if lang in LANGS else DEFAULT_LANG
    headers = getattr(request, "headers", None) or {}
    return lang_from_accept(headers.get("accept-language", ""))


def current_lang() -> str:
    return _current.get()


def use_lang(lang: str):
    """Set the language for templates rendered from here on (returns the token for ``reset_lang``)."""
    return _current.set(lang if lang in LANGS else DEFAULT_LANG)


def reset_lang(token) -> None:
    _current.reset(token)


def t(text, /, **params) -> str:
    """Jinja global: ``text`` in the language of the page being rendered."""
    return translate(_current.get(), text, **params)


def translate_ctx(lang: str, context: str, text, /, **params) -> str:
    """Like translate(), for an English word that needs different Thai in different places: the catalog key is
    ``"context|text"`` (e.g. ``"issues|Active"``); English shows ``text``."""
    if lang == "th":
        th = _catalog().get(f"{context}|{text}")
        if th:
            try:
                return th.format(**params) if params else th
            except (KeyError, IndexError, ValueError, AttributeError):
                pass
        if RECORD_MISSING:
            MISSING.add(f"{context}|{text}")
    return translate("en", text, **params)


def tp(context: str, text, /, **params) -> str:
    """Jinja global: ``tp("issues", "Active")`` (see translate_ctx)."""
    return translate_ctx(_current.get(), context, text, **params)


def tr(request, text, /, **params) -> str:
    """``text`` in the request's language (flash messages, validation errors, other server-built UI text)."""
    return translate(request_lang(request), text, **params)


def safe_back(path: str) -> str:
    """A same-site relative path to return to (``/`` for anything else), without a stale ?msg= / ?err=."""
    path = (path or "").strip()
    if not path.startswith("/") or path.startswith(("//", "/\\")) or any(ord(c) < 32 or c == "\\" for c in path):
        return "/"
    parts = urlsplit(path)
    if parts.scheme or parts.netloc:
        return "/"
    query = urlencode([(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k not in ("msg", "err")])
    return urlunsplit(("", "", parts.path or "/", query, parts.fragment))


def _gettable(request, path: str) -> bool:
    from starlette.routing import Match
    scope = {"type": "http", "method": "GET", "path": path, "root_path": ""}
    return any(r.matches(scope)[0] == Match.FULL for r in getattr(request.app, "routes", ()) if hasattr(r, "matches"))


def switch_back(request) -> str:
    """Where the language switch returns to: this page for a GET; for a page rendered by a POST (a form error), the
    same-site Referer, else the nearest parent path that answers GET."""
    url = request.url
    if request.method == "GET":
        return safe_back(url.path + ("?" + url.query if url.query else ""))
    ref = urlsplit(request.headers.get("referer", ""))
    if ref.netloc and ref.netloc == url.netloc and ref.scheme in ("http", "https") and ref.path:
        return safe_back(urlunsplit(("", "", ref.path, ref.query, "")))
    path = url.path.rstrip("/")
    while path:
        if _gettable(request, path):
            return safe_back(path)
        path = path.rsplit("/", 1)[0]
    return "/"


# Characters kept literal in ?msg= / ?err= values (as the English URLs always had them).
_FLASH_SAFE = ":;,()'!*/@$"


def flash(request, text, /, **params) -> str:
    """Translated ``text``, URL-encoded (spaces as ``+``) for a ``?msg=`` / ``?err=`` query value."""
    return quote_plus(tr(request, text, **params), safe=_FLASH_SAFE)


# ----------------------------------------------------------------- JavaScript strings
# Every user-visible string in app/static/app.js. base.html embeds their Thai values; app.js falls back to English.
JS_STRINGS: tuple[str, ...] = (
    "Dismiss", "Copied to clipboard", "Copy failed: select the text and copy it manually", "No templates match.",
    "Search failed; try again.", "Job #{id} {status}", "Remove {name}", "1 result", "{n} results", "Add all",
    "nmap {n} target(s) ({ports}) → nuclei ({preset}) on the services found",
    "queued", "running", "done", "failed", "cancelled",
)


def js_catalog(lang: str) -> dict[str, str]:
    if lang != "th":
        return {}
    cat = _catalog()
    return {s: cat[s] for s in JS_STRINGS if cat.get(s)}


# ----------------------------------------------------------------- catalog checks
def dynamic_keys() -> set[str]:
    """English strings that reach ``t()`` / ``tr()`` through a variable (labels kept in Python dicts and tables).
    The catalog checks count these as used."""
    keys: set[str] = set(JS_STRINGS)

    def add(*values):
        for v in values:
            if isinstance(v, str):
                if v:
                    keys.add(v)
            elif isinstance(v, dict):
                add(*v.values())
            elif isinstance(v, (list, tuple, set, frozenset)):
                add(*v)

    from . import navigation
    for g in navigation.NAV:
        add(g.label)
        for i in g.items:
            add(i.label, *(tb.label for tb in i.tabs))
    from .authz import PERMISSIONS, ROLE_DESCRIPTIONS, ROLE_LABELS
    add(ROLE_LABELS, ROLE_DESCRIPTIONS, PERMISSIONS)
    for f in (_dyn_dashboard, _dyn_issues, _dyn_scanning, _dyn_inventory, _dyn_reports, _dyn_system):
        add(f())
    return keys


# Labels each area of the UI shows through t(variable).
def _dyn_dashboard():
    from .onboarding import _STEPS
    from .surface import KIND_LABELS
    from .trends import PERIOD_LABELS
    return [[s[1], s[2], s[4]] for s in _STEPS] + [PERIOD_LABELS, KIND_LABELS] + [
        # app/charts.py: passed to the geometry functions as tr=..., and the bucket words
        "{range}: {values} ({total} total)", "{range}: {values}", "no data", "{lo} to {hi}", "week", "day",
    ]


def _dyn_issues():
    from .ai_features import TRIAGE_LABELS
    from .issues import _NEXT, CONFIDENCE_LABELS, STATUS_LABELS
    from .proof import SKIP_LABELS, VERIFY_LABELS
    return [STATUS_LABELS, CONFIDENCE_LABELS, TRIAGE_LABELS, VERIFY_LABELS, SKIP_LABELS,
            [label for label, _ in _NEXT.values()],
            # app/issues.py next_actions()
            "Verify now", "Assign to me", "False positive…", "Waiting for re-verification",
            # app/proof.py BulkResult.summary()
            "Started {jobs} job(s) for {issues} issue(s)", "; skipped ",
            # app/risk.py risk parts (detail column)
            "CVSS base score × 5", "Issue severity (no CVSS score known)",
            "Listed in CISA Known Exploited Vulnerabilities", "Known use in ransomware campaigns",
            "FIRST EPSS percentile × 20", "Detection confidence", "Scope criticality",
            # issue_detail.html proof parts
            "Request", "Response"]


def _dyn_scanning():
    """Labels shown through t(variable) in the scanning pages."""
    from .discovery import STATES, WEB_FILTERS
    from .nuclei_presets import PRESETS
    from .quick import EMPTY_SUMMARY, LEVELS
    from .scanners.nuclei_runner import PROFILES
    out = [EMPTY_SUMMARY, *WEB_FILTERS.values(), *STATES.values()]
    for lv in LEVELS.values():
        out += [lv["label"], lv["help"], lv["ports_label"]]
    for d in (*PRESETS.values(), *PROFILES.values()):
        out += [d["label"], d["help"]]
    # _readonly.html: the "what" each page passes; job status keywords shown on the job pages
    out += ["start scans", "start discovery jobs", "run updates", "create or change version rules",
            "upload, pull or delete templates", "queued", "running", "done", "failed", "cancelled"]
    return out


def _dyn_inventory():
    from .inventory_groups import GROUP_LABELS, TYPE_ORDER
    from .routers.changes import DAYS_LABELS
    from .scanners.nuclei_runner import PROFILES
    from .surface import KIND_LABELS
    return [GROUP_LABELS, list(TYPE_ORDER), "Unscoped", "Unknown product", DAYS_LABELS, KIND_LABELS,
            [p["label"] for p in PROFILES.values()], ["active", "draft", "closed", "dismissed"]]


def _dyn_reports():
    from .nuclei_presets import PRESETS
    from .scanners.nuclei_runner import PROFILES
    from .scheduler import FREQUENCIES, KINDS, WEEKDAYS
    return [KINDS, FREQUENCIES, list(WEEKDAYS),
            ["started", "skipped", "error"],                        # Schedule.last_status
            "No scope",                                              # app/reports.py executive(): issues without a scope
            [p["label"] for p in PROFILES.values()],
            [v for p in PRESETS.values() for v in (p.get("label", ""), p.get("help", ""))],
            # app/risk.py risk parts (detail column of the issue report)
            "CVSS base score × 5", "Issue severity (no CVSS score known)",
            "Listed in CISA Known Exploited Vulnerabilities", "Known use in ransomware campaigns",
            "FIRST EPSS percentile × 20", "Detection confidence", "Scope criticality",
            # _readonly.html "what" from rules.html / templates.html
            "create or change version rules", "upload, pull or delete templates"]


def _dyn_system():
    from .updates import UPDATE_ACTIONS
    out = [v for a in UPDATE_ACTIONS.values() for v in (a["label"], a["help"])]
    out += ["create or change version rules", "run updates", "start discovery jobs", "start scans",
            "upload, pull or delete templates"]   # _readonly.html "what" (passed from page templates)
    out += ["Deactivated {name}", "Activated {name}"]   # routers/users.py toggle flash
    from .apikeys import EXPIRY_CHOICES
    from .audit import ACTION_GROUPS
    from .channels import FIELDS, KINDS
    from .llm import PROVIDER_KINDS
    from .notifications import EVENTS
    out += [*EXPIRY_CHOICES.values(), *ACTION_GROUPS.values(), *KINDS.values(), *PROVIDER_KINDS.values(),
            *EVENTS.values(), *(label for f in FIELDS.values() for _n, label, _s in f)]
    out += ["sent", "pending", "failed"]   # delivery status shown through t()
    from .discovery import PROVIDERS
    out += [label for label, _fmt, _pair in PROVIDERS.values()]   # settings.html discovery source names
    out += ["Custom (0-day) templates"]   # templates_index group label (nuclei.html)
    return out
