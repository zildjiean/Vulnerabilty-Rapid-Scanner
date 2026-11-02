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
from urllib.parse import quote_plus

LANGS = ("en", "th")
LANG_NAMES = {"en": "English", "th": "ไทย"}
DEFAULT_LANG = "en"

# Thai lookups that found no catalog entry (the completeness tests clear and read it).
MISSING: set[str] = set()

_current = contextvars.ContextVar("ui_lang", default=DEFAULT_LANG)


def _catalog() -> dict[str, str]:
    from .i18n_th import CATALOG_TH
    return CATALOG_TH


class Msg(str):
    """An English message plus its placeholders. ``str(m)`` is the English text, ``tr(request, m)`` translates the
    template and then fills the placeholders."""

    def __new__(cls, template: str, **params):
        try:
            text = template.format(**params) if params else template
        except (KeyError, IndexError, ValueError, AttributeError):
            text = template
        obj = super().__new__(cls, text)
        obj.template, obj.params = template, params
        return obj


def _format(text: str, params: dict) -> str:
    return text.format(**params)


def translate(lang: str, text, **params) -> str:
    """``text`` in ``lang`` (Thai catalog lookup, English fallback), then ``str.format(**params)``. Never raises."""
    if isinstance(text, BaseException):
        text = text.args[0] if text.args else str(text)
    if isinstance(text, Msg):
        params = {**text.params, **params}
        text = text.template
    src = "" if text is None else str(text)
    out = src
    if lang == "th" and src:
        th = _catalog().get(src)
        if th:
            out = th
        else:
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


def t(text, **params) -> str:
    """Jinja global: ``text`` in the language of the page being rendered."""
    return translate(_current.get(), text, **params)


def tr(request, text, **params) -> str:
    """``text`` in the request's language (flash messages, validation errors, other server-built UI text)."""
    return translate(request_lang(request), text, **params)


# Characters kept literal in ?msg= / ?err= values (as the English URLs always had them).
_FLASH_SAFE = ":;,()'!*/@$"


def flash(request, text, **params) -> str:
    """Translated ``text``, URL-encoded (spaces as ``+``) for a ``?msg=`` / ``?err=`` query value."""
    return quote_plus(tr(request, text, **params), safe=_FLASH_SAFE)


# ----------------------------------------------------------------- JavaScript strings
# Every user-visible string in app/static/app.js. base.html embeds their Thai values; app.js falls back to English.
JS_STRINGS: tuple[str, ...] = (
    "Dismiss", "Copied to clipboard", "Copy failed: select the text and copy it manually", "No templates match.",
    "Search failed; try again.", "Job #{id} {status}", "Remove {name}", "1 result", "{n} results", "Add all",
    "nmap {n} target(s) ({ports}) → nuclei ({preset}) on the services found",
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
    # (while areas are being translated) app/i18n_th_*.py may list their own dynamic labels in dynamic()
    import importlib
    import pkgutil
    from pathlib import Path
    for m in pkgutil.iter_modules([str(Path(__file__).parent)]):
        if m.name.startswith("i18n_th_"):
            mod = importlib.import_module(f"app.{m.name}")
            if hasattr(mod, "dynamic"):
                add(mod.dynamic())
    return keys
