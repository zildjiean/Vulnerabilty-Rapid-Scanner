"""Render model output as a tiny, safe markdown subset: everything is HTML-escaped first; links are not rendered."""
from __future__ import annotations

import re

from markupsafe import Markup, escape

_INLINE = [(re.compile(r"`([^`]+)`"), r"<code>\1</code>"),
           (re.compile(r"\*\*([^*]+)\*\*"), r"<strong>\1</strong>")]


def _inline(text: str) -> str:
    out = str(escape(text))
    for pattern, repl in _INLINE:
        out = pattern.sub(repl, out)
    return out


def render_markdown(text: str) -> Markup:
    html: list[str] = []
    para: list[str] = []
    list_tag: str | None = None
    in_code, code = False, []

    def flush_para():
        if para:
            html.append("<p>" + "<br>".join(_inline(p) for p in para) + "</p>")
            para.clear()

    def close_list():
        nonlocal list_tag
        if list_tag:
            html.append(f"</{list_tag}>")
            list_tag = None

    for line in (text or "").splitlines():
        if line.strip().startswith("```"):
            if in_code:
                html.append("<pre><code>" + str(escape("\n".join(code))) + "</code></pre>")
                code, in_code = [], False
            else:
                flush_para(); close_list()
                in_code = True
            continue
        if in_code:
            code.append(line)
            continue
        s = line.strip()
        heading = re.match(r"^(#{1,6})\s+(.*)", s)
        bullet = re.match(r"^[-*]\s+(.*)", s)
        number = re.match(r"^\d+[.)]\s+(.*)", s)
        if not s:
            flush_para(); close_list()
        elif heading:
            flush_para(); close_list()
            level = 3 if len(heading.group(1)) == 1 else 4
            html.append(f"<h{level}>{_inline(heading.group(2))}</h{level}>")
        elif bullet or number:
            flush_para()
            tag = "ul" if bullet else "ol"
            if list_tag != tag:
                close_list()
                html.append(f"<{tag}>")
                list_tag = tag
            html.append(f"<li>{_inline((bullet or number).group(1))}</li>")
        else:
            close_list()
            para.append(s)
    if in_code:
        html.append("<pre><code>" + str(escape("\n".join(code))) + "</code></pre>")
    flush_para(); close_list()
    return Markup("\n".join(html))
