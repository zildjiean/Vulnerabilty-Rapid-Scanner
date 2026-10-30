"""Replace IP addresses and known host names with stable HOST-n tokens before text leaves the scanner."""
from __future__ import annotations

import ipaddress
import re

_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f:]{0,4}(?![0-9A-Fa-f:])")


class Redactor:
    def __init__(self, known: list[str] | None = None, enabled: bool = True):
        self.enabled = enabled
        self.mapping: dict[str, str] = {}
        self.reverse: dict[str, str] = {}
        names = sorted({k.strip() for k in (known or []) if k and k.strip()}, key=len, reverse=True)
        self._known = re.compile("|".join(re.escape(n) for n in names), re.I) if names else None

    def _token(self, value: str) -> str:
        key = value.lower()
        if key not in self.mapping:
            token = f"HOST-{len(self.mapping) + 1}"
            self.mapping[key] = token
            self.reverse[token] = value
        return self.mapping[key]

    def redact(self, text: str) -> str:
        if not self.enabled or not text:
            return text
        if self._known is not None:
            text = self._known.sub(lambda m: self._token(m.group(0)), text)
        text = _IPV4.sub(lambda m: self._token(m.group(0)), text)

        def v6(m):
            try:
                ipaddress.IPv6Address(m.group(0))
            except ValueError:
                return m.group(0)
            return self._token(m.group(0))
        return _IPV6.sub(v6, text)

    def restore(self, text: str) -> str:
        if not self.enabled or not text or not self.reverse:
            return text
        for token in sorted(self.reverse, key=len, reverse=True):   # HOST-11 before HOST-1
            text = re.sub(rf"\b{re.escape(token)}\b", lambda _m, t=token: self.reverse[t], text)
        return text

    def restore_data(self, obj):
        if isinstance(obj, str):
            return self.restore(obj)
        if isinstance(obj, list):
            return [self.restore_data(x) for x in obj]
        if isinstance(obj, dict):
            return {k: self.restore_data(v) for k, v in obj.items()}
        return obj
