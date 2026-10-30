"""Encrypt integration secrets at rest (Fernet, key derived from the instance secret key)."""
from __future__ import annotations

import base64
import hashlib
import json

from cryptography.fernet import Fernet, InvalidToken


class SecretBox:
    def __init__(self, secret_key: str):
        key = hashlib.sha256(f"zdrs-integrations:{secret_key}".encode()).digest()
        self._f = Fernet(base64.urlsafe_b64encode(key))

    def encrypt(self, values: dict) -> str:
        values = {k: v for k, v in values.items() if v}
        return self._f.encrypt(json.dumps(values).encode()).decode() if values else ""

    def decrypt(self, token: str) -> dict:
        if not token:
            return {}
        try:
            data = json.loads(self._f.decrypt(token.encode()))
        except (InvalidToken, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def merge(self, token: str, updates: dict) -> str:
        """Apply non-empty updates on top of the stored values (blank form fields keep the secret)."""
        values = self.decrypt(token)
        values.update({k: v for k, v in updates.items() if v})
        return self.encrypt(values)
