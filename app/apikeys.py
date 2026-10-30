"""API keys: generation, hashing, authentication and the principal that represents a key holder."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .authz import ROLES
from .db import ApiKey, User, utcnow

KEY_PREFIX = "zdrs_"
PREFIX_LEN = 12
EXPIRY_CHOICES = {"30": "30 days", "90": "90 days", "365": "1 year", "never": "Never"}


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def generate() -> tuple[str, str, str]:
    raw = KEY_PREFIX + secrets.token_urlsafe(32)
    return raw, raw[:PREFIX_LEN], hash_key(raw)


def allowed_roles(owner_role: str) -> list[str]:
    """A key may carry the owner's role or a lower one (ROLES is ordered most → least privileged)."""
    if owner_role not in ROLES:
        return []
    return list(ROLES[ROLES.index(owner_role):])


def create_key(db: Session, owner: User, name: str, role: str, expires: str) -> tuple[ApiKey, str]:
    name = name.strip()
    if not name or len(name) > 64:
        raise ValueError("Give the key a name (max 64 characters).")
    if role not in allowed_roles(owner.role):
        raise ValueError(f"A key's role cannot exceed yours ({owner.role}).")
    if expires not in EXPIRY_CHOICES:
        raise ValueError("Unknown expiry.")
    raw, prefix, digest = generate()
    key = ApiKey(name=name, prefix=prefix, key_hash=digest, user_id=owner.id, role=role,
                 expires_at=None if expires == "never" else utcnow() + timedelta(days=int(expires)))
    db.add(key)
    db.flush()
    return key, raw


@dataclass
class ApiPrincipal:
    """Stands in for request.state.user on /api: same attributes the permission and audit code use."""
    id: int
    username: str
    role: str
    is_active: bool
    display_name: str
    email: str
    key_id: int
    key_name: str
    owner_username: str
    must_change_password: bool = False


def authenticate(db: Session, raw: str, ip: str = "") -> ApiPrincipal | None:
    raw = (raw or "").strip()
    if not raw.startswith(KEY_PREFIX) or len(raw) < PREFIX_LEN + 8:
        return None
    now = utcnow()
    for key in db.scalars(select(ApiKey).where(ApiKey.prefix == raw[:PREFIX_LEN])):
        if not hmac.compare_digest(key.key_hash, hash_key(raw)):
            continue
        owner = db.get(User, key.user_id)
        if key.revoked_at or (key.expires_at and key.expires_at <= now) or owner is None or not owner.is_active:
            return None
        # a key never outranks its owner, even if the owner was demoted after creating it
        role = key.role if key.role in allowed_roles(owner.role) else owner.role
        key.last_used_at, key.last_used_ip = now, ip[:64]
        db.commit()
        return ApiPrincipal(id=owner.id, username=f"{owner.username} (api:{key.name})", role=role, is_active=True,
                            display_name=owner.display_name, email=owner.email, key_id=key.id, key_name=key.name,
                            owner_username=owner.username)
    return None
