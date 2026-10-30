from __future__ import annotations

import secrets
import time
from collections import defaultdict, deque

import bcrypt
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse

from .db import User

DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "changeme"
MIN_PASSWORD_LEN = 12
SESSION_COOKIE = "zdrs_session"
SESSION_MAX_AGE = 12 * 3600
PUBLIC_PATHS = {"/login", "/healthz"}
PUBLIC_PREFIXES = ("/static/",)
CHANGE_PASSWORD_ALLOWED = {"/change-password", "/logout"}


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        return False


def validate_new_password(new: str, confirm: str, current: str) -> str | None:
    if len(new) < MIN_PASSWORD_LEN:
        return f"New password must be at least {MIN_PASSWORD_LEN} characters."
    if new != confirm:
        return "Passwords do not match."
    if new == current:
        return "New password must differ from the current one."
    return None


def seed_admin(db: Session) -> None:
    if db.scalar(select(User).limit(1)) is None:
        db.add(User(username=DEFAULT_USERNAME, password_hash=hash_password(DEFAULT_PASSWORD), must_change_password=True,
                    role="admin"))
        db.commit()


class SessionStore:
    def __init__(self, secret_key: str):
        self._s = URLSafeTimedSerializer(secret_key, salt="zdrs-session")

    def encode(self, user_id: int, session_version: int = 0) -> str:
        return self._s.dumps({"uid": user_id, "sv": session_version, "csrf": secrets.token_urlsafe(24)})

    def decode(self, token: str) -> dict | None:
        try:
            data = self._s.loads(token, max_age=SESSION_MAX_AGE)
        except BadSignature:
            return None
        if not isinstance(data, dict) or "uid" not in data or "csrf" not in data:
            return None
        return data


class LoginRateLimiter:
    def __init__(self, max_attempts: int = 5, window_seconds: int = 60):
        self.max_attempts = max_attempts
        self.window = window_seconds
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, ip: str) -> deque[float]:
        q = self._failures[ip]
        cutoff = time.monotonic() - self.window
        while q and q[0] < cutoff:
            q.popleft()
        return q

    def allowed(self, ip: str) -> bool:
        return len(self._prune(ip)) < self.max_attempts

    def record_failure(self, ip: str) -> None:
        self._prune(ip).append(time.monotonic())

    def reset(self, ip: str) -> None:
        self._failures.pop(ip, None)


class AuthMiddleware(BaseHTTPMiddleware):
    """Loads the user from the session cookie, enforces login and the forced password change."""

    async def dispatch(self, request: Request, call_next):
        app = request.app
        request.state.user = None
        request.state.csrf = None
        if request.url.path.startswith("/api/"):
            return await self._api(request, call_next)
        token = request.cookies.get(SESSION_COOKIE)
        data = app.state.sessions.decode(token) if token else None
        if data:
            with app.state.SessionLocal() as db:
                user = db.get(User, data["uid"])
            # a deactivated user, or one whose sessions were revoked (password reset, deactivation), is signed out
            if user is not None and user.is_active and data.get("sv", 0) == user.session_version:
                request.state.user = user
                request.state.csrf = data["csrf"]

        path = request.url.path
        public = path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES)
        if request.state.user is None:
            if not public:
                return RedirectResponse("/login", status_code=303)
        elif request.state.user.must_change_password and not public and path not in CHANGE_PASSWORD_ALLOWED:
            return RedirectResponse("/change-password", status_code=303)
        return await call_next(request)


    @staticmethod
    async def _api(request: Request, call_next):
        """/api/* accepts only API keys (never the session cookie), so it needs no CSRF protection."""
        from starlette.responses import JSONResponse
        from .apikeys import authenticate
        header = request.headers.get("authorization", "")
        raw = header[7:] if header.lower().startswith("bearer ") else request.headers.get("x-api-key", "")
        ip = request.client.host if request.client else ""
        with request.app.state.SessionLocal() as db:
            principal = authenticate(db, raw, ip) if raw else None
        if principal is None:
            return JSONResponse({"detail": "Missing, invalid, expired or revoked API key."}, status_code=401,
                                headers={"WWW-Authenticate": "Bearer"})
        request.state.user = principal
        return await call_next(request)


def set_session_cookie(response, token: str, secure: bool) -> None:
    response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_MAX_AGE, httponly=True, samesite="lax", secure=secure, path="/")


def clear_session_cookie(response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")
