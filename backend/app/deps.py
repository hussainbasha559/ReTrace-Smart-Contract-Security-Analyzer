"""Request dependencies: current user, CSRF check, admin check, ownership helper."""
from __future__ import annotations

from datetime import timedelta
from typing import Type, TypeVar

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import Base, get_db, utcnow
from app.models import User, UserSession
from app.security import safe_equal, token_hash

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def err(status: int, code: str, message: str, **extra) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message, **extra})


def request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def current_session(request: Request, db: Session = Depends(get_db)) -> UserSession:
    s = get_settings()
    token = request.cookies.get(s.session_cookie_name)
    if not token:
        raise err(401, "not_authenticated", "Please sign in.")
    sess = db.scalar(select(UserSession).where(UserSession.token_hash == token_hash(token)))
    now = utcnow()
    if sess is None:
        raise err(401, "not_authenticated", "Please sign in.")
    idle_limit = sess.last_seen_at + timedelta(minutes=s.session_idle_minutes)
    if sess.expires_at <= now or idle_limit <= now or not sess.user.is_active:
        db.delete(sess)
        db.commit()
        raise err(401, "session_expired", "Your session has expired. Please sign in again.")
    if now - sess.last_seen_at > timedelta(minutes=1):  # avoid a write on every request
        sess.last_seen_at = now
        db.commit()
    # CSRF: unsafe methods must echo the per-session token (synchronizer-token pattern).
    if request.method not in SAFE_METHODS:
        sent = request.headers.get("x-csrf-token", "")
        if not sent or not safe_equal(sent, sess.csrf_token):
            raise err(403, "csrf_failed", "Security check failed. Refresh the page and try again.")
    return sess


def require_user(sess: UserSession = Depends(current_session)) -> User:
    return sess.user


def require_admin(user: User = Depends(require_user)) -> User:
    if user.role != "admin":
        raise err(403, "forbidden", "Administrator access is required.")
    return user


T = TypeVar("T", bound=Base)


def get_owned(db: Session, model: Type[T], obj_id: int, user: User) -> T:
    """Fetch a row only if it belongs to `user`. Other users' rows look like they do not exist,
    so knowing an ID never grants (or confirms) access."""
    obj = db.get(model, obj_id)
    if obj is None or getattr(obj, "owner_user_id") != user.id:
        raise err(404, "not_found", "Not found.")
    return obj
