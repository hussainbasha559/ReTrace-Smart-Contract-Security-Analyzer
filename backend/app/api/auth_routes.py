"""Registration, login, logout, profile and password change."""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db, utcnow
from app.deps import client_ip, current_session, err, request_id, require_user
from app.models import AIAnalysis, Scan, UploadedFile, User, UserSession
from app.security import (
    clean_name, hash_password, limiter, needs_rehash, new_csrf_token, new_session_token,
    normalize_email, password_problems, token_hash, verify_password,
)
from app.services import account_service
from app.services.audit_service import audit

router = APIRouter(prefix="/api")


class RegisterIn(BaseModel):
    name: str = Field(max_length=200)
    email: str = Field(max_length=320)
    password: str = Field(max_length=1024)


class LoginIn(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=1024)


class ChangePasswordIn(BaseModel):
    current_password: str = Field(max_length=1024)
    new_password: str = Field(max_length=1024)


class ProfileIn(BaseModel):
    name: str = Field(max_length=200)


class DeleteAccountIn(BaseModel):
    password: str = Field(max_length=1024)


def user_out(u: User) -> dict:
    return {"id": u.id, "name": u.name, "email": u.email, "role": u.role}


def _start_session(db: Session, response: Response, user: User) -> str:
    s = get_settings()
    token = new_session_token()
    csrf = new_csrf_token()
    db.add(UserSession(
        user_id=user.id, token_hash=token_hash(token), csrf_token=csrf,
        expires_at=utcnow() + timedelta(hours=s.session_ttl_hours),
    ))
    response.set_cookie(
        s.session_cookie_name, token, max_age=s.session_ttl_hours * 3600, httponly=True,
        secure=s.cookie_secure, samesite=s.cookie_samesite, path="/",
    )
    return csrf


def _too_many() -> Exception:
    return err(429, "rate_limited", "Too many attempts. Please wait a few minutes and try again.")


@router.post("/auth/register", status_code=201)
def register(body: RegisterIn, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = client_ip(request)
    if not limiter.check(f"register:{ip}", 5, 3600):
        raise _too_many()
    fields: dict[str, list[str]] = {}
    name = email = ""
    try:
        name = clean_name(body.name)
    except ValueError as e:
        fields["name"] = [str(e)]
    try:
        email = normalize_email(body.email)
    except ValueError:
        fields["email"] = ["Enter a valid email address."]
    problems = password_problems(body.password, email, name)
    if problems:
        fields["password"] = problems
    if fields:
        raise err(422, "validation_error", "Please fix the highlighted fields.", fields=fields)

    user = User(name=name, email=email, password_hash=hash_password(body.password))
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise err(409, "email_taken", "An account with this email already exists.",
                  fields={"email": ["An account with this email already exists."]})
    csrf = _start_session(db, response, user)
    audit(db, "auth.register", "user", user.id, actor_user_id=user.id, request_id=request_id(request), commit=False)
    db.commit()
    return {"user": user_out(user), "csrf_token": csrf}


@router.post("/auth/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = client_ip(request)
    email_key = body.email.strip().lower()[:254]
    if not limiter.check(f"login-ip:{ip}", 20, 900) or not limiter.check(f"login-email:{email_key}", 8, 900):
        raise _too_many()
    user = db.scalar(select(User).where(User.email == email_key))
    ok = verify_password(body.password, user.password_hash if user else None)
    if not (ok and user and user.is_active):
        audit(db, "auth.login", "user", user.id if user else None, outcome="failure",
              actor_user_id=user.id if user else None, request_id=request_id(request))
        # One message for unknown email, wrong password and disabled account.
        raise err(401, "invalid_credentials", "Invalid email or password.")
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    user.last_login_at = utcnow()
    csrf = _start_session(db, response, user)
    audit(db, "auth.login", "user", user.id, actor_user_id=user.id, request_id=request_id(request), commit=False)
    db.commit()
    return {"user": user_out(user), "csrf_token": csrf}


@router.post("/auth/logout")
def logout(request: Request, response: Response, sess: UserSession = Depends(current_session), db: Session = Depends(get_db)):
    uid = sess.user_id
    db.delete(sess)
    audit(db, "auth.logout", "user", uid, actor_user_id=uid, request_id=request_id(request), commit=False)
    db.commit()
    response.delete_cookie(get_settings().session_cookie_name, path="/")
    return {"ok": True}


@router.get("/auth/me")
def me(sess: UserSession = Depends(current_session)):
    """Used on every page load to restore the login state; returns the CSRF token for this session."""
    return {"user": user_out(sess.user), "csrf_token": sess.csrf_token}


@router.get("/profile")
def profile(user: User = Depends(require_user), db: Session = Depends(get_db)):
    scans = db.scalar(select(func.count()).select_from(Scan).where(Scan.owner_user_id == user.id)) or 0
    files = db.scalar(select(func.count()).select_from(UploadedFile).where(UploadedFile.owner_user_id == user.id)) or 0
    ai = db.scalar(select(func.count()).select_from(AIAnalysis).where(AIAnalysis.owner_user_id == user.id)) or 0
    sessions = db.scalar(select(func.count()).select_from(UserSession).where(UserSession.user_id == user.id)) or 0
    return {
        **user_out(user),
        "created_at": user.created_at.isoformat() + "Z",
        "last_login_at": user.last_login_at.isoformat() + "Z" if user.last_login_at else None,
        "activity": {"scans": scans, "files": files, "ai_analyses": ai, "active_sessions": sessions},
        "email_verified": False,   # email verification is not implemented (needs an SMTP service)
    }


@router.patch("/profile")
def update_profile(body: ProfileIn, request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    try:
        user.name = clean_name(body.name)
    except ValueError as e:
        raise err(422, "validation_error", str(e), fields={"name": [str(e)]})
    audit(db, "profile.update", "user", user.id, actor_user_id=user.id, request_id=request_id(request), commit=False)
    db.commit()
    return user_out(user)


@router.post("/auth/change-password")
def change_password(body: ChangePasswordIn, request: Request, sess: UserSession = Depends(current_session),
                    db: Session = Depends(get_db)):
    user = sess.user
    if not limiter.check(f"pwchange:{user.id}", 5, 900):
        raise _too_many()
    if not verify_password(body.current_password, user.password_hash):
        audit(db, "auth.change_password", "user", user.id, outcome="failure", actor_user_id=user.id,
              request_id=request_id(request))
        raise err(403, "wrong_password", "Current password is incorrect.", fields={"current_password": ["Incorrect password."]})
    problems = password_problems(body.new_password, user.email, user.name)
    if body.new_password == body.current_password:
        problems.append("Choose a password different from the current one.")
    if problems:
        raise err(422, "validation_error", "The new password is not acceptable.", fields={"new_password": problems})
    user.password_hash = hash_password(body.new_password)
    # Sign out every other device.
    for other in db.scalars(select(UserSession).where(UserSession.user_id == user.id, UserSession.id != sess.id)):
        db.delete(other)
    audit(db, "auth.change_password", "user", user.id, actor_user_id=user.id, request_id=request_id(request), commit=False)
    db.commit()
    return {"ok": True}


@router.delete("/profile/data")
def delete_my_data(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    """Delete the user's files, scans, reports, projects, AI results and usage records.
    The account and audit log are kept."""
    counts = account_service.delete_user_data(db, user, get_settings())
    audit(db, "profile.delete_data", "user", user.id, actor_user_id=user.id, request_id=request_id(request))
    return {"deleted": counts}


@router.delete("/profile")
def delete_account(body: DeleteAccountIn, request: Request, response: Response,
                   user: User = Depends(require_user), db: Session = Depends(get_db)):
    if not verify_password(body.password, user.password_hash):
        raise err(403, "wrong_password", "Password is incorrect.")
    if user.role == "admin" and (db.scalar(select(func.count()).select_from(User).where(User.role == "admin", User.is_active)) or 0) <= 1:
        raise err(409, "last_admin", "You are the only administrator; promote someone else first.")
    uid = user.id
    account_service.delete_user_data(db, user, get_settings())
    db.delete(user)
    audit(db, "account.delete", "user", uid, request_id=request_id(request), commit=False)
    db.commit()
    response.delete_cookie(get_settings().session_cookie_name, path="/")
    return {"ok": True}
