"""Admin command line.   python -m app.cli --help

  create-admin   create (or promote) an administrator; the password is read from a hidden prompt
  purge          delete expired sessions and audit-log rows older than the retention period
"""
from __future__ import annotations

import argparse
import getpass
import sys
from datetime import timedelta

from sqlalchemy import delete, select

from app.config import get_settings
from app.db import session_factory, utcnow
from app.models import AuditLog, User, UserSession
from app.security import clean_name, hash_password, normalize_email, password_problems


def create_admin(email: str, name: str) -> int:
    email = normalize_email(email)
    name = clean_name(name)
    with session_factory()() as db:
        user = db.scalar(select(User).where(User.email == email))
        if user:
            user.role = "admin"
            db.commit()
            print(f"Existing user {email} promoted to admin.")
            return 0
        pw = getpass.getpass("Password: ")
        if pw != getpass.getpass("Repeat password: "):
            print("Passwords do not match.", file=sys.stderr)
            return 1
        problems = password_problems(pw, email, name)
        if problems:
            print("Weak password: " + " ".join(problems), file=sys.stderr)
            return 1
        db.add(User(name=name, email=email, password_hash=hash_password(pw), role="admin"))
        db.commit()
        print(f"Admin {email} created.")
        return 0


def purge() -> int:
    s = get_settings()
    with session_factory()() as db:
        a = db.execute(delete(UserSession).where(UserSession.expires_at < utcnow())).rowcount
        b = db.execute(delete(AuditLog).where(AuditLog.timestamp < utcnow() - timedelta(days=s.audit_retention_days))).rowcount
        db.commit()
    print(f"Deleted {a} expired session(s) and {b} audit row(s) older than {s.audit_retention_days} days.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="python -m app.cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create-admin")
    c.add_argument("--email", required=True)
    c.add_argument("--name", required=True)
    sub.add_parser("purge")
    a = ap.parse_args()
    return create_admin(a.email, a.name) if a.cmd == "create-admin" else purge()


if __name__ == "__main__":
    raise SystemExit(main())
