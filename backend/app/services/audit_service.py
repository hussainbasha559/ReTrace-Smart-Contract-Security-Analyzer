"""Audit log and usage events. Neither ever receives passwords, tokens or bytecode."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import AuditLog, UsageEvent


def audit(
    db: Session,
    action: str,
    resource_type: str,
    resource_id: object = None,
    outcome: str = "success",
    actor_user_id: int | None = None,
    request_id: str | None = None,
    commit: bool = True,
) -> None:
    db.add(
        AuditLog(
            actor_user_id=actor_user_id,
            action=action,
            resource_type=resource_type,
            resource_id=None if resource_id is None else str(resource_id),
            outcome=outcome,
            request_id=request_id,
        )
    )
    if commit:
        db.commit()


def usage(
    db: Session,
    user_id: int,
    event_type: str,
    resource_type: str,
    resource_id: int | None = None,
    quantity: int = 1,
    duration_ms: int | None = None,
    commit: bool = False,
) -> None:
    db.add(
        UsageEvent(
            owner_user_id=user_id,
            event_type=event_type,
            resource_type=resource_type,
            resource_id=resource_id,
            quantity=quantity,
            duration_ms=duration_ms,
        )
    )
    if commit:
        db.commit()
