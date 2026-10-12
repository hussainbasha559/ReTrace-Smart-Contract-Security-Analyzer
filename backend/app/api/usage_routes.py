from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.adapters import heimdall_adapter, mythril_adapter
from app.config import get_settings
from app.db import get_db, utcnow
from app.deps import err, request_id, require_admin, require_user
from app.models import AIAnalysis, Scan, UploadedFile, User, Vulnerability
from app.services.audit_service import audit

router = APIRouter(prefix="/api")


def _trend(rows, days: int = 30) -> list[dict]:
    since = utcnow() - timedelta(days=days - 1)
    per: dict[str, int] = defaultdict(int)
    for created in rows:
        if created >= since:
            per[created.date().isoformat()] += 1
    return [{"date": (since + timedelta(days=i)).date().isoformat(),
             "count": per.get((since + timedelta(days=i)).date().isoformat(), 0)} for i in range(days)]


@router.get("/usage/me")
def my_usage(user: User = Depends(require_user), db: Session = Depends(get_db)):
    scans = list(db.scalars(select(Scan).where(Scan.owner_user_id == user.id)))
    ai = list(db.scalars(select(AIAnalysis).where(AIAnalysis.owner_user_id == user.id)))
    files = db.execute(select(func.count(), func.coalesce(func.sum(UploadedFile.file_size), 0))
                       .where(UploadedFile.owner_user_id == user.id)).one()
    done = [s for s in scans if s.scan_status == "COMPLETED"]
    dur = [s.duration_ms for s in done if s.duration_ms is not None]
    return {
        "scans_total": len(scans), "scans_successful": len(done),
        "scans_failed": sum(1 for s in scans if s.scan_status == "FAILED"),
        "files_uploaded": files[0], "bytecode_bytes_stored": int(files[1]),
        "bytecode_bytes_scanned": sum(s.input_bytes for s in scans if s.scan_status == "COMPLETED"),
        "avg_duration_ms": int(sum(dur) / len(dur)) if dur else None,
        "ai_analyses": sum(1 for a in ai if a.status == "completed"),
        "ai_tokens": sum(a.token_usage or 0 for a in ai),
        "ai_tokens_note": "Counts only calls to an external LLM provider that reported usage; rule-based answers use none.",
        "scan_trend": _trend([s.created_at for s in scans]),
        "ai_trend": _trend([a.created_at for a in ai]),
    }


@router.get("/admin/overview")
def admin_overview(user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Aggregates only. Administrators see counts and categories, never anyone's files or scan contents."""
    s = get_settings()
    users = db.execute(select(func.count(), func.coalesce(func.sum(case((User.is_active.is_(True), 1), else_=0)), 0))).one()
    scans = list(db.execute(select(Scan.scan_status, Scan.duration_ms, Scan.created_at)).all())
    done = [x for x in scans if x[0] == "COMPLETED"]
    failed = [x for x in scans if x[0] == "FAILED"]
    finished = len(done) + len(failed)
    durs = sorted(x[1] for x in done if x[1] is not None)
    cats = db.execute(select(Vulnerability.category, func.count()).group_by(Vulnerability.category)
                      .order_by(func.count().desc()).limit(10)).all()
    ai_rows = db.execute(select(AIAnalysis.provider, AIAnalysis.status, func.count(), func.coalesce(func.sum(AIAnalysis.prompt_tokens), 0),
                                func.coalesce(func.sum(AIAnalysis.completion_tokens), 0)).group_by(AIAnalysis.provider, AIAnalysis.status)).all()
    p_in, p_out = int(sum(r[3] for r in ai_rows)), int(sum(r[4] for r in ai_rows))
    cost = None
    if s.ai_price_input_per_1m is not None and s.ai_price_output_per_1m is not None:
        cost = round(p_in / 1e6 * s.ai_price_input_per_1m + p_out / 1e6 * s.ai_price_output_per_1m, 4)
    failed_recent = db.execute(select(Scan.id, Scan.owner_user_id, Scan.completed_at, Scan.error_summary)
                               .where(Scan.scan_status == "FAILED").order_by(Scan.id.desc()).limit(10)).all()
    try:
        db.execute(select(1)); db_ok = True
    except Exception:
        db_ok = False
    return {
        "users": {"total": users[0], "active": int(users[1])},
        "scans": {"total": len(scans), "completed": len(done), "failed": len(failed),
                  "success_rate": round(len(done) / finished, 3) if finished else None,
                  "avg_duration_ms": int(sum(durs) / len(durs)) if durs else None,
                  "p95_duration_ms": durs[min(len(durs) - 1, int(len(durs) * 0.95))] if durs else None,
                  "trend": _trend([x[2] for x in scans])},
        "top_categories": [{"category": c, "count": n} for c, n in cats],
        "ai": {"calls": sum(r[2] for r in ai_rows), "failed": sum(r[2] for r in ai_rows if r[1] == "failed"),
               "by_provider": [{"provider": r[0], "status": r[1], "count": r[2]} for r in ai_rows],
               "prompt_tokens": p_in, "completion_tokens": p_out, "estimated_cost_usd": cost,
               "cost_note": "Estimated from RETRACE_AI_PRICE_* settings; null when pricing is not configured."},
        "failed_jobs": [{"scan_id": r[0], "owner_user_id": r[1], "at": r[2].isoformat() + "Z" if r[2] else None,
                         "error": r[3]} for r in failed_recent],
        "health": {"database": db_ok, "heimdall": heimdall_adapter.is_available(s), "mythril": mythril_adapter.is_available(s),
                   "ai_provider": s.ai_provider if s.ai_provider != "none" and s.ai_api_key else "not configured"},
    }


class UserPatch(BaseModel):
    is_active: bool


@router.get("/admin/users")
def admin_users(user: User = Depends(require_admin), db: Session = Depends(get_db)):
    scan_counts = dict(db.execute(select(Scan.owner_user_id, func.count()).group_by(Scan.owner_user_id)).all())
    rows = db.scalars(select(User).order_by(User.id)).all()
    return {"items": [{"id": u.id, "name": u.name, "email": u.email, "role": u.role, "is_active": u.is_active,
                       "created_at": u.created_at.isoformat() + "Z",
                       "last_login_at": u.last_login_at.isoformat() + "Z" if u.last_login_at else None,
                       "scan_count": scan_counts.get(u.id, 0)} for u in rows]}


@router.patch("/admin/users/{user_id}")
def admin_set_active(user_id: int, body: UserPatch, request: Request, admin: User = Depends(require_admin),
                     db: Session = Depends(get_db)):
    target = db.get(User, user_id)
    if target is None:
        raise err(404, "not_found", "Not found.")
    if target.id == admin.id:
        raise err(409, "self_change", "You cannot change your own active status.")
    target.is_active = body.is_active
    audit(db, "admin.set_active" if body.is_active else "admin.deactivate", "user", target.id,
          actor_user_id=admin.id, request_id=request_id(request))
    return {"id": target.id, "is_active": target.is_active}
