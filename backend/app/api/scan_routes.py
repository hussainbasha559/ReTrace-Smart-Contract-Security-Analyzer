from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.file_routes import _check_project, store_file
from app.api.helpers import like_escape, paging, parse_date
from app.config import get_settings
from app.db import get_db, utcnow
from app.deps import err, get_owned, request_id, require_user
from app.models import Scan, ScanReport, UploadedFile, User, Vulnerability
from app.services import file_service, scan_service, storage_service
from app.services.audit_service import audit
from app.utils.validation import ValidationError, validate_bytecode

router = APIRouter(prefix="/api")
MAX_ACTIVE_SCANS = 5


class ScanIn(BaseModel):
    file_id: int | None = None
    bytecode: str | None = Field(default=None, max_length=60_000)
    name: str | None = Field(default=None, max_length=120)
    project_id: int | None = None
    run_decompiler: bool = True
    run_mythril: bool = True


def _read_hex(db: Session, f: UploadedFile) -> str:
    try:
        return storage_service.read(get_settings(), "uploads", f.generated_storage_key).decode("ascii")
    except OSError:
        raise err(410, "file_missing", "The stored file is no longer available.")


def _active(db: Session, user: User) -> int:
    return db.scalar(select(func.count()).select_from(Scan).where(
        Scan.owner_user_id == user.id, Scan.scan_status.in_(("QUEUED", "RUNNING")))) or 0


def _start(db: Session, user: User, f: UploadedFile, project_id, dec: bool, myth: bool) -> Scan:
    if _active(db, user) >= MAX_ACTIVE_SCANS:
        raise err(429, "busy", f"You already have {MAX_ACTIVE_SCANS} scans queued or running. Wait for one to finish.")
    return scan_service.create_scan(db, user, _read_hex(db, f), f, project_id if project_id is not None else f.project_id,
                                    dec, myth, get_settings())


@router.post("/scans", status_code=202)
def create_scan(body: ScanIn, request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    """Queue a scan of a stored file (file_id) or of pasted bytecode (stored as a file first)."""
    if (body.file_id is None) == (body.bytecode is None):
        raise err(422, "bad_request", "Provide either file_id or bytecode.")
    if body.file_id is not None:
        f = get_owned(db, UploadedFile, body.file_id, user)
    else:
        settings = get_settings()
        try:
            hex_code = validate_bytecode(body.bytecode, settings.max_bytecode_bytes)
        except ValidationError as exc:
            raise err(422, exc.code, exc.message)
        name = file_service.sanitize_filename(body.name, default=f"pasted-{hex_code[:8]}.hex")
        f = store_file(db, user, hex_code, "pasted_hex", name, body.project_id, request)
    _check_project(db, user, body.project_id)
    scan = _start(db, user, f, body.project_id, body.run_decompiler, body.run_mythril)
    return scan_service.scan_out(scan)


@router.get("/scans")
def list_scans(status: str | None = None, project_id: int | None = None, file_id: int | None = None,
               severity: str | None = None, q: str | None = None, date_from: str | None = None,
               date_to: str | None = None, page: int = 1, page_size: int = 20,
               user: User = Depends(require_user), db: Session = Depends(get_db)):
    page, page_size, offset = paging(page, page_size)
    cond = [Scan.owner_user_id == user.id]
    if status:
        if status.upper() not in ("QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"):
            raise err(422, "bad_filter", "Unknown status.")
        cond.append(Scan.scan_status == status.upper())
    if project_id is not None:
        cond.append(Scan.project_id == project_id)
    if file_id is not None:
        cond.append(Scan.uploaded_file_id == file_id)
    if severity:
        if severity not in ("high", "medium", "low", "informational"):
            raise err(422, "bad_filter", "Unknown severity.")
        cond.append(Scan.id.in_(select(Vulnerability.scan_id).where(Vulnerability.severity == severity)))
    if q:
        like = f"%{like_escape(q.strip()[:100])}%"
        cond.append(Scan.target_name.ilike(like, escape="\\") | Scan.target_identifier.ilike(like, escape="\\"))
    if (d := parse_date(date_from)):
        cond.append(Scan.created_at >= d)
    if (d := parse_date(date_to, end=True)):
        cond.append(Scan.created_at <= d)
    total = db.scalar(select(func.count()).select_from(Scan).where(*cond)) or 0
    scans = list(db.scalars(select(Scan).where(*cond).order_by(Scan.created_at.desc(), Scan.id.desc()).offset(offset).limit(page_size)))
    counts = scan_service.severity_counts(db, [s.id for s in scans])
    return {"items": [scan_service.scan_out(s, counts[s.id]) for s in scans], "total": total, "page": page, "page_size": page_size}


@router.get("/dashboard")
def dashboard(user: User = Depends(require_user), db: Session = Depends(get_db)):
    scans = list(db.scalars(select(Scan).where(Scan.owner_user_id == user.id).order_by(Scan.created_at.desc(), Scan.id.desc())))
    by_status = defaultdict(int)
    for s in scans:
        by_status[s.scan_status] += 1
    sev = {"high": 0, "medium": 0, "low": 0, "informational": 0}
    reent = 0
    rows = db.execute(select(Vulnerability.severity, Vulnerability.reentrancy_related)
                      .join(Scan, Scan.id == Vulnerability.scan_id).where(Scan.owner_user_id == user.id)).all()
    for s_, r_ in rows:
        sev[s_] += 1
        reent += 1 if r_ else 0
    done = [s for s in scans if s.scan_status == "COMPLETED"]
    durations = [s.duration_ms for s in done if s.duration_ms is not None]
    since = utcnow() - timedelta(days=29)
    per_day: dict[str, int] = defaultdict(int)
    for s in scans:
        if s.created_at >= since:
            per_day[s.created_at.date().isoformat()] += 1
    trend = [{"date": (since + timedelta(days=i)).date().isoformat(),
              "scans": per_day.get((since + timedelta(days=i)).date().isoformat(), 0)} for i in range(30)]
    # Historical change: latest vs previous completed scan of the same bytecode (same SHA-256).
    by_target: dict[str, list[Scan]] = defaultdict(list)
    for s in done:
        by_target[s.target_identifier].append(s)
    changes = []
    for target, lst in by_target.items():
        if len(lst) >= 2:
            latest, prev = lst[0], lst[1]
            c = scan_service.severity_counts(db, [latest.id, prev.id])
            changes.append({"target": target, "file_name": latest.target_name, "latest_scan_id": latest.id,
                            "previous_scan_id": prev.id, "latest_total": c[latest.id]["total"],
                            "previous_total": c[prev.id]["total"], "delta": c[latest.id]["total"] - c[prev.id]["total"]})
    recent = scans[:8]
    rc = scan_service.severity_counts(db, [s.id for s in recent])
    return {
        "totals": {"total": len(scans), "completed": by_status["COMPLETED"], "failed": by_status["FAILED"],
                   "running": by_status["RUNNING"] + by_status["QUEUED"], "cancelled": by_status["CANCELLED"]},
        "vulnerabilities_by_severity": sev, "reentrancy_findings": reent,
        "files_analyzed": len(by_target),
        "avg_duration_ms": int(sum(durations) / len(durations)) if durations else None,
        "recent": [scan_service.scan_out(s, rc[s.id]) for s in recent],
        "trend": trend, "changes": changes[:10],
    }


@router.get("/scans/compare")
def compare_scans(base: int, head: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    b, h = get_owned(db, Scan, base, user), get_owned(db, Scan, head, user)
    for s in (b, h):
        if s.scan_status != "COMPLETED":
            raise err(409, "not_completed", "Both scans must be completed to compare them.")
    return scan_service.compare(db, b, h)


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    s = get_owned(db, Scan, scan_id, user)
    vulns = list(db.scalars(select(Vulnerability).where(Vulnerability.scan_id == s.id)))
    reports = list(db.scalars(select(ScanReport).where(ScanReport.scan_id == s.id)))
    return {**scan_service.scan_out(s, scan_service.severity_counts(db, [s.id])[s.id]),
            "vulnerabilities": [{"id": v.id, "title": v.title, "category": v.category, "severity": v.severity,
                                 "verification_status": v.verification_status, "program_counter": v.program_counter,
                                 "source": v.source} for v in vulns],
            "reports": [{"id": r.id, "kind": r.report_kind, "format": r.report_format,
                         "created_at": r.created_at.isoformat() + "Z"} for r in reports]}


@router.get("/scans/{scan_id}/result")
def get_result(scan_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    """The full analysis in the shape the dashboard renders (instructions, decompiled code, findings)."""
    s = get_owned(db, Scan, scan_id, user)
    if s.scan_status != "COMPLETED":
        raise err(409, "not_completed", f"This scan is {s.scan_status.lower()}; there is no result.")
    try:
        result = scan_service.load_result(db, s, get_settings())
    except ValueError:
        raise err(500, "integrity_failed", "The stored report failed its integrity check.")
    if result is None:
        raise err(410, "report_missing", "The stored report is no longer available.")
    return result


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: int, request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    s = get_owned(db, Scan, scan_id, user)
    if not scan_service.cancel(db, s):
        raise err(409, "not_cancellable", f"A {s.scan_status.lower()} scan cannot be cancelled.")
    audit(db, "scan.cancel", "scan", s.id, actor_user_id=user.id, request_id=request_id(request))
    return scan_service.scan_out(s)


@router.post("/scans/{scan_id}/rerun", status_code=202)
def rerun_scan(scan_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    s = get_owned(db, Scan, scan_id, user)
    f = db.get(UploadedFile, s.uploaded_file_id) if s.uploaded_file_id else None
    if f is None or f.owner_user_id != user.id:
        raise err(409, "file_deleted", "The file for this scan was deleted, so it cannot be re-run.")
    return scan_service.scan_out(_start(db, user, f, s.project_id, s.run_decompiler, s.run_mythril))


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: int, request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    s = get_owned(db, Scan, scan_id, user)
    if s.scan_status in ("QUEUED", "RUNNING"):
        raise err(409, "scan_active", "Cancel the scan before deleting it.")
    keys = list(db.scalars(select(ScanReport.storage_key).where(ScanReport.scan_id == s.id)))
    db.delete(s)
    audit(db, "scan.delete", "scan", scan_id, actor_user_id=user.id, request_id=request_id(request), commit=False)
    db.commit()
    for k in keys:
        storage_service.delete(get_settings(), "reports", k)
    return {"ok": True}


@router.get("/scans/{scan_id}/export")
def export_scan(scan_id: int, format: str = "json", request: Request = None, user: User = Depends(require_user),
                db: Session = Depends(get_db)):
    s = get_owned(db, Scan, scan_id, user)
    if s.scan_status != "COMPLETED":
        raise err(409, "not_completed", "Only completed scans can be exported.")
    result = scan_service.load_result(db, s, get_settings())
    if result is None:
        raise err(410, "report_missing", "The stored report is no longer available.")
    audit(db, "scan.export", "scan", s.id, actor_user_id=user.id, request_id=request_id(request) if request else None)
    headers = {"X-Content-Type-Options": "nosniff"}
    if format == "md":
        vulns = list(db.scalars(select(Vulnerability).where(Vulnerability.scan_id == s.id)))
        headers["Content-Disposition"] = f'attachment; filename="retrace-scan-{s.id}.md"'
        return Response(scan_service.markdown_report(s, result, vulns), media_type="text/markdown; charset=utf-8", headers=headers)
    if format != "json":
        raise err(422, "bad_format", "format must be json or md.")
    headers["Content-Disposition"] = f'attachment; filename="retrace-scan-{s.id}.json"'
    result_meta = {"scan": scan_service.scan_out(s), "analysis": result}
    return JSONResponse(result_meta, headers=headers)
