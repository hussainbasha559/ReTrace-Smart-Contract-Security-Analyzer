from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.helpers import like_escape, paging
from app.config import get_settings
from app.db import get_db
from app.deps import err, get_owned, request_id, require_user
from app.models import Project, Scan, UploadedFile, User
from app.services import file_service, scan_service, storage_service
from app.services.audit_service import audit, usage
from app.utils.validation import ValidationError

router = APIRouter(prefix="/api/files")


class PasteIn(BaseModel):
    bytecode: str = Field(max_length=60_000)
    name: str | None = Field(default=None, max_length=120)
    project_id: int | None = None


class FileUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=120)
    project_id: int | None = None
    clear_project: bool = False


def file_out(f: UploadedFile, scan_count: int = 0, latest: Scan | None = None) -> dict:
    return {
        "id": f.id, "name": f.original_filename, "size": f.file_size, "sha256": f.file_hash,
        "type": f.detected_input_type, "project_id": f.project_id, "created_at": f.created_at.isoformat() + "Z",
        # "processing status": the state of the most recent scan of this file.
        "status": latest.scan_status if latest else "NOT_SCANNED",
        "scan_count": scan_count,
        "latest_scan": None if latest is None else {"id": latest.id, "status": latest.scan_status, "verdict": latest.verdict},
    }


def _check_project(db: Session, user: User, project_id: int | None) -> None:
    if project_id is not None:
        p = db.get(Project, project_id)
        if p is None or p.owner_user_id != user.id:
            raise err(404, "project_not_found", "Project not found.")


def store_file(db: Session, user: User, hex_code: str, detected: str, name: str, project_id: int | None,
               request: Request | None = None) -> UploadedFile:
    settings = get_settings()
    count = db.scalar(select(func.count()).select_from(UploadedFile).where(UploadedFile.owner_user_id == user.id)) or 0
    if count >= settings.max_files_per_user:
        raise err(409, "limit_reached", f"You can store at most {settings.max_files_per_user} files. Delete some first.")
    _check_project(db, user, project_id)
    raw = bytes.fromhex(hex_code)
    key = storage_service.new_key()
    # Stored content is the canonical hex text, whatever the upload format was.
    storage_service.write(settings, "uploads", key, hex_code.encode("ascii"))
    try:
        f = UploadedFile(owner_user_id=user.id, project_id=project_id, original_filename=name,
                         generated_storage_key=key, file_size=len(raw), file_hash=storage_service.sha256(raw),
                         detected_input_type=detected, upload_status="stored")
        db.add(f)
        db.flush()
        usage(db, user.id, "file_uploaded", "file", f.id, quantity=len(raw))
        audit(db, "file.upload", "file", f.id, actor_user_id=user.id,
              request_id=request_id(request) if request else None, commit=False)
        db.commit()
    except Exception:
        db.rollback()
        storage_service.delete(settings, "uploads", key)
        raise
    return f


@router.post("", status_code=201)
def upload(request: Request, file: UploadFile = File(...), project_id: int | None = Form(default=None),
           user: User = Depends(require_user), db: Session = Depends(get_db)):
    settings = get_settings()
    data = file.file.read(settings.max_upload_bytes + 1)      # never read more than the cap
    try:
        hex_code, detected = file_service.detect_and_normalize(data, settings)
    except ValidationError as exc:
        raise err(422, exc.code, exc.message)
    name = file_service.sanitize_filename(file.filename)
    return file_out(store_file(db, user, hex_code, detected, name, project_id, request))


@router.post("/paste", status_code=201)
def paste(body: PasteIn, request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    from app.utils.validation import validate_bytecode
    settings = get_settings()
    try:
        hex_code = validate_bytecode(body.bytecode, settings.max_bytecode_bytes)
    except ValidationError as exc:
        raise err(422, exc.code, exc.message)
    name = file_service.sanitize_filename(body.name, default=f"pasted-{hex_code[:8]}.hex")
    return file_out(store_file(db, user, hex_code, "pasted_hex", name, body.project_id, request))


@router.get("")
def list_files(q: str | None = None, project_id: int | None = None, page: int = 1, page_size: int = 20,
               user: User = Depends(require_user), db: Session = Depends(get_db)):
    page, page_size, offset = paging(page, page_size)
    cond = [UploadedFile.owner_user_id == user.id]
    if q:
        cond.append(UploadedFile.original_filename.ilike(f"%{like_escape(q.strip()[:100])}%", escape="\\"))
    if project_id is not None:
        cond.append(UploadedFile.project_id == project_id)
    total = db.scalar(select(func.count()).select_from(UploadedFile).where(*cond)) or 0
    files = list(db.scalars(select(UploadedFile).where(*cond).order_by(UploadedFile.created_at.desc(), UploadedFile.id.desc())
                            .offset(offset).limit(page_size)))
    ids = [f.id for f in files]
    counts = dict(db.execute(select(Scan.uploaded_file_id, func.count()).where(Scan.uploaded_file_id.in_(ids))
                             .group_by(Scan.uploaded_file_id)).all()) if ids else {}
    latest: dict[int, Scan] = {}
    if ids:
        for s in db.scalars(select(Scan).where(Scan.uploaded_file_id.in_(ids)).order_by(Scan.id)):
            latest[s.uploaded_file_id] = s
    return {"items": [file_out(f, counts.get(f.id, 0), latest.get(f.id)) for f in files],
            "total": total, "page": page, "page_size": page_size}


@router.get("/{file_id}")
def get_file(file_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    f = get_owned(db, UploadedFile, file_id, user)
    scans = list(db.scalars(select(Scan).where(Scan.uploaded_file_id == f.id).order_by(Scan.id.desc())))
    counts = scan_service.severity_counts(db, [s.id for s in scans])
    return {**file_out(f, len(scans), scans[0] if scans else None),
            "scans": [scan_service.scan_out(s, counts[s.id]) for s in scans]}


@router.patch("/{file_id}")
def update_file(file_id: int, body: FileUpdate, request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    f = get_owned(db, UploadedFile, file_id, user)
    if body.name is not None:
        f.original_filename = file_service.sanitize_filename(body.name, default=f.original_filename)
    if body.clear_project:
        f.project_id = None
    elif body.project_id is not None:
        _check_project(db, user, body.project_id)
        f.project_id = body.project_id
    audit(db, "file.update", "file", f.id, actor_user_id=user.id, request_id=request_id(request), commit=False)
    db.commit()
    return file_out(f)


@router.get("/{file_id}/download")
def download(file_id: int, request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    f = get_owned(db, UploadedFile, file_id, user)
    try:
        data = storage_service.read(get_settings(), "uploads", f.generated_storage_key)
    except OSError:
        raise err(410, "file_missing", "The stored file is no longer available.")
    if storage_service.sha256(bytes.fromhex(data.decode("ascii"))) != f.file_hash:
        raise err(500, "integrity_failed", "The stored file failed its integrity check.")
    audit(db, "file.download", "file", f.id, actor_user_id=user.id, request_id=request_id(request))
    fname = f.original_filename if f.original_filename.lower().endswith((".hex", ".txt")) else f.original_filename + ".hex"
    return Response(data, media_type="text/plain; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="{fname}"', "X-Content-Type-Options": "nosniff"})


@router.delete("/{file_id}")
def delete_file(file_id: int, request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    f = get_owned(db, UploadedFile, file_id, user)
    key = f.generated_storage_key
    db.delete(f)           # scans keep their history; uploaded_file_id becomes NULL
    audit(db, "file.delete", "file", file_id, actor_user_id=user.id, request_id=request_id(request), commit=False)
    db.commit()            # remove the stored bytes only after the DB change committed
    storage_service.delete(get_settings(), "uploads", key)
    return {"ok": True}
