from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import err, get_owned, request_id, require_user
from app.models import Project, Scan, UploadedFile, User
from app.services.audit_service import audit

router = APIRouter(prefix="/api/projects")
MAX_PROJECTS = 50


class ProjectIn(BaseModel):
    project_name: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=1000)


def _out(p: Project, files: int = 0, scans: int = 0) -> dict:
    return {"id": p.id, "project_name": p.project_name, "description": p.description,
            "created_at": p.created_at.isoformat() + "Z", "file_count": files, "scan_count": scans}


@router.get("")
def list_projects(user: User = Depends(require_user), db: Session = Depends(get_db)):
    projects = list(db.scalars(select(Project).where(Project.owner_user_id == user.id).order_by(Project.project_name)))
    fc = dict(db.execute(select(UploadedFile.project_id, func.count()).where(UploadedFile.owner_user_id == user.id)
                         .group_by(UploadedFile.project_id)).all())
    sc = dict(db.execute(select(Scan.project_id, func.count()).where(Scan.owner_user_id == user.id)
                         .group_by(Scan.project_id)).all())
    return {"items": [_out(p, fc.get(p.id, 0), sc.get(p.id, 0)) for p in projects]}


@router.post("", status_code=201)
def create_project(body: ProjectIn, request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    name = " ".join(body.project_name.split())
    if not name or any(ord(c) < 32 or c in "<>" for c in name):
        raise err(422, "validation_error", "Project name contains characters that are not allowed.")
    if (db.scalar(select(func.count()).select_from(Project).where(Project.owner_user_id == user.id)) or 0) >= MAX_PROJECTS:
        raise err(409, "limit_reached", f"You can have at most {MAX_PROJECTS} projects.")
    p = Project(owner_user_id=user.id, project_name=name, description=body.description)
    db.add(p)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise err(409, "duplicate", "You already have a project with this name.")
    audit(db, "project.create", "project", p.id, actor_user_id=user.id, request_id=request_id(request), commit=False)
    db.commit()
    return _out(p)


@router.patch("/{project_id}")
def update_project(project_id: int, body: ProjectIn, user: User = Depends(require_user), db: Session = Depends(get_db)):
    p = db.get(Project, project_id)
    if p is None or p.owner_user_id != user.id:
        raise err(404, "not_found", "Not found.")
    p.project_name = " ".join(body.project_name.split())
    p.description = body.description
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise err(409, "duplicate", "You already have a project with this name.")
    return _out(p)


@router.delete("/{project_id}")
def delete_project(project_id: int, request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    p = db.get(Project, project_id)
    if p is None or p.owner_user_id != user.id:
        raise err(404, "not_found", "Not found.")
    db.delete(p)      # files and scans keep existing; their project_id becomes NULL
    audit(db, "project.delete", "project", project_id, actor_user_id=user.id, request_id=request_id(request), commit=False)
    db.commit()
    return {"ok": True}
