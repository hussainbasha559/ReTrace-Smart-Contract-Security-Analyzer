"""Deleting a user's data (retention / right-to-erasure)."""
from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import AIAnalysis, Project, Scan, ScanReport, UploadedFile, UsageEvent, User
from app.services import storage_service


def delete_user_data(db: Session, user: User, settings: Settings) -> dict[str, int]:
    report_keys = list(db.scalars(
        select(ScanReport.storage_key).join(Scan, Scan.id == ScanReport.scan_id).where(Scan.owner_user_id == user.id)))
    file_keys = list(db.scalars(select(UploadedFile.generated_storage_key).where(UploadedFile.owner_user_id == user.id)))
    counts = {
        "scans": db.query(Scan).filter(Scan.owner_user_id == user.id).count(),
        "files": len(file_keys),
        "reports": len(report_keys),
    }
    # DB first (one transaction); stored files are removed only after the commit succeeds.
    db.execute(delete(AIAnalysis).where(AIAnalysis.owner_user_id == user.id))
    db.execute(delete(Scan).where(Scan.owner_user_id == user.id))          # cascades vulns + reports
    db.execute(delete(UploadedFile).where(UploadedFile.owner_user_id == user.id))
    db.execute(delete(Project).where(Project.owner_user_id == user.id))
    db.execute(delete(UsageEvent).where(UsageEvent.owner_user_id == user.id))
    db.commit()
    for k in report_keys:
        storage_service.delete(settings, "reports", k)
    for k in file_keys:
        storage_service.delete(settings, "uploads", k)
    return counts
