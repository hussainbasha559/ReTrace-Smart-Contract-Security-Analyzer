"""Stateless utility endpoints. Scans go through api/scan_routes.py so that every analysis is
owned by a user and recorded."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.adapters import heimdall_adapter, mythril_adapter
from app.config import get_settings
from app.deps import require_user
from app.models import User
from app.schemas import DisassembleRequest, DisassembleResponse, HealthResponse
from app.services import report_service
from app.utils.validation import ValidationError

router = APIRouter(prefix="/api")


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    s = get_settings()
    return HealthResponse(
        status="ok",
        tools={"heimdall": heimdall_adapter.is_available(s), "mythril": mythril_adapter.is_available(s)},
        details={"heimdall": heimdall_adapter.describe(s), "mythril": mythril_adapter.describe(s)},
    )


@router.post("/disassemble", response_model=DisassembleResponse)
def disassemble(req: DisassembleRequest, user: User = Depends(require_user)) -> DisassembleResponse:
    try:
        return report_service.disassemble_only(req.bytecode, get_settings())
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail={"code": exc.code, "message": exc.message})
