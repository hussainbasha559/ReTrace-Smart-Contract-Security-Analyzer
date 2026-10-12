from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai import service as ai
from app.ai.providers import AIProviderError, get_provider
from app.config import get_settings
from app.db import get_db
from app.deps import err, get_owned, request_id, require_user
from app.models import AIAnalysis, Scan, ScanReport, User
from app.security import limiter
from app.services import scan_service, storage_service
from app.services.audit_service import audit, usage

router = APIRouter(prefix="/api")


class ReportIn(BaseModel):
    kind: str = "executive"
    compare_with_scan_id: int | None = None   # base scan for kind=comparison


class ChatMessage(BaseModel):
    role: str
    content: str = Field(max_length=2000)


class ChatIn(BaseModel):
    messages: list[ChatMessage] = Field(min_length=1, max_length=12)


def _ctx(db: Session, scan: Scan, user: User) -> dict:
    if scan.scan_status != "COMPLETED":
        raise err(409, "not_completed", "AI analysis needs a completed scan.")
    result = scan_service.load_result(db, scan, get_settings())
    if result is None:
        raise err(410, "report_missing", "The stored report is no longer available.")
    return ai.build_context(result)


def _record(db: Session, user: User, scan: Scan, kind: str, provider: str, model: str | None, status: str,
            text: str | None, res=None) -> AIAnalysis:
    row = AIAnalysis(owner_user_id=user.id, scan_id=scan.id, provider=provider, model_name=model, analysis_type=kind,
                     status=status, result_summary=(text or "")[:300] or None, result_text=text,
                     token_usage=res.total_tokens if res else None, prompt_tokens=res.prompt_tokens if res else None,
                     completion_tokens=res.completion_tokens if res else None)
    db.add(row)
    usage(db, user.id, "ai_analysis", "scan", scan.id)
    db.commit()
    return row


def _guard_llm(user: User, provider) -> None:
    s = get_settings()
    if provider is not None and not limiter.check(f"ai:{user.id}", s.ai_requests_per_hour, 3600):
        raise err(429, "rate_limited", "AI request limit reached for this hour. Try again later.")


def _run(db, request, user, scan, kind, fn):
    """Call an AI function, persist the outcome, and shape the response."""
    s = get_settings()
    provider = get_provider(s)
    _guard_llm(user, provider)
    try:
        text, res, issues = fn(provider)
    except AIProviderError as exc:
        _record(db, user, scan, kind, provider.name if provider else "builtin-rules", s.ai_model, "failed", None)
        raise err(502, "ai_failed", str(exc))
    row = _record(db, user, scan, kind, res and provider.name or "builtin-rules", res.model if res else None, "completed", text, res)
    audit(db, f"ai.{kind}", "scan", scan.id, actor_user_id=user.id, request_id=request_id(request))
    return {"analysis_id": row.id, "kind": kind, "text": text, "provider": row.provider, "model": row.model_name,
            "generated_by_llm": res is not None, "grounding_warnings": issues,
            "disclaimer": ("AI-generated interpretation of the analyzer's findings; verify against the evidence."
                           if res else "Rule-based guidance from reviewed templates; no LLM was used.")}


@router.get("/ai/status")
def ai_status(user: User = Depends(require_user)):
    s = get_settings()
    configured = s.ai_provider != "none" and bool(s.ai_api_key)
    return {"llm_configured": configured, "provider": s.ai_provider if configured else None,
            "model": s.ai_model if configured else None,
            "chat_available": configured,
            "note": None if configured else "No LLM provider is configured. Risk assessment and rule-based explanations still work; chat and AI-written reports need RETRACE_AI_PROVIDER and an API key."}


@router.post("/scans/{scan_id}/ai/explain")
def explain(scan_id: int, request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    scan = get_owned(db, Scan, scan_id, user)
    ctx = _ctx(db, scan, user)
    return _run(db, request, user, scan, "explain", lambda p: ai.explain(p, ctx, get_settings().ai_max_tokens))


@router.post("/scans/{scan_id}/ai/remediation")
def remediation(scan_id: int, request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    scan = get_owned(db, Scan, scan_id, user)
    ctx = _ctx(db, scan, user)
    return _run(db, request, user, scan, "remediation", lambda p: ai.remediation(p, ctx, get_settings().ai_max_tokens))


@router.post("/scans/{scan_id}/ai/risk")
def risk_assessment(scan_id: int, request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    """Deterministic: computed from stored findings, no LLM, so it is repeatable."""
    scan = get_owned(db, Scan, scan_id, user)
    out = ai.compute_risk(_ctx(db, scan, user))
    _record(db, user, scan, "risk", "deterministic", out["model"], "completed", f"{out['overall_risk_category']}")
    return out


@router.post("/scans/{scan_id}/ai/report")
def make_report(scan_id: int, body: ReportIn, request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    if body.kind not in ai.REPORT_KINDS:
        raise err(422, "bad_kind", "Unknown report kind.")
    scan = get_owned(db, Scan, scan_id, user)
    ctx = _ctx(db, scan, user)
    comparison = None
    if body.kind == "comparison":
        if body.compare_with_scan_id is None:
            raise err(422, "bad_request", "Choose the scan to compare against.")
        base = get_owned(db, Scan, body.compare_with_scan_id, user)
        if base.scan_status != "COMPLETED":
            raise err(409, "not_completed", "Both scans must be completed.")
        comparison = scan_service.compare(db, base, scan)
    s = get_settings()
    provider = get_provider(s)
    _guard_llm(user, provider)
    try:
        observed, interp, res, issues, source = ai.report(provider, body.kind, ctx, s.ai_max_tokens + 600, comparison)
    except AIProviderError as exc:
        _record(db, user, scan, "report", provider.name if provider else "builtin-rules", s.ai_model, "failed", None)
        raise err(502, "ai_failed", str(exc))
    md = (f"# {body.kind.replace('_', ' ').title()} report - scan #{scan.id}\n\n## Observed evidence (from the analyzers)\n\n{observed}\n\n"
          f"## Interpretation ({'AI-generated by ' + source if res else 'rule-based, no LLM'})\n\n{interp}\n")
    raw = md.encode()
    key = storage_service.new_key()
    storage_service.write(s, "reports", key, raw)
    try:
        db.add(ScanReport(scan_id=scan.id, report_kind=f"ai_{body.kind}", report_format="md", storage_key=key,
                          report_hash=storage_service.sha256(raw)))
        row = _record(db, user, scan, "report", source if res else "builtin-rules", res.model if res else None, "completed", md, res)
    except Exception:
        db.rollback()
        storage_service.delete(s, "reports", key)
        raise
    audit(db, "ai.report", "scan", scan.id, actor_user_id=user.id, request_id=request_id(request))
    return {"analysis_id": row.id, "kind": body.kind, "observed_evidence": observed, "interpretation": interp,
            "markdown": md, "provider": row.provider, "model": row.model_name, "generated_by_llm": res is not None,
            "grounding_warnings": issues}


@router.post("/scans/{scan_id}/ai/chat")
def chat(scan_id: int, body: ChatIn, request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    scan = get_owned(db, Scan, scan_id, user)       # the model only ever sees this user's scan
    s = get_settings()
    provider = get_provider(s)
    if provider is None:
        raise err(503, "ai_not_configured", "The chat assistant needs an LLM provider. Ask the administrator to configure one.")
    if any(m.role not in ("user", "assistant") for m in body.messages) or body.messages[-1].role != "user":
        raise err(422, "bad_request", "Messages must alternate user/assistant and end with a user message.")
    _guard_llm(user, provider)
    ctx = _ctx(db, scan, user)
    history = [{"role": m.role, "content": m.content} for m in body.messages]
    try:
        res, issues = ai.chat(provider, ctx, history, s.ai_max_tokens)
    except AIProviderError as exc:
        _record(db, user, scan, "chat", provider.name, s.ai_model, "failed", None)
        raise err(502, "ai_failed", str(exc))
    _record(db, user, scan, "chat", provider.name, res.model, "completed", res.text, res)
    return {"reply": res.text, "provider": provider.name, "model": res.model, "grounding_warnings": issues,
            "disclaimer": "AI-generated; it only saw this scan's analyzer findings."}


@router.get("/scans/{scan_id}/ai/history")
def ai_history(scan_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    scan = get_owned(db, Scan, scan_id, user)
    rows = db.scalars(select(AIAnalysis).where(AIAnalysis.scan_id == scan.id, AIAnalysis.owner_user_id == user.id,
                                               AIAnalysis.analysis_type != "chat").order_by(AIAnalysis.id.desc()).limit(20))
    return {"items": [{"id": r.id, "type": r.analysis_type, "provider": r.provider, "model": r.model_name, "status": r.status,
                       "summary": r.result_summary, "created_at": r.created_at.isoformat() + "Z"} for r in rows]}
