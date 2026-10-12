"""Scan lifecycle: QUEUED -> RUNNING -> COMPLETED | FAILED | CANCELLED.

A scan is COMPLETED only after the analysis pipeline has returned and its results (vulnerability
rows, report file) have been committed. A pipeline that finishes with a tool timeout/failure is
still COMPLETED but its verdict is "analysis_incomplete" and error_summary says why: the work
finished, the answer is just partial. FAILED means the pipeline itself could not run.
"""
from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import session_factory, utcnow
from app.models import Scan, ScanReport, UploadedFile, User, Vulnerability
from app.services import report_service, storage_service
from app.services.audit_service import audit, usage
from app.utils.validation import ValidationError

log = logging.getLogger("retrace.scans")

_executor: ThreadPoolExecutor | None = None


def _pool() -> ThreadPoolExecutor:
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(max_workers=get_settings().max_concurrent_analyses, thread_name_prefix="scan")
    return _executor


def recover_stale_scans() -> int:
    """At startup, scans left QUEUED/RUNNING by a previous process can never finish (jobs live in
    memory), so mark them FAILED instead of leaving them 'running' forever."""
    with session_factory()() as db:
        stale = list(db.scalars(select(Scan).where(Scan.scan_status.in_(("QUEUED", "RUNNING")))))
        for s in stale:
            s.scan_status = "FAILED"
            s.completed_at = utcnow()
            s.error_summary = "The server restarted before this scan finished. Re-run it."
        db.commit()
        return len(stale)


def create_scan(db: Session, user: User, hex_code: str, file: UploadedFile | None, project_id: int | None,
                run_decompiler: bool, run_mythril: bool, settings: Settings) -> Scan:
    scan = Scan(
        owner_user_id=user.id, project_id=project_id, uploaded_file_id=file.id if file else None,
        target_identifier=storage_service.sha256(bytes.fromhex(hex_code)), target_name=file.original_filename if file else None,
        scan_status="QUEUED", run_decompiler=run_decompiler, run_mythril=run_mythril,
        input_bytes=len(hex_code) // 2, analyzer_version=settings.analyzer_version,
    )
    db.add(scan)
    db.flush()
    usage(db, user.id, "scan_created", "scan", scan.id, quantity=1)
    audit(db, "scan.create", "scan", scan.id, actor_user_id=user.id, commit=False)
    db.commit()
    scan_id = scan.id
    if settings.jobs_inline:
        run_job(scan_id, hex_code)
    else:
        _pool().submit(run_job, scan_id, hex_code)
    db.refresh(scan)
    return scan


def run_job(scan_id: int, hex_code: str) -> None:
    settings = get_settings()
    SessionLocal = session_factory()
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None or scan.scan_status != "QUEUED":     # cancelled (or deleted) while queued
            return
        scan.scan_status = "RUNNING"
        scan.started_at = utcnow()
        db.commit()
        owner_id = scan.owner_user_id
        run_dec, run_myth = scan.run_decompiler, scan.run_mythril

    result = None
    error: str | None = None
    attempts = 0
    t0 = time.monotonic()
    while attempts < max(1, settings.scan_max_attempts):
        attempts += 1
        try:
            result = report_service.analyze(hex_code, run_dec, run_myth, settings)
            error = None
            break
        except ValidationError as exc:                       # bad input will not improve on retry
            error = exc.message
            break
        except Exception:                                    # unexpected internal error: retry
            log.exception("scan %s attempt %s crashed", scan_id, attempts)
            error = "The analyzer hit an internal error."
    duration_ms = int((time.monotonic() - t0) * 1000)

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None or scan.scan_status != "RUNNING":    # cancelled while running: discard result
            return
        scan.attempts = attempts
        scan.duration_ms = duration_ms
        scan.completed_at = utcnow()
        if result is None:
            scan.scan_status = "FAILED"
            scan.error_summary = error
            usage(db, owner_id, "scan_failed", "scan", scan_id, duration_ms=duration_ms)
            audit(db, "scan.finish", "scan", scan_id, outcome="failure", actor_user_id=owner_id, commit=False)
            db.commit()
            return
        payload = result.model_dump(mode="json")
        raw = json.dumps(payload, separators=(",", ":")).encode()
        key = storage_service.new_key()
        storage_service.write(settings, "reports", key, raw)
        try:
            _store_vulnerabilities(db, scan, payload)
            db.add(ScanReport(scan_id=scan_id, report_kind="analysis", report_format="json",
                              storage_key=key, report_hash=storage_service.sha256(raw)))
            scan.verdict = payload["verdict"]
            problems = [f"{t['name']}: {t['status']}" + (f" ({t['error']})" if t.get("error") else "")
                        for t in payload["tools"] if t["status"] in ("not_installed", "timeout", "error")]
            scan.error_summary = "; ".join(problems)[:2000] or None
            scan.scan_status = "COMPLETED"                   # only now: results are persisted
            usage(db, owner_id, "scan_completed", "scan", scan_id, duration_ms=duration_ms)
            audit(db, "scan.finish", "scan", scan_id, actor_user_id=owner_id, commit=False)
            db.commit()
        except Exception:
            db.rollback()
            storage_service.delete(settings, "reports", key)
            log.exception("could not persist scan %s", scan_id)
            scan = db.get(Scan, scan_id)
            scan.scan_status = "FAILED"
            scan.completed_at = utcnow()
            scan.duration_ms = duration_ms
            scan.error_summary = "Results could not be saved."
            db.commit()


def verification_status(f: dict) -> str:
    if f.get("corroborated_by"):
        return "corroborated"        # two independent methods point at the same instruction
    if f["source"] == "mythril":
        return "symbolically_feasible"
    return "heuristic"


def _store_vulnerabilities(db: Session, scan: Scan, payload: dict) -> None:
    for f in payload["findings"]:
        pcs = f["evidence"]["pcs"]
        db.add(Vulnerability(
            scan_id=scan.id,
            category="reentrancy" if f["reentrancy_related"] else f["title"][:120],
            title=f["title"][:200], swc_id=f.get("swc_id"), source=f["source"], severity=f["severity"],
            confidence_label=f["confidence"], verification_status=verification_status(f),
            reentrancy_related=f["reentrancy_related"], program_counter=pcs[0] if pcs else None,
            opcode_evidence=f["evidence"]["instructions"], description=f["description"],
            remediation=f["recommendation"],
        ))


def load_result(db: Session, scan: Scan, settings: Settings) -> dict | None:
    """The full analysis (instructions, decompiled code, findings), verified against its stored hash."""
    rep = db.scalar(select(ScanReport).where(ScanReport.scan_id == scan.id, ScanReport.report_kind == "analysis"))
    if rep is None:
        return None
    try:
        raw = storage_service.read(settings, "reports", rep.storage_key)
    except OSError:
        return None
    if storage_service.sha256(raw) != rep.report_hash:
        raise ValueError("report_integrity_failed")
    return json.loads(raw)


def cancel(db: Session, scan: Scan) -> bool:
    if scan.scan_status not in ("QUEUED", "RUNNING"):
        return False
    scan.scan_status = "CANCELLED"
    scan.completed_at = utcnow()
    scan.error_summary = "Cancelled by the user."
    db.commit()
    return True


def scan_out(s: Scan, counts: dict | None = None) -> dict:
    return {
        "id": s.id, "status": s.scan_status, "verdict": s.verdict, "scan_type": s.scan_type,
        "project_id": s.project_id, "file_id": s.uploaded_file_id, "file_name": s.target_name,
        "target": s.target_identifier, "input_bytes": s.input_bytes,
        "run_decompiler": s.run_decompiler, "run_mythril": s.run_mythril,
        "created_at": s.created_at.isoformat() + "Z",
        "started_at": s.started_at.isoformat() + "Z" if s.started_at else None,
        "completed_at": s.completed_at.isoformat() + "Z" if s.completed_at else None,
        "duration_ms": s.duration_ms, "analyzer_version": s.analyzer_version,
        "error_summary": s.error_summary, "attempts": s.attempts,
        "severity_counts": counts,
    }


def severity_counts(db: Session, scan_ids: list[int]) -> dict[int, dict]:
    out = {i: {"high": 0, "medium": 0, "low": 0, "informational": 0, "reentrancy": 0, "total": 0} for i in scan_ids}
    if not scan_ids:
        return out
    for sid, sev, re_rel in db.execute(
        select(Vulnerability.scan_id, Vulnerability.severity, Vulnerability.reentrancy_related)
        .where(Vulnerability.scan_id.in_(scan_ids))
    ):
        out[sid][sev] += 1
        out[sid]["total"] += 1
        if re_rel:
            out[sid]["reentrancy"] += 1
    return out


def compare(db: Session, base: Scan, head: Scan) -> dict:
    def rows(s: Scan):
        return list(db.scalars(select(Vulnerability).where(Vulnerability.scan_id == s.id)))

    def key(v: Vulnerability):
        return (v.source, v.title, v.swc_id, v.program_counter)

    def brief(v: Vulnerability):
        return {"title": v.title, "severity": v.severity, "source": v.source, "swc_id": v.swc_id,
                "program_counter": v.program_counter, "verification_status": v.verification_status,
                "reentrancy_related": v.reentrancy_related}

    b, h = {key(v): v for v in rows(base)}, {key(v): v for v in rows(head)}
    sc = severity_counts(db, [base.id, head.id])
    return {
        "base": scan_out(base, sc[base.id]), "head": scan_out(head, sc[head.id]),
        "same_target": base.target_identifier == head.target_identifier,
        "introduced": [brief(h[k]) for k in h if k not in b],
        "resolved": [brief(b[k]) for k in b if k not in h],
        "unchanged": [brief(h[k]) for k in h if k in b],
        "verdict_changed": base.verdict != head.verdict,
        "note": ("Findings are matched on source, title, SWC id and program counter. If the two scans analyzed "
                 "different bytecode, program counters shift, so a moved finding can appear as one resolved "
                 "and one introduced; compare the evidence before concluding a fix worked."),
    }


def markdown_report(s: Scan, result: dict, vulns: list[Vulnerability]) -> str:
    """Deterministic export built only from stored analyzer output (no AI text)."""
    L = [f"# ReTrace scan report #{s.id}", "",
         f"- Target (SHA-256): `{s.target_identifier}`", f"- File: {s.target_name or '(pasted)'}",
         f"- Bytecode size: {s.input_bytes} bytes", f"- Status: {s.scan_status}",
         f"- Verdict: {s.verdict}", f"- Analyzer: {s.analyzer_version}",
         f"- Completed: {s.completed_at.isoformat() + 'Z' if s.completed_at else '-'}", "",
         f"**Verdict reason:** {result.get('verdict_reason', '')}", "", "## Tools", ""]
    for t in result.get("tools", []):
        L.append(f"- {t['name']}: {t['status']}" + (f" - {t['error']}" if t.get("error") else ""))
    L += ["", f"## Findings ({len(vulns)})", ""]
    for v in vulns:
        L += [f"### {v.title} ({v.severity})", "",
              f"- Source: {v.source}; verification: {v.verification_status}; SWC: {v.swc_id or '-'}",
              f"- Program counter: {v.program_counter if v.program_counter is not None else '-'}", "",
              v.description, "", f"**Remediation:** {v.remediation}", ""]
        if v.opcode_evidence:
            L.append("Instructions near the finding:\n")
            for i in v.opcode_evidence:
                L.append(f"    {i['pc']:>6}  {i['name']} {('0x' + i['operand']) if i.get('operand') else ''}".rstrip())
            L.append("")
    if result.get("warnings"):
        L += ["## Warnings", ""] + [f"- {w}" for w in result["warnings"]] + [""]
    L.append("_No finding is a proof of exploitability or of safety. Symbolic execution is bounded by timeouts and depth._")
    return "\n".join(L) + "\n"
