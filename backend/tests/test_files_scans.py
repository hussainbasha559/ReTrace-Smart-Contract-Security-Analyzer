import os
from pathlib import Path

import pytest
from sqlalchemy import select

from app.config import get_settings
from app.db import session_factory
from app.models import AuditLog, Scan, UploadedFile
from app.services import scan_service
from tests.conftest import SAFE, VULNERABLE, mythril_json, run_scan

HEX = "0x6001600055"


def up(s, content, name="c.hex", **data):
    return s.post("/api/files", files={"file": (name, content, "application/octet-stream")}, data=data)


def test_upload_hex_binary_and_paste(alice):
    a = up(alice, HEX.encode())
    assert a.status_code == 201 and a.json()["type"] == "hex_text" and a.json()["size"] == 5
    b = up(alice, bytes.fromhex("6001600055"), "raw.bin")
    assert b.status_code == 201 and b.json()["type"] == "raw_binary" and b.json()["sha256"] == a.json()["sha256"]
    c = alice.post("/api/files/paste", json={"bytecode": HEX, "name": "pasted"})
    assert c.json()["type"] == "pasted_hex"


@pytest.mark.parametrize("content,code", [(b"", "empty"), (b"pragma solidity ^0.8.0; contract A {}", "unsupported_format"),
                                          (b"0x123", "odd_length"), (b"A" * 200_000, "too_large")])
def test_upload_rejects_non_bytecode_by_content(alice, content, code):
    r = up(alice, content, "evil.hex")        # a .hex name does not make it valid
    assert r.status_code in (413, 422) and (r.status_code == 413 or r.json()["detail"]["code"] == code)


def test_filename_is_sanitized_and_storage_is_server_named(alice):
    r = up(alice, HEX.encode(), "../../etc/passwd<script>.hex")
    name = r.json()["name"]
    assert "/" not in name and "<" not in name and ".." not in name.replace("...", "")
    with session_factory()() as db:
        f = db.scalar(select(UploadedFile))
        p = Path(get_settings().storage_dir) / "uploads" / f.generated_storage_key[:2] / f.generated_storage_key
        assert p.exists() and "passwd" not in str(p)
    assert str(get_settings().storage_dir) not in r.text      # no filesystem paths leak


def test_ownership_enforced_on_every_file_operation(alice, bob):
    fid = up(alice, HEX.encode()).json()["id"]
    assert bob.get(f"/api/files/{fid}").status_code == 404
    assert bob.get(f"/api/files/{fid}/download").status_code == 404
    assert bob.patch(f"/api/files/{fid}", json={"name": "x"}).status_code == 404
    assert bob.delete(f"/api/files/{fid}").status_code == 404
    assert bob.post("/api/scans", json={"file_id": fid}).status_code == 404
    assert bob.get("/api/files").json()["total"] == 0
    assert alice.get(f"/api/files/{fid}").status_code == 200


def test_rename_download_delete_removes_stored_bytes(alice):
    fid = up(alice, HEX.encode()).json()["id"]
    assert alice.patch(f"/api/files/{fid}", json={"name": "renamed"}).json()["name"] == "renamed"
    d = alice.get(f"/api/files/{fid}/download")
    assert d.status_code == 200 and d.text == "6001600055" and "attachment" in d.headers["content-disposition"]
    with session_factory()() as db:
        key = db.scalar(select(UploadedFile)).generated_storage_key
    stored = Path(get_settings().storage_dir) / "uploads" / key[:2] / key
    assert stored.exists()
    assert alice.delete(f"/api/files/{fid}").status_code == 200
    assert not stored.exists() and alice.get(f"/api/files/{fid}").status_code == 404


def test_project_must_be_owned(alice, bob):
    pid = alice.post("/api/projects", json={"project_name": "Bank"}).json()["id"]
    assert up(bob, HEX.encode(), project_id=pid).status_code == 404
    assert up(alice, HEX.encode(), project_id=pid).status_code == 201
    assert alice.post("/api/projects", json={"project_name": "Bank"}).status_code == 409
    assert bob.get("/api/projects").json()["items"] == []


def test_scan_from_file_links_file_and_history(alice, fake_tools):
    fid = up(alice, VULNERABLE.encode()).json()["id"]
    sid = alice.post("/api/scans", json={"file_id": fid}).json()["id"]
    scan = alice.get(f"/api/scans/{sid}").json()
    assert scan["status"] == "COMPLETED" and scan["file_id"] == fid and scan["duration_ms"] is not None
    f = alice.get(f"/api/files/{fid}").json()
    assert f["scan_count"] == 1 and f["status"] == "COMPLETED" and f["scans"][0]["id"] == sid
    assert alice.get("/api/files").json()["items"][0]["latest_scan"]["verdict"] == "issues_detected"


def test_scans_are_private(alice, bob, fake_tools):
    sid = run_scan(alice, SAFE)["id"]
    for path in (f"/api/scans/{sid}", f"/api/scans/{sid}/result", f"/api/scans/{sid}/export"):
        assert bob.get(path).status_code == 404
    assert bob.post(f"/api/scans/{sid}/cancel").status_code == 404
    assert bob.post(f"/api/scans/{sid}/rerun").status_code == 404
    assert bob.delete(f"/api/scans/{sid}").status_code == 404
    assert bob.get("/api/scans").json()["total"] == 0
    assert bob.get("/api/scans/compare", params={"base": sid, "head": sid}).status_code == 404


def test_lifecycle_failed_and_not_completed_until_persisted(alice, fake_tools, monkeypatch):
    from app.services import report_service
    monkeypatch.setattr(report_service, "analyze", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    scan = run_scan(alice, SAFE)
    assert scan["status"] == "FAILED" and scan["attempts"] == 2          # retried once, then failed
    assert alice.get(f"/api/scans/{scan['id']}/result").status_code == 409
    assert "boom" not in str(scan)                                        # internals are not leaked


def test_queued_scan_can_be_cancelled_and_job_discards(alice, fake_tools, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(scan_service, "run_job", lambda *a, **k: None)   # leave it QUEUED
    r = alice.post("/api/scans", json={"bytecode": SAFE})
    sid = r.json()["id"]
    assert alice.get(f"/api/scans/{sid}").json()["status"] == "QUEUED"
    assert alice.post(f"/api/scans/{sid}/cancel").json()["status"] == "CANCELLED"
    monkeypatch.undo()
    scan_service.run_job(sid, SAFE)                                       # worker wakes up later
    assert alice.get(f"/api/scans/{sid}").json()["status"] == "CANCELLED"
    assert alice.post(f"/api/scans/{sid}/cancel").status_code == 409


def test_stale_scans_recovered_at_startup(alice, fake_tools, monkeypatch):
    monkeypatch.setattr(scan_service, "run_job", lambda *a, **k: None)
    sid = alice.post("/api/scans", json={"bytecode": SAFE}).json()["id"]
    assert scan_service.recover_stale_scans() == 1
    assert alice.get(f"/api/scans/{sid}").json()["status"] == "FAILED"


def test_rerun_filters_pagination_dashboard(alice, fake_tools):
    fid = up(alice, VULNERABLE.encode(), "vuln.hex").json()["id"]
    for _ in range(3):
        alice.post("/api/scans", json={"file_id": fid})
    first = alice.get("/api/files/%d" % fid).json()["scans"][-1]["id"]
    rr = alice.post(f"/api/scans/{first}/rerun")
    assert rr.status_code == 202 and rr.json()["id"] != first
    page = alice.get("/api/scans", params={"page_size": 2, "page": 2}).json()
    assert page["total"] == 4 and len(page["items"]) == 2
    assert alice.get("/api/scans", params={"severity": "medium"}).json()["total"] == 4   # heuristic finding is medium
    assert alice.get("/api/scans", params={"severity": "high"}).json()["total"] == 0
    assert alice.get("/api/scans", params={"q": "vuln"}).json()["total"] == 4
    assert alice.get("/api/scans", params={"status": "FAILED"}).json()["total"] == 0
    assert alice.get("/api/scans", params={"date_from": "2999-01-01"}).json()["total"] == 0
    assert alice.get("/api/scans", params={"status": "bogus"}).status_code == 422
    d = alice.get("/api/dashboard").json()
    assert d["totals"]["total"] == 4 and d["totals"]["completed"] == 4 and d["reentrancy_findings"] == 4
    assert d["files_analyzed"] == 1 and d["changes"][0]["delta"] == 0 and len(d["trend"]) == 30


def test_compare_vulnerable_vs_fixed(alice, fake_tools):
    base = run_scan(alice, VULNERABLE)["id"]
    head = run_scan(alice, SAFE)["id"]
    c = alice.get("/api/scans/compare", params={"base": base, "head": head}).json()
    assert len(c["resolved"]) == 1 and c["introduced"] == [] and c["verdict_changed"] is True
    assert c["same_target"] is False and "program counters shift" in c["note"]


def test_export_json_and_markdown_contain_only_analyzer_output(alice, fake_tools):
    sid = run_scan(alice, VULNERABLE)["id"]
    j = alice.get(f"/api/scans/{sid}/export").json()
    assert j["analysis"]["findings"] and j["scan"]["id"] == sid
    md = alice.get(f"/api/scans/{sid}/export", params={"format": "md"})
    assert "attachment" in md.headers["content-disposition"] and "heuristic" in md.text and "proof of exploitability or of safety" in md.text


def test_report_integrity_is_verified(alice, fake_tools):
    sid = run_scan(alice, SAFE)["id"]
    reports = Path(get_settings().storage_dir) / "reports"
    target = next(p for p in reports.rglob("*") if p.is_file() and p.suffix == "")
    target.write_bytes(b"{}")                                              # tamper
    assert alice.get(f"/api/scans/{sid}/result").status_code == 500


def test_delete_scan_and_user_data(alice, fake_tools):
    sid = run_scan(alice, SAFE)["id"]
    assert alice.delete(f"/api/scans/{sid}").status_code == 200
    run_scan(alice, VULNERABLE)
    r = alice.delete("/api/profile/data").json()["deleted"]
    assert r["scans"] == 1 and r["files"] == 2
    assert alice.get("/api/files").json()["total"] == 0 and alice.get("/api/scans").json()["total"] == 0
    storage = Path(get_settings().storage_dir)
    assert not [p for p in storage.rglob("*") if p.is_file() and p.parent.parent.name in ("uploads", "reports")]


def test_audit_log_has_no_secrets(alice, fake_tools):
    run_scan(alice, SAFE)
    with session_factory()() as db:
        rows = db.scalars(select(AuditLog)).all()
    assert {"auth.register", "scan.create", "scan.finish"} <= {r.action for r in rows}
    blob = " ".join(f"{r.action}{r.resource_type}{r.resource_id}" for r in rows)
    assert SAFE not in blob and "Passw0rd" not in blob and all(r.request_id or r.action == "scan.finish" for r in rows[:2])
