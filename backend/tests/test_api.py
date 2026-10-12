"""The analysis pipeline, exercised through the authenticated scan API (tools mocked)."""
import pytest

from app.adapters.base import AdapterResult
from tests.conftest import SAFE, VULNERABLE, mythril_json


def analyze(session, code, **kw):
    r = session.post("/api/scans", json={"bytecode": code, **kw})
    assert r.status_code == 202, r.text
    sid = r.json()["id"]
    scan = session.get(f"/api/scans/{sid}").json()
    result = session.get(f"/api/scans/{sid}/result")
    return scan, (result.json() if result.status_code == 200 else None)


def test_health_shape(alice):
    r = alice.get("/api/health")
    assert r.status_code == 200
    assert set(r.json()["tools"]) == {"heimdall", "mythril"}


def test_disassemble_requires_login_and_works(alice, make_session):
    assert make_session().post("/api/disassemble", json={"bytecode": "0x6001600055"}).status_code == 401
    r = alice.post("/api/disassemble", json={"bytecode": "0x6001600055"})
    assert r.status_code == 200 and r.json()["instructions"][2]["name"] == "SSTORE"


@pytest.mark.parametrize("code,err", [("", "empty"), ("0xnothex", "invalid_hex"), ("abc", "odd_length")])
def test_invalid_input_is_422_with_code(alice, code, err):
    r = alice.post("/api/scans", json={"bytecode": code})
    assert r.status_code == 422 and r.json()["detail"]["code"] == err


def test_clean_result_requires_mythril_to_complete(alice, fake_tools):
    scan, body = analyze(alice, SAFE)
    assert scan["status"] == "COMPLETED" and body["verdict"] == "no_issues_detected"
    assert body["decompiled_code"].startswith("function withdraw")


@pytest.mark.parametrize("status", ["not_installed", "timeout", "error"])
def test_mythril_failure_is_incomplete_not_clean(alice, fake_tools, status):
    fake_tools["mythril"] = AdapterResult(status, error="boom")
    scan, body = analyze(alice, SAFE)
    assert body["verdict"] == "analysis_incomplete" and body["status"] == "partial"
    assert scan["status"] == "COMPLETED" and "mythril" in scan["error_summary"]


def test_skipping_mythril_is_incomplete(alice, fake_tools):
    _, body = analyze(alice, SAFE, run_mythril=False)
    assert body["verdict"] == "analysis_incomplete"


def test_mythril_finding_is_linked_to_instructions_and_corroborated(alice, fake_tools):
    issue = {"title": "State access after external call", "swc-id": "107", "severity": "Medium", "address": 18,
             "function": "withdraw()", "description": {"head": "Write to persistent state following external call.", "tail": "Review."}}
    fake_tools["mythril"] = AdapterResult("ok", output=mythril_json([issue]))
    scan, body = analyze(alice, VULNERABLE)
    assert body["verdict"] == "issues_detected"
    by_source = {f["source"]: f for f in body["findings"]}
    m = by_source["mythril"]
    assert m["swc_id"] == "SWC-107" and m["reentrancy_related"] and m["severity"] == "medium"
    assert any(i["pc"] == 18 and i["name"] == "SSTORE" for i in m["evidence"]["instructions"])
    assert by_source["heuristic"]["id"] in m["corroborated_by"]
    # persisted rows carry the verification label
    vulns = scan["vulnerabilities"]
    assert {v["verification_status"] for v in vulns} == {"corroborated"}


def test_disagreement_is_surfaced(alice, fake_tools):
    _, body = analyze(alice, VULNERABLE)
    assert body["verdict"] == "issues_detected" and any("disagree" in w for w in body["warnings"])
    # heuristic-only finding is labelled as such
    assert body["findings"][0]["confidence"] == "heuristic"


def test_garbage_mythril_output_is_an_error(alice, fake_tools):
    fake_tools["mythril"] = AdapterResult("ok", output="not json")
    _, body = analyze(alice, SAFE)
    assert body["verdict"] == "analysis_incomplete"


def test_finding_pointing_outside_code_warns(alice, fake_tools):
    issue = {"title": "x", "swc-id": "110", "severity": "Low", "address": 9999}
    fake_tools["mythril"] = AdapterResult("ok", output=mythril_json([issue]))
    _, body = analyze(alice, SAFE)
    assert any("9999" in w for w in body["warnings"])


def test_call_only_mythril_finding_does_not_trigger_false_disagreement(alice, fake_tools):
    issue = {"title": "External Call To User-Supplied Address", "swc-id": "107", "severity": "Low", "address": 18,
             "function": "withdraw()", "description": "A call to a user-supplied address is executed."}
    fake_tools["mythril"] = AdapterResult("ok", output=mythril_json([issue]))
    _, body = analyze(alice, SAFE)
    assert any(f["title"].startswith("External Call") for f in body["findings"])
    assert not any("did not reproduce" in w for w in body["warnings"])
