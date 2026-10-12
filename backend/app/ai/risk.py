"""Transparent, deterministic risk model built only from scan findings. No LLM involved.

This is a *relative prioritisation aid*. The weights below are judgement calls that have NOT been
validated against real incident data; do not read the number as a probability or a loss estimate.
Technical severity (what the analyzer says) is kept separate from business risk, which needs facts
this tool does not have (funds at stake, who can call what) and is therefore reported as not assessed.
"""
from __future__ import annotations

SEVERITY_BASE = {"high": 40, "medium": 25, "low": 10, "informational": 3}
EVIDENCE_FACTOR = {"corroborated": 1.0, "symbolically_feasible": 0.85, "heuristic": 0.5}
REENTRANCY_BONUS = 10
MODEL_VERSION = "risk-model-1 (unvalidated weights)"


def _category(score: float) -> str:
    return "high" if score >= 50 else "medium" if score >= 30 else "low" if score > 0 else "none"


def assess(context: dict) -> dict:
    findings = context["findings"]
    per = []
    for f in findings:
        base = SEVERITY_BASE[f["severity"]]
        factor = EVIDENCE_FACTOR[f["verification_status"]]
        bonus = REENTRANCY_BONUS if (f["reentrancy_related"] and "state" in f["title"].lower()) or f["source"] == "heuristic" else 0
        score = round((base + bonus) * factor, 1)
        up, down = [], []
        up.append(f"Analyzer severity is {f['severity']} (+{base}).")
        if bonus:
            up.append(f"State is written after an external call, the classic re-entrancy ordering (+{bonus}).")
        if f["verification_status"] == "corroborated":
            up.append("Two independent methods (symbolic execution and structural analysis) point at the same instruction.")
        elif f["verification_status"] == "symbolically_feasible":
            down.append("Reported by symbolic execution only; not corroborated by the structural check (x0.85).")
        else:
            down.append("Structural heuristic only: reachable is not the same as exploitable (x0.5).")
        if f["severity"] == "informational":
            down.append("Informational findings describe a pattern, not necessarily a flaw.")
        per.append({"ref": f["ref"], "title": f["title"], "technical_severity": f["severity"],
                    "verification_status": f["verification_status"], "relative_score": score,
                    "risk_category": _category(score), "increasing_factors": up, "reducing_factors": down})

    top = max((p["relative_score"] for p in per), default=0)
    extra = min(10, 2 * max(0, len(per) - 1))        # a few more findings nudge the total, capped
    overall_score = round(top + (extra if top else 0), 1)
    verdict = context["verdict"]
    if per:
        category = _category(overall_score)
    elif verdict == "analysis_incomplete":
        category = "inconclusive"
    else:
        category = "no_findings_detected"

    missing = ["Funds held or controlled by the contract (asset exposure) - not derivable from bytecode.",
               "Access-control and caller restrictions on the flagged functions.",
               "Whether mitigations (re-entrancy guards, pull payments) exist in the original source. Their absence "
               "in findings is not proof they are present."]
    uncertainty = []
    for t in context["tools"]:
        if t["status"] not in ("ok", "skipped"):
            uncertainty.append(f"{t['name']} did not complete ({t['status']}); results may be missing findings.")
        if t["status"] == "skipped":
            uncertainty.append(f"{t['name']} was skipped.")
    uncertainty += [w for w in context["warnings"][:5]]

    actions = []
    if any(p["risk_category"] == "high" for p in per):
        actions.append("Fix the highest-scoring finding first and re-scan; add a regression test that reproduces it.")
    if any(f["verification_status"] == "heuristic" for f in findings):
        actions.append("Review heuristic-only findings against source code to decide whether they are real.")
    if verdict == "analysis_incomplete":
        actions.append("Re-run with all tools available (a clean result needs Mythril to complete).")
    actions.append("Have a human auditor review the contract before deployment; automated analysis is not a safety guarantee.")

    return {
        "model": MODEL_VERSION, "overall_risk_category": category, "overall_relative_score": overall_score,
        "score_note": "A relative prioritisation index, not a probability and not validated against real incidents.",
        "technical_findings": len(per), "business_risk": "not_assessed",
        "business_risk_note": "Financial impact needs facts about funds at stake and usage; none are inferred here.",
        "per_finding": per, "missing_information": missing, "uncertainty": uncertainty, "next_actions": actions,
    }
