import { useEffect, useState } from "react";
import * as api from "../services/api.js";
import { listScans } from "../services/api.js";

// AI output is rendered as plain text (never as HTML), so model output cannot inject markup.
const Text = ({ children }) => <pre className="ai-text">{children}</pre>;

function Meta({ r }) {
  return (
    <div className="ai-meta">
      <span className={"badge " + (r.generated_by_llm ? "sev-informational" : "")}>{r.generated_by_llm ? `AI · ${r.model || r.provider}` : "Rule-based · no LLM"}</span>
      {r.disclaimer && <span className="muted small">{r.disclaimer}</span>}
      {r.grounding_warnings?.map((w) => <p key={w} className="field-err" role="alert">{w}</p>)}
    </div>
  );
}

function RiskView({ r }) {
  return (
    <div className="ai-body">
      <p><b>Overall technical risk:</b> <span className={"badge sev-" + ({ high: "high", medium: "medium", low: "low" }[r.overall_risk_category] || "informational")}>{r.overall_risk_category.replace(/_/g, " ")}</span>{" "}
        <span className="muted small">relative index {r.overall_relative_score}</span></p>
      <p className="muted small">{r.score_note} Business risk: <b>{r.business_risk.replace("_", " ")}</b>. {r.business_risk_note}</p>
      {r.per_finding.map((f) => (
        <div key={f.ref} className="ai-card"><b>{f.ref} · {f.title}</b> <span className="muted small">({f.technical_severity}, {f.verification_status.replace(/_/g, " ")}, {f.relative_score})</span>
          <div className="two-col"><div><h4>Raises risk</h4><ul className="plain-list">{f.increasing_factors.map((x) => <li key={x}>{x}</li>)}</ul></div>
            <div><h4>Lowers confidence/risk</h4><ul className="plain-list">{f.reducing_factors.map((x) => <li key={x}>{x}</li>)}</ul></div></div></div>
      ))}
      {r.uncertainty.length > 0 && <><h4>Uncertainty</h4><ul className="plain-list">{r.uncertainty.map((x) => <li key={x}>{x}</li>)}</ul></>}
      <h4>Missing information</h4><ul className="plain-list">{r.missing_information.map((x) => <li key={x}>{x}</li>)}</ul>
      <h4>Recommended next actions</h4><ul className="plain-list">{r.next_actions.map((x) => <li key={x}>{x}</li>)}</ul>
    </div>
  );
}

const KINDS = [["executive", "Executive summary"], ["technical", "Technical report"], ["beginner", "Beginner-friendly"], ["per_finding", "Vulnerability by vulnerability"],
  ["remediation_plan", "Remediation plan"], ["comparison", "Vulnerable vs fixed comparison"]];

export default function AiPanel({ scanId }) {
  const [tab, setTab] = useState("risk");
  const [status, setStatus] = useState(null);
  const [out, setOut] = useState({});
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [kind, setKind] = useState("executive");
  const [others, setOthers] = useState([]);
  const [base, setBase] = useState("");
  const [msgs, setMsgs] = useState([]);
  const [draft, setDraft] = useState("");

  useEffect(() => { api.aiStatus().then(setStatus).catch(() => {}); setOut({}); setMsgs([]); setErr(null); }, [scanId]);
  useEffect(() => {
    if (kind === "comparison") listScans({ status: "COMPLETED", page_size: 50 }).then((r) => setOthers(r.items.filter((s) => s.id !== scanId))).catch(() => {});
  }, [kind, scanId]);

  const run = async (key, fn) => {
    setBusy(true); setErr(null);
    try { setOut((o) => ({ ...o, [key]: null })); const r = await fn(); setOut((o) => ({ ...o, [key]: r })); }
    catch (e) { setErr(e.message); } finally { setBusy(false); }
  };
  const send = async (e) => {
    e.preventDefault();
    const next = [...msgs, { role: "user", content: draft }];
    setMsgs(next); setDraft(""); setBusy(true); setErr(null);
    try { const r = await api.aiChat(scanId, next); setMsgs([...next, { role: "assistant", content: r.reply, warnings: r.grounding_warnings }]); }
    catch (e2) { setErr(e2.message); } finally { setBusy(false); }
  };
  const download = (r) => {
    const url = URL.createObjectURL(new Blob([r.markdown], { type: "text/markdown" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: `retrace-${kind}-scan-${scanId}.md` });
    a.click(); URL.revokeObjectURL(url);
  };

  const tabs = [["risk", "Risk assessment"], ["explain", "Explain findings"], ["fix", "Remediation"], ["report", "Reports"], ["chat", "Ask the assistant"]];
  const r = out[tab];
  return (
    <section className="card ai-panel" aria-labelledby="ai-h">
      <h2 id="ai-h">AI-assisted analysis</h2>
      <p className="muted small">Findings come from the analyzers, never from an AI. This panel explains them. {status && !status.llm_configured && status.note}</p>
      <div className="tabs ai-tabs">{tabs.map(([k, l]) => <button key={k} className={tab === k ? "on" : ""} onClick={() => setTab(k)}>{l}</button>)}</div>
      {err && <p className="field-err" role="alert">{err}</p>}

      {tab === "risk" && <>
        <button className="btn sm primary" disabled={busy} onClick={() => run("risk", () => api.aiRisk(scanId))}>{busy ? "Working…" : "Compute risk assessment"}</button>
        {r && <RiskView r={r} />}</>}
      {tab === "explain" && <>
        <button className="btn sm primary" disabled={busy} onClick={() => run("explain", () => api.aiExplain(scanId))}>{busy ? "Working…" : "Explain the findings"}</button>
        {r && <><Meta r={r} /><Text>{r.text}</Text></>}</>}
      {tab === "fix" && <>
        <button className="btn sm primary" disabled={busy} onClick={() => run("fix", () => api.aiRemediation(scanId))}>{busy ? "Working…" : "Suggest remediation"}</button>
        {r && <><Meta r={r} /><Text>{r.text}</Text></>}</>}
      {tab === "report" && <>
        <div className="opts">
          <select value={kind} onChange={(e) => setKind(e.target.value)} aria-label="Report type">{KINDS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
          {kind === "comparison" && <select value={base} onChange={(e) => setBase(e.target.value)} aria-label="Earlier scan to compare against">
            <option value="">Compare against scan…</option>{others.map((s) => <option key={s.id} value={s.id}>#{s.id} {s.file_name || s.target.slice(0, 8)}</option>)}</select>}
          <button className="btn sm primary" disabled={busy || (kind === "comparison" && !base)}
            onClick={() => run("report", () => api.aiReport(scanId, { kind, compare_with_scan_id: base ? Number(base) : null }))}>{busy ? "Working…" : "Generate"}</button>
        </div>
        {r && <><Meta r={{ ...r, disclaimer: null }} />
          <h4>Observed evidence (from the analyzers)</h4><Text>{r.observed_evidence}</Text>
          <h4>Interpretation ({r.generated_by_llm ? "AI-generated" : "rule-based"})</h4><Text>{r.interpretation}</Text>
          <button className="btn sm" onClick={() => download(r)}>Download .md</button></>}</>}
      {tab === "chat" && (status && !status.chat_available
        ? <p className="empty">The chat assistant needs an LLM provider. Ask your administrator to set RETRACE_AI_PROVIDER and an API key.</p>
        : <div className="chat">
            <p className="muted small">Try: “Why was this contract flagged?”, “Which instructions support the finding?”, “What should I test before deployment?” The assistant sees only this scan's findings.</p>
            <ul className="chat-log">{msgs.map((m, i) => <li key={i} className={m.role}><b>{m.role === "user" ? "You" : "Assistant"}</b><Text>{m.content}</Text>{m.warnings?.map((w) => <p key={w} className="field-err">{w}</p>)}</li>)}</ul>
            <form className="inline-form" onSubmit={send}>
              <input className="text-in grow" value={draft} maxLength={2000} placeholder="Ask about this scan…" onChange={(e) => setDraft(e.target.value)} />
              <button className="btn sm primary" disabled={busy || !draft.trim()}>{busy ? "…" : "Send"}</button></form>
          </div>)}
    </section>
  );
}
