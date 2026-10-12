import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import * as api from "../services/api.js";
import { ErrorBox, Pager, Status } from "../components/Bits.jsx";
import { fmtDate, fmtMs, VERDICT_LABEL } from "../fmt.js";

const EMPTY = { q: "", status: "", severity: "", project_id: "", date_from: "", date_to: "" };

function Compare({ cmp }) {
  const List = ({ title, items, cls }) => (
    <div><h3 className={cls}>{title} ({items.length})</h3>
      {items.length === 0 ? <p className="muted small">None</p> : (
        <ul className="plain-list">{items.map((v, i) => (
          <li key={i}>{v.title} <span className={"badge sev-" + v.severity}>{v.severity}</span>{" "}
            <span className="muted small">pc {v.program_counter ?? "—"} · {v.verification_status.replace("_", " ")}</span></li>))}</ul>)}
    </div>
  );
  return (
    <section className="card" aria-label="Scan comparison">
      <h2>Comparison: scan #{cmp.base.id} → scan #{cmp.head.id}</h2>
      <p className="muted small">Verdict: {VERDICT_LABEL[cmp.base.verdict]} → {VERDICT_LABEL[cmp.head.verdict]} · {cmp.same_target ? "same bytecode" : "different bytecode"}</p>
      <div className="grid-3"><List title="Resolved" items={cmp.resolved} cls="green" /><List title="Introduced" items={cmp.introduced} cls="red" /><List title="Unchanged" items={cmp.unchanged} cls="muted" /></div>
      <p className="muted small">{cmp.note}</p>
    </section>
  );
}

export default function ScansPage() {
  const nav = useNavigate();
  const [f, setF] = useState(EMPTY);
  const [page, setPage] = useState(1);
  const [data, setData] = useState({ items: [], total: 0, page: 1, page_size: 15 });
  const [projects, setProjects] = useState([]);
  const [sel, setSel] = useState([]);
  const [cmp, setCmp] = useState(null);
  const [err, setErr] = useState(null);

  const load = useCallback(() => {
    api.listScans({ ...f, page, page_size: 15 }).then(setData).catch((e) => setErr(e.message));
  }, [f, page]);
  useEffect(load, [load]);
  useEffect(() => { api.listProjects().then((r) => setProjects(r.items)).catch(() => {}); }, []);
  useEffect(() => {
    // keep the list fresh while anything is queued or running
    if (!data.items.some((s) => s.status === "QUEUED" || s.status === "RUNNING")) return;
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [data, load]);

  const set = (k) => (e) => { setPage(1); setF({ ...f, [k]: e.target.value }); };
  const act = (fn) => async () => { setErr(null); try { await fn(); load(); } catch (e) { setErr(e.message); } };
  const toggle = (id) => setSel((s) => s.includes(id) ? s.filter((x) => x !== id) : [...s.slice(-1), id]);   // at most two
  const doCompare = async () => {
    setErr(null);
    const [a, b] = [...sel].sort((x, y) => x - y);     // older scan = base
    try { setCmp(await api.compareScans(a, b)); } catch (e) { setErr(e.message); }
  };

  return (
    <main className="page">
      <div className="page-head"><h1>Scan history</h1>
        <button className="btn primary" disabled={sel.length !== 2} onClick={doCompare}>Compare selected ({sel.length}/2)</button></div>
      <ErrorBox error={err} />
      <section className="card">
        <div className="filters">
          <input className="text-in" placeholder="Search file name or hash" value={f.q} onChange={set("q")} />
          <select value={f.status} onChange={set("status")} aria-label="Status"><option value="">Any status</option>
            {["QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"].map((s) => <option key={s}>{s}</option>)}</select>
          <select value={f.severity} onChange={set("severity")} aria-label="Severity"><option value="">Any severity</option>
            {["high", "medium", "low", "informational"].map((s) => <option key={s}>{s}</option>)}</select>
          <select value={f.project_id} onChange={set("project_id")} aria-label="Project"><option value="">Any project</option>
            {projects.map((p) => <option key={p.id} value={p.id}>{p.project_name}</option>)}</select>
          <label className="small muted">From <input type="date" value={f.date_from} onChange={set("date_from")} /></label>
          <label className="small muted">To <input type="date" value={f.date_to} onChange={set("date_to")} /></label>
          <button className="btn sm ghost" onClick={() => { setF(EMPTY); setPage(1); }}>Reset</button>
        </div>
        {data.items.length === 0 ? <p className="empty">No scans match.</p> : (
          <div className="table-wrap"><table className="table">
            <thead><tr><th aria-label="Select"></th><th>#</th><th>Target</th><th>Status</th><th>Verdict</th><th>H / M / L / I</th><th>Duration</th><th>Started</th><th>Actions</th></tr></thead>
            <tbody>{data.items.map((s) => {
              const c = s.severity_counts;
              return (
                <tr key={s.id}>
                  <td><input type="checkbox" checked={sel.includes(s.id)} disabled={s.status !== "COMPLETED"} onChange={() => toggle(s.id)} aria-label={`Select scan ${s.id}`} /></td>
                  <td><Link to={`/scans/${s.id}`}>{s.id}</Link></td>
                  <td>{s.file_name || "—"}<div className="muted small mono">{s.target.slice(0, 10)}…</div></td>
                  <td><Status s={s.status} />{s.error_summary && <div className="muted small" title={s.error_summary}>{s.error_summary.slice(0, 50)}</div>}</td>
                  <td>{s.verdict ? VERDICT_LABEL[s.verdict] : "—"}</td>
                  <td>{c ? `${c.high} / ${c.medium} / ${c.low} / ${c.informational}` : "—"}{c?.reentrancy ? <span className="muted small"> · {c.reentrancy} re-entrancy</span> : null}</td>
                  <td>{fmtMs(s.duration_ms)}</td><td>{fmtDate(s.created_at)}</td>
                  <td className="actions">
                    <Link className="btn sm" to={`/scans/${s.id}`}>Open</Link>
                    {(s.status === "QUEUED" || s.status === "RUNNING") && <button className="btn sm" onClick={act(() => api.cancelScan(s.id))}>Cancel</button>}
                    {s.file_id && s.status !== "QUEUED" && s.status !== "RUNNING" && <button className="btn sm" onClick={async () => { try { const n = await api.rerunScan(s.id); nav(`/scans/${n.id}`); } catch (e) { setErr(e.message); } }}>Re-run</button>}
                    {s.status === "COMPLETED" && <><a className="btn sm" href={api.exportUrl(s.id, "json")}>JSON</a><a className="btn sm" href={api.exportUrl(s.id, "md")}>MD</a></>}
                    {s.status !== "QUEUED" && s.status !== "RUNNING" && <button className="btn sm ghost red" onClick={act(async () => { if (window.confirm(`Delete scan #${s.id}?`)) await api.deleteScan(s.id); })}>Delete</button>}
                  </td>
                </tr>
              );
            })}</tbody>
          </table></div>
        )}
        <Pager page={data.page} pageSize={data.page_size} total={data.total} onPage={setPage} />
      </section>
      {cmp && <Compare cmp={cmp} />}
    </main>
  );
}
