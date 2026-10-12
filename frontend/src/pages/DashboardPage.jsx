import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getDashboard } from "../services/api.js";
import { Bars, ErrorBox, Stat, Status } from "../components/Bits.jsx";
import { fmtDate, fmtMs, VERDICT_LABEL } from "../fmt.js";

export default function DashboardPage() {
  const [d, setD] = useState(null);
  const [err, setErr] = useState(null);
  useEffect(() => {
    getDashboard().then(setD).catch((e) => setErr(e.message));
    // Refresh while scans are in flight.
    const t = setInterval(() => getDashboard().then(setD).catch(() => {}), 5000);
    return () => clearInterval(t);
  }, []);
  if (err) return <main className="page"><ErrorBox error={err} /></main>;
  if (!d) return <main className="page"><p className="empty">Loading…</p></main>;
  const t = d.totals, sev = d.vulnerabilities_by_severity;
  const maxSev = Math.max(1, ...Object.values(sev));
  return (
    <main className="page">
      <div className="page-head"><h1>Dashboard</h1><Link className="btn primary" to="/analyze">New analysis</Link></div>
      <div className="grid-4">
        <section className="card"><dl><Stat label="Total scans" value={t.total} /></dl></section>
        <section className="card"><dl><Stat label="Completed" value={t.completed} cls="green" /></dl></section>
        <section className="card"><dl><Stat label="Failed" value={t.failed} cls={t.failed ? "red" : ""} /></dl></section>
        <section className="card"><dl><Stat label="Queued / running" value={t.running} cls="blue" /></dl></section>
      </div>
      <div className="grid-3">
        <section className="card">
          <h2>Vulnerabilities by severity</h2>
          {[["high", "red"], ["medium", "orange"], ["low", "yellow"], ["informational", "blue"]].map(([k, c]) => (
            <div key={k} className="hbar"><span>{k}</span><div><i className={"fill " + c} style={{ width: `${(sev[k] / maxSev) * 100}%` }} /></div><b>{sev[k]}</b></div>
          ))}
          <p className="muted small">Re-entrancy-related findings: <b>{d.reentrancy_findings}</b></p>
        </section>
        <section className="card">
          <h2>Scans, last 30 days</h2>
          <Bars data={d.trend} field="scans" label="Scans per day for the last 30 days" />
          <p className="muted small">Distinct contracts analyzed: <b>{d.files_analyzed}</b> · Average duration: <b>{fmtMs(d.avg_duration_ms)}</b></p>
        </section>
        <section className="card">
          <h2>Changes between runs</h2>
          {d.changes.length === 0 && <p className="empty">Scan the same bytecode twice to see how results change.</p>}
          <ul className="plain-list">
            {d.changes.map((c) => (
              <li key={c.target}>
                <Link to={`/scans/${c.latest_scan_id}`}>{c.file_name || c.target.slice(0, 10)}</Link>{" "}
                <span className={c.delta > 0 ? "red" : c.delta < 0 ? "green" : "muted"}>{c.previous_total} → {c.latest_total} findings</span>
              </li>
            ))}
          </ul>
        </section>
      </div>
      <section className="card">
        <h2>Recent scans</h2>
        {d.recent.length === 0 ? <p className="empty">No scans yet. <Link to="/analyze">Run your first analysis.</Link></p> : (
          <div className="table-wrap"><table className="table">
            <thead><tr><th>#</th><th>Target</th><th>Status</th><th>Verdict</th><th>Findings</th><th>Duration</th><th>Started</th></tr></thead>
            <tbody>{d.recent.map((s) => (
              <tr key={s.id}><td><Link to={`/scans/${s.id}`}>{s.id}</Link></td><td>{s.file_name || s.target.slice(0, 10)}</td><td><Status s={s.status} /></td>
                <td>{s.verdict ? VERDICT_LABEL[s.verdict] : "—"}</td><td>{s.severity_counts?.total ?? 0}</td><td>{fmtMs(s.duration_ms)}</td><td>{fmtDate(s.created_at)}</td></tr>
            ))}</tbody>
          </table></div>
        )}
      </section>
    </main>
  );
}
