import { useEffect, useState } from "react";
import { adminOverview, adminSetActive, adminUsers } from "../services/api.js";
import { Bars, ErrorBox, Stat } from "../components/Bits.jsx";
import { fmtDate, fmtMs } from "../fmt.js";

export default function AdminPage() {
  const [o, setO] = useState(null);
  const [users, setUsers] = useState([]);
  const [err, setErr] = useState(null);
  const load = () => {
    adminOverview().then(setO).catch((e) => setErr(e.message));
    adminUsers().then((r) => setUsers(r.items)).catch((e) => setErr(e.message));
  };
  useEffect(load, []);
  if (!o) return <main className="page"><ErrorBox error={err} /></main>;
  const pct = (x) => (x == null ? "—" : `${Math.round(x * 100)}%`);
  const toggle = async (u) => { setErr(null); try { await adminSetActive(u.id, !u.is_active); load(); } catch (e) { setErr(e.message); } };
  return (
    <main className="page">
      <div className="page-head"><h1>Administration</h1></div>
      <p className="muted small">Aggregate statistics only. Administrators cannot open other users' files, scans or reports.</p>
      <ErrorBox error={err} />
      <section className="card"><dl className="stats">
        <Stat label="Registered users" value={o.users.total} /><Stat label="Active accounts" value={o.users.active} />
        <Stat label="Total scans" value={o.scans.total} /><Stat label="Success rate" value={pct(o.scans.success_rate)} />
        <Stat label="Failed scans" value={o.scans.failed} cls={o.scans.failed ? "red" : ""} />
        <Stat label="Avg processing" value={fmtMs(o.scans.avg_duration_ms)} /><Stat label="p95 processing" value={fmtMs(o.scans.p95_duration_ms)} />
      </dl></section>
      <div className="grid-3">
        <section className="card"><h2>Scan volume (30 days)</h2><Bars data={o.scans.trend} label="Scans per day" /></section>
        <section className="card"><h2>Common vulnerability categories</h2>
          {o.top_categories.length === 0 ? <p className="empty">No findings yet.</p> : <ul className="plain-list">{o.top_categories.map((c) => <li key={c.category}>{c.category} <b>{c.count}</b></li>)}</ul>}</section>
        <section className="card"><h2>Service health</h2>
          <ul className="plain-list">{Object.entries(o.health).map(([k, v]) => <li key={k}><span className={"dot " + (v === true || (typeof v === "string" && v !== "not configured") ? "g" : "r")} aria-hidden="true" /> {k}: {String(v)}</li>)}</ul></section>
      </div>
      <div className="grid-2">
        <section className="card"><h2>AI usage</h2>
          <dl className="stats"><Stat label="Calls" value={o.ai.calls} /><Stat label="Failed" value={o.ai.failed} /><Stat label="Prompt tokens" value={o.ai.prompt_tokens} /><Stat label="Completion tokens" value={o.ai.completion_tokens} />
            <Stat label="Estimated cost" value={o.ai.estimated_cost_usd == null ? "n/a" : `$${o.ai.estimated_cost_usd}`} /></dl>
          <p className="muted small">{o.ai.cost_note}</p></section>
        <section className="card"><h2>Recent failed jobs</h2>
          {o.failed_jobs.length === 0 ? <p className="empty">None.</p> : <ul className="plain-list">{o.failed_jobs.map((j) => <li key={j.scan_id}>Scan #{j.scan_id} (user {j.owner_user_id}) · {fmtDate(j.at)} · {j.error}</li>)}</ul>}</section>
      </div>
      <section className="card"><h2>Users</h2>
        <div className="table-wrap"><table className="table">
          <thead><tr><th>ID</th><th>Name</th><th>Email</th><th>Role</th><th>Scans</th><th>Last sign-in</th><th>Status</th><th></th></tr></thead>
          <tbody>{users.map((u) => (
            <tr key={u.id}><td>{u.id}</td><td>{u.name}</td><td>{u.email}</td><td>{u.role}</td><td>{u.scan_count}</td><td>{fmtDate(u.last_login_at)}</td>
              <td>{u.is_active ? "active" : <span className="red">disabled</span>}</td>
              <td><button className="btn sm" onClick={() => toggle(u)}>{u.is_active ? "Deactivate" : "Reactivate"}</button></td></tr>))}</tbody>
        </table></div></section>
    </main>
  );
}
