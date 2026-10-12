import { useEffect, useState } from "react";
import { myUsage } from "../services/api.js";
import { Bars, ErrorBox, Stat } from "../components/Bits.jsx";
import { fmtBytes, fmtMs } from "../fmt.js";

export default function UsagePage() {
  const [u, setU] = useState(null);
  const [err, setErr] = useState(null);
  useEffect(() => { myUsage().then(setU).catch((e) => setErr(e.message)); }, []);
  if (err) return <main className="page"><ErrorBox error={err} /></main>;
  if (!u) return <main className="page"><p className="empty">Loading…</p></main>;
  return (
    <main className="page">
      <div className="page-head"><h1>My usage</h1></div>
      <section className="card"><dl className="stats">
        <Stat label="Scans performed" value={u.scans_total} />
        <Stat label="Successful" value={u.scans_successful} cls="green" />
        <Stat label="Failed" value={u.scans_failed} cls={u.scans_failed ? "red" : ""} />
        <Stat label="Average duration" value={fmtMs(u.avg_duration_ms)} />
        <Stat label="Files uploaded" value={u.files_uploaded} />
        <Stat label="Bytecode stored" value={fmtBytes(u.bytecode_bytes_stored)} />
        <Stat label="Bytecode scanned" value={fmtBytes(u.bytecode_bytes_scanned)} />
        <Stat label="AI analyses" value={u.ai_analyses} />
        <Stat label="AI tokens" value={u.ai_tokens} />
      </dl><p className="muted small">{u.ai_tokens_note}</p></section>
      <div className="grid-2">
        <section className="card"><h2>Scans per day (30 days)</h2><Bars data={u.scan_trend} label="Scans per day" /></section>
        <section className="card"><h2>AI analyses per day (30 days)</h2><Bars data={u.ai_trend} label="AI analyses per day" /></section>
      </div>
    </main>
  );
}
