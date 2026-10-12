import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../auth.jsx";
import * as api from "../services/api.js";
import { ErrorBox, Stat } from "../components/Bits.jsx";
import { fmtDate } from "../fmt.js";

export default function ProfilePage() {
  const { setName, logout } = useAuth();
  const nav = useNavigate();
  const [p, setP] = useState(null);
  const [name, setN] = useState("");
  const [pw, setPw] = useState({ current_password: "", new_password: "" });
  const [errs, setErrs] = useState({});
  const [err, setErr] = useState(null);
  const [note, setNote] = useState(null);
  const [delPw, setDelPw] = useState("");

  const load = () => api.getProfile().then((r) => { setP(r); setN(r.name); }).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, []);
  const run = async (fn, ok) => { setErr(null); setNote(null); setErrs({}); try { await fn(); if (ok) setNote(ok); } catch (e) { setErrs(e.fields || {}); setErr(e.fields ? null : e.message); } };
  const fe = (k) => errs[k]?.map((m) => <p key={m} className="field-err" role="alert">{m}</p>);
  if (!p) return <main className="page"><ErrorBox error={err} /></main>;

  return (
    <main className="page narrow">
      <div className="page-head"><h1>Profile</h1></div>
      <ErrorBox error={err} />{note && <p className="notice" role="status">{note}</p>}
      <section className="card">
        <h2>Account</h2>
        <dl className="stats">
          <Stat label="Email" value={p.email} /><Stat label="Role" value={p.role} />
          <Stat label="Member since" value={fmtDate(p.created_at)} /><Stat label="Last sign-in" value={fmtDate(p.last_login_at)} />
        </dl>
        <p className="muted small">Email verification is not enabled in this build.</p>
        <form className="stack" onSubmit={(e) => { e.preventDefault(); run(async () => { const r = await api.updateProfile(name); setName(r.name); await load(); }, "Name updated."); }}>
          <label className="field">Display name<input value={name} maxLength={100} onChange={(e) => setN(e.target.value)} />{fe("name")}</label>
          <button className="btn sm">Save name</button>
        </form>
      </section>
      <section className="card">
        <h2>Activity</h2>
        <dl className="stats"><Stat label="Scans" value={p.activity.scans} /><Stat label="Files" value={p.activity.files} />
          <Stat label="AI analyses" value={p.activity.ai_analyses} /><Stat label="Signed-in sessions" value={p.activity.active_sessions} /></dl>
      </section>
      <section className="card">
        <h2>Change password</h2>
        <form className="stack" onSubmit={(e) => { e.preventDefault(); run(async () => { await api.changePassword(pw); setPw({ current_password: "", new_password: "" }); await load(); }, "Password changed. Other devices were signed out."); }}>
          <label className="field">Current password<input type="password" autoComplete="current-password" value={pw.current_password} onChange={(e) => setPw({ ...pw, current_password: e.target.value })} />{fe("current_password")}</label>
          <label className="field">New password<input type="password" autoComplete="new-password" value={pw.new_password} onChange={(e) => setPw({ ...pw, new_password: e.target.value })} />{fe("new_password")}</label>
          <button className="btn sm primary" disabled={!pw.current_password || !pw.new_password}>Change password</button>
        </form>
      </section>
      <section className="card danger">
        <h2>Your data</h2>
        <p className="muted small">Delete all your files, scans, reports, projects and AI results. Your account and security audit log are kept.</p>
        <button className="btn sm" onClick={() => window.confirm("Delete all your files, scans and reports? This cannot be undone.") && run(async () => { await api.deleteMyData(); await load(); }, "Your data was deleted.")}>Delete my data</button>
        <h2 className="mt">Delete account</h2>
        <form className="stack" onSubmit={(e) => { e.preventDefault(); if (!window.confirm("Permanently delete your account and all data?")) return; run(async () => { await api.deleteAccount(delPw); await logout(); nav("/login"); }); }}>
          <label className="field">Confirm with your password<input type="password" autoComplete="current-password" value={delPw} onChange={(e) => setDelPw(e.target.value)} /></label>
          <button className="btn sm red-btn" disabled={!delPw}>Delete account</button>
        </form>
      </section>
    </main>
  );
}
