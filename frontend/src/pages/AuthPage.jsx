import { useState } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth.jsx";
import Icon from "../components/Icon.jsx";

function checks(pw) {
  return [
    ["10+ characters", pw.length >= 10], ["lowercase letter", /[a-z]/.test(pw)],
    ["uppercase letter", /[A-Z]/.test(pw)], ["a digit", /\d/.test(pw)],
  ];
}

export default function AuthPage({ mode }) {
  const isReg = mode === "register";
  const { user, login, register } = useAuth();
  const nav = useNavigate();
  const loc = useLocation();
  const [f, setF] = useState({ name: "", email: "", password: "" });
  const [errors, setErrors] = useState({});
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(false);
  if (user) return <Navigate to={loc.state?.from || "/dashboard"} replace />;

  async function submit(e) {
    e.preventDefault();
    setBusy(true); setErrors({}); setMsg(null);
    try {
      if (isReg) await register(f.name, f.email, f.password); else await login(f.email, f.password);
      nav(loc.state?.from || "/dashboard", { replace: true });
    } catch (err) {
      setErrors(err.fields || {});
      setMsg(err.fields ? null : err.message);
    } finally { setBusy(false); }
  }
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  const fieldErr = (k) => errors[k]?.map((m) => <p key={m} className="field-err" role="alert">{m}</p>);

  return (
    <main className="auth-wrap">
      <form className="card auth-card" onSubmit={submit} noValidate>
        <div className="brand"><Icon name="shield" size={36} className="brand-icon" /><div><h1>ReTrace</h1><p>EVM bytecode security platform</p></div></div>
        <h2>{isReg ? "Create your account" : "Sign in"}</h2>
        {msg && <div className="error-box" role="alert"><p>{msg}</p></div>}
        {isReg && <label className="field">Name<input value={f.name} onChange={set("name")} autoComplete="name" required maxLength={100} />{fieldErr("name")}</label>}
        <label className="field">Email<input type="email" value={f.email} onChange={set("email")} autoComplete="email" required />{fieldErr("email")}</label>
        <label className="field">Password
          <input type="password" value={f.password} onChange={set("password")} autoComplete={isReg ? "new-password" : "current-password"} required />
          {fieldErr("password")}
        </label>
        {isReg && (
          <ul className="pw-rules" aria-label="Password requirements">
            {checks(f.password).map(([label, ok]) => <li key={label} className={ok ? "ok" : ""}>{ok ? "✓" : "○"} {label}</li>)}
          </ul>
        )}
        <button className="btn primary" disabled={busy}>{busy ? "Please wait…" : isReg ? "Create account" : "Sign in"}</button>
        <p className="muted small center">
          {isReg ? <>Already registered? <Link to="/login">Sign in</Link></> : <>New here? <Link to="/register">Create an account</Link></>}
        </p>
      </form>
    </main>
  );
}
