import Icon from "./Icon.jsx";

export default function Sidebar({ active, onNav, samples, onSample, health, busy }) {
  const item = (id, icon, label) => (
    <li key={id}>
      <button className={"nav" + (active === id ? " on" : "")} onClick={() => onNav(id)}>
        <Icon name={icon} size={17} /> {label}
      </button>
    </li>
  );
  return (
    <aside className="sidebar" aria-label="Navigation">
      <p className="side-h">Report</p>
      <ul>
        {item("top", "grid", "Dashboard")}
        {item("findings", "bug", "Findings")}
        {item("code", "code", "Instructions")}
        {item("decompiled", "file", "Decompiled")}
      </ul>

      <p className="side-h">Samples</p>
      <ul>
        {samples.map((s) => (
          <li key={s.label}>
            <button className="nav" onClick={() => onSample(s.hex)} disabled={busy}>
              <Icon name="list" size={17} /> {s.label}
            </button>
          </li>
        ))}
      </ul>

      <div className="conn">
        <p className="side-h">Tools</p>
        {!health && <p className="muted">Checking…</p>}
        {health?.error && <p className="red">{health.error}</p>}
        {health?.tools && Object.entries(health.tools).map(([n, ok]) => {
          const detail = health.details?.[n];
          return (
            <div key={n} className="conn-item">
              <p className="conn-row">
                <span className={"dot " + (ok ? "g" : "r")} aria-hidden="true" />
                <span className="conn-name">{n}</span> <span className="muted">{ok ? "found" : "not found"}</span>
              </p>
              {detail && <p className="conn-detail muted small">{detail}</p>}
            </div>
          );
        })}
      </div>
    </aside>
  );
}
