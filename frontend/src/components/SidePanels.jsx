import Icon from "./Icon.jsx";

export function Recommendations({ result }) {
  const recs = [...new Set((result?.findings ?? []).map((f) => f.recommendation))];
  return (
    <section className="card" aria-labelledby="rec-h">
      <h2 id="rec-h">Recommendations</h2>
      {!result && <p className="empty">Recommendations come from the findings.</p>}
      {result && recs.length === 0 && <p className="empty">No findings, so no recommendations.</p>}
      <ul className="checklist">
        {recs.map((r, i) => <li key={i}><Icon name="check" size={17} className="green" /> <span>{r}</span></li>)}
      </ul>
    </section>
  );
}

const STATE = { ok: ["check", "green"], skipped: ["dash", "muted"], timeout: ["x", "orange"], error: ["x", "red"], not_installed: ["x", "red"] };

export function Timeline({ result, busy }) {
  const steps = [];
  if (result) {
    steps.push(["Input validated", "check", "green", null]);
    steps.push([`${result.instructions.length.toLocaleString()} instructions decoded`, "check", "green", null]);
    result.tools.forEach((t) => {
      const [icon, cls] = STATE[t.status] ?? ["circle", "muted"];
      const name = t.name === "heimdall" ? "Heimdall decompile" : "Mythril analysis";
      steps.push([`${name}: ${t.status.replace("_", " ")}`, icon, cls, t.status === "ok" || t.status === "timeout" ? `${t.duration_s}s` : null]);
    });
    steps.push(["Structural check", "check", "green", null]);
    steps.push(["Report built", "check", "green", null]);
  }
  return (
    <section className="card" aria-labelledby="tl-h">
      <h2 id="tl-h">Run Timeline</h2>
      {busy && <p className="empty busy">Running. Symbolic execution can take a while…</p>}
      {!result && !busy && <p className="empty">No run yet.</p>}
      <ul className="timeline">
        {steps.map(([label, icon, cls, time], i) => (
          <li key={i}><Icon name={icon} size={17} className={cls} /> <span>{label}</span><span className="muted small t">{time}</span></li>
        ))}
      </ul>
    </section>
  );
}

export function Notes({ warnings }) {
  if (!warnings?.length) return null;
  return (
    <section className="card notes" aria-labelledby="nt-h">
      <h2 id="nt-h">Notes and limitations ({warnings.length})</h2>
      <ul className="plain">{warnings.map((w, i) => <li key={i}>{w}</li>)}</ul>
    </section>
  );
}
