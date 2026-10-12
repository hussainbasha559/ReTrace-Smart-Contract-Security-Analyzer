import Icon from "./Icon.jsx";
import { sev } from "./TopBar.jsx";

const SEV_ROWS = [
  ["high", "High Risk", "red"],
  ["medium", "Medium Risk", "orange"],
  ["low", "Low Risk", "yellow"],
  ["informational", "Informational", "blue"],
];
const TOOL_LABEL = { ok: "Completed", not_installed: "Not installed", timeout: "Timed out", error: "Failed", skipped: "Skipped" };
const TOOL_CLS = { ok: "green", not_installed: "red", timeout: "orange", error: "red", skipped: "muted" };

export function RiskSummary({ result }) {
  const c = sev(result);
  return (
    <section className="card" aria-labelledby="risk-h">
      <h2 id="risk-h">Risk Summary</h2>
      <dl className="rows">
        {SEV_ROWS.map(([k, label, color]) => (
          <div key={k}><dt><span className={"dot " + color} aria-hidden="true" />{label}</dt>
            <dd className={result ? color : "muted"}>{result ? c[k] : "—"}</dd></div>
        ))}
      </dl>
    </section>
  );
}

export function ToolChecks({ result }) {
  const heur = result?.findings.filter((f) => f.source === "heuristic").length;
  return (
    <section className="card" aria-labelledby="chk-h">
      <h2 id="chk-h">Analysis Checks</h2>
      <dl className="rows">
        {(result?.tools ?? [{ name: "heimdall" }, { name: "mythril" }]).map((t) => (
          <div key={t.name}><dt>{t.name === "heimdall" ? "Heimdall" : "Mythril"}</dt>
            <dd className={t.status ? TOOL_CLS[t.status] : "muted"}>{t.status ? TOOL_LABEL[t.status] : "—"}</dd></div>
        ))}
        <div><dt>Structural check</dt><dd className={result ? "green" : "muted"}>{result ? "Completed" : "—"}</dd></div>
        <div><dt>Heuristic hits</dt><dd className={heur ? "orange" : result ? "" : "muted"}>{result ? heur : "—"}</dd></div>
      </dl>
    </section>
  );
}

export function Overview({ result }) {
  const n = (name) => result?.instructions.filter((i) => i.name === name).length;
  const rows = [
    ["Size", result ? `${result.input_bytes.toLocaleString()} bytes` : "—"],
    ["Instructions", result ? result.instructions.length.toLocaleString() : "—"],
    ["Jump targets", result ? n("JUMPDEST") : "—"],
    ["External calls", result ? n("CALL") + n("CALLCODE") + n("DELEGATECALL") : "—"],
    ["Storage writes", result ? n("SSTORE") : "—"],
    ["Self-destructs", result ? n("SELFDESTRUCT") : "—"],
  ];
  return (
    <section className="card" aria-labelledby="ov-h">
      <h2 id="ov-h">Bytecode Overview</h2>
      <dl className="rows">
        {rows.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}
      </dl>
    </section>
  );
}

const V = {
  issues_detected: { icon: "warn", cls: "red", title: "Issues detected" },
  no_issues_detected: { icon: "shield", cls: "green", title: "No issues detected" },
  analysis_incomplete: { icon: "hold", cls: "amber", title: "Analysis incomplete" },
};

export function VerdictCard({ result, finishedAt, busy }) {
  if (busy) return <section className="card verdict-card"><h2>Audit Status</h2><p className="muted center">Running…</p></section>;
  if (!result) return <section className="card verdict-card"><h2>Audit Status</h2><p className="muted center">No analysis yet</p></section>;
  const v = V[result.verdict];
  return (
    <section className={"card verdict-card vc-" + v.cls} role="status" aria-labelledby="vd-h">
      <h2 id="vd-h">Audit Status</h2>
      <Icon name={v.icon} size={52} className={"vicon " + v.cls} />
      <p className={"vtitle " + v.cls}>{v.title}</p>
      <p className="vreason">{result.verdict_reason}</p>
      {finishedAt && <p className="muted small">{finishedAt.toLocaleString()}</p>}
    </section>
  );
}
