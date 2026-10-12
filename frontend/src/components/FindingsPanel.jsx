import { useState } from "react";
import Icon from "./Icon.jsx";
import { sev } from "./TopBar.jsx";

const SEV_LABEL = { high: "High", medium: "Medium", low: "Low", informational: "Info" };
const SOURCE = { mythril: "Mythril", heuristic: "Structural heuristic" };
const FILTERS = [["all", "All"], ["high", "High"], ["medium", "Medium"], ["low", "Low"], ["informational", "Informational"]];

function Item({ f, open, onToggle, onShow }) {
  const marked = new Set(f.evidence.pcs);
  return (
    <article className={"vuln sev-" + f.severity}>
      <div className="vuln-head">
        <Icon name={f.severity === "informational" ? "circle" : "warn"} size={18} className={"vi sev-" + f.severity} />
        <div className="vuln-main">
          <h3>{f.title} <span className={"badge sev-" + f.severity}>{SEV_LABEL[f.severity]}</span></h3>
          <p className="muted">{f.description}</p>
        </div>
        <button className="btn ghost sm" aria-expanded={open} onClick={onToggle}>
          Details <Icon name="chev" size={14} className={open ? "flip" : ""} />
        </button>
      </div>
      {open && (
        <div className="vuln-body">
          <p className="muted small">
            {SOURCE[f.source]}{f.swc_id ? ` · ${f.swc_id}` : ""}{f.function ? ` · ${f.function}` : ""}
            {" · "}{f.confidence === "heuristic" ? "lower confidence" : "reported by tool"}
            {f.corroborated_by.length ? " · confirmed by a second method" : ""}
          </p>
          {f.evidence.instructions.length > 0 && (
            <>
              <h4>Evidence</h4>
              <ol className="evidence" aria-label="Instructions near the finding">
                {f.evidence.instructions.map((i) => (
                  <li key={i.pc} className={marked.has(i.pc) ? "mark" : ""}>
                    <span>{i.pc}</span><span>{i.name}</span><span>{i.operand ? "0x" + i.operand : ""}</span>
                  </li>
                ))}
              </ol>
              <button className="btn sm" onClick={() => onShow(f)}>Highlight in instruction list</button>
            </>
          )}
          <h4>Why it matters</h4><p>{f.explanation}</p>
          <h4>Possible fix</h4><p>{f.recommendation}</p>
          {f.evidence.tool_output && (
            <details><summary>Raw tool output</summary><pre className="raw">{f.evidence.tool_output}</pre></details>
          )}
        </div>
      )}
    </article>
  );
}

export default function FindingsPanel({ result, onShow }) {
  const [filter, setFilter] = useState("all");
  const [openId, setOpenId] = useState(null);
  const counts = sev(result);
  const all = result?.findings ?? [];
  const list = filter === "all" ? all : all.filter((f) => f.severity === filter);

  return (
    <section className="card card-find" id="findings" aria-labelledby="fd-h">
      <h2 id="fd-h">Findings</h2>
      <div className="chips" role="group" aria-label="Filter by severity">
        {FILTERS.map(([k, label]) => (
          <button key={k} className={"chip" + (filter === k ? " on" : "")} aria-pressed={filter === k} onClick={() => setFilter(k)}>
            {label} ({k === "all" ? all.length : counts[k]})
          </button>
        ))}
      </div>
      {!result && <p className="empty">Findings appear here after an analysis.</p>}
      {result && list.length === 0 && (
        <p className="empty">
          {all.length === 0 ? "Nothing was flagged. Check the Audit Status card for what that does and does not mean." : "No findings at this severity."}
        </p>
      )}
      <div className="vulns">
        {list.map((f) => (
          <Item key={f.id} f={f} open={openId === f.id} onToggle={() => setOpenId(openId === f.id ? null : f.id)} onShow={onShow} />
        ))}
      </div>
    </section>
  );
}
