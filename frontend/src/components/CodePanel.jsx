import OpcodeTable from "./OpcodeTable.jsx";

const MAX_LINES = 3000;

function Decompiled({ code, tool }) {
  if (code) {
    const lines = code.split("\n");
    const shown = lines.slice(0, MAX_LINES);
    return (
      <div className="src" tabIndex={0}>
        {shown.map((l, i) => (
          <div key={i} className="src-line"><span className="ln">{i + 1}</span><span className="lt">{l || " "}</span></div>
        ))}
        {lines.length > MAX_LINES && <p className="muted small pad">Showing first {MAX_LINES} of {lines.length} lines.</p>}
      </div>
    );
  }
  const why = !tool ? "Run an analysis to see decompiled output."
    : tool.status === "skipped" ? "The decompiler was not run."
    : tool.status === "not_installed" ? "Heimdall is not installed, so there is no decompiled output."
    : `Heimdall ${tool.status}${tool.error ? ": " + tool.error : "."}`;
  return <p className="empty">{why}</p>;
}

export default function CodePanel({ tab, onTab, result, highlight, onClear }) {
  const tool = result?.tools.find((t) => t.name === "heimdall");
  return (
    <section className="card card-code" id="code-panel" aria-label="Code view">
      <div className="tabs" role="tablist">
        <button role="tab" aria-selected={tab === "instructions"} className={tab === "instructions" ? "on" : ""} onClick={() => onTab("instructions")}>
          Instructions{result ? ` (${result.instructions.length.toLocaleString()})` : ""}
        </button>
        <button role="tab" aria-selected={tab === "decompiled"} className={tab === "decompiled" ? "on" : ""} onClick={() => onTab("decompiled")}>
          Decompiled
        </button>
      </div>
      {tab === "decompiled" && <p className="hint pad">An approximation: names, comments and formatting cannot be recovered from bytecode.</p>}
      {tab === "instructions" && (result
        ? <OpcodeTable instructions={result.instructions} highlightPcs={highlight.pcs} focus={highlight.focus} onClear={onClear} />
        : <p className="empty">Run an analysis to see the decoded instructions.</p>)}
      {tab === "decompiled" && <Decompiled code={result?.decompiled_code} tool={tool} />}
    </section>
  );
}
