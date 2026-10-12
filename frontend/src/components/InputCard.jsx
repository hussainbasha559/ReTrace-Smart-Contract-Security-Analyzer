export default function InputCard({ value, onChange, options, onOptionsChange, onSubmit, busy }) {
  const clean = value.trim().replace(/^0x/i, "");
  const bytes = Math.floor(clean.length / 2);
  return (
    <section className="card card-input" aria-labelledby="in-h">
      <h2 id="in-h">Runtime bytecode</h2>
      <label htmlFor="bytecode" className="sr-only">Bytecode hex</label>
      <textarea id="bytecode" className="code-input" value={value} rows={4} spellCheck="false"
        autoComplete="off" placeholder="0x6080604052…" onChange={(e) => onChange(e.target.value)} />
      <p className="muted small">{clean ? `${bytes.toLocaleString()} bytes` : "Paste deployed hex; 0x prefix optional"}</p>
      <div className="opts">
        <label><input type="checkbox" checked={options.run_decompiler}
          onChange={(e) => onOptionsChange({ ...options, run_decompiler: e.target.checked })} /> Heimdall</label>
        <label><input type="checkbox" checked={options.run_mythril}
          onChange={(e) => onOptionsChange({ ...options, run_mythril: e.target.checked })} /> Mythril</label>
        <button className="btn primary sm" onClick={onSubmit} disabled={busy || !clean}>
          {busy ? "Analyzing…" : "Analyze"}
        </button>
      </div>
    </section>
  );
}
