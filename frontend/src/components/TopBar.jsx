import Icon from "./Icon.jsx";
import ThemeToggle from "./ThemeToggle.jsx";

const VERDICT_SHORT = {
  issues_detected: ["Issues", "v-red"],
  no_issues_detected: ["None found", "v-green"],
  analysis_incomplete: ["Incomplete", "v-amber"],
};

export default function TopBar({ runs, result, busy, canRun, onRun, onClear, theme, onToggleTheme }) {
  const counts = sev(result);
  const time = result ? result.tools.reduce((s, t) => s + (t.duration_s || 0), 0) : null;
  const v = result ? VERDICT_SHORT[result.verdict] : null;
  return (
    <header className="topbar">
      <div className="brand">
        <Icon name="shield" size={40} className="brand-icon" />
        <div>
          <h1>ReTrace <span className="ver">v0.1</span></h1>
          <p>Bytecode decompilation and re-entrancy analysis</p>
        </div>
      </div>

      <dl className="topstats">
        <div><dt>Analyses this session</dt><dd>{runs}</dd></div>
        <div><dt>Findings</dt><dd>{result ? result.findings.length : "—"}</dd></div>
        <div><dt>High severity</dt><dd className={counts.high ? "v-red" : ""}>{result ? counts.high : "—"}</dd></div>
        <div><dt>Verdict</dt><dd className={v ? v[1] : ""}>{v ? v[0] : "—"}</dd></div>
        <div><dt>Tool time</dt><dd>{time === null ? "—" : `${time.toFixed(1)}s`}</dd></div>
      </dl>

      <div className="topactions">
        <ThemeToggle theme={theme} onToggle={onToggleTheme} />
        <button className="btn primary" onClick={onRun} disabled={busy || !canRun}>
          {busy ? "Analyzing…" : "New analysis"}
        </button>
        <button className="btn ghost" onClick={onClear}><Icon name="reset" size={16} /> Clear</button>
      </div>
    </header>
  );
}

export function sev(result) {
  const c = { high: 0, medium: 0, low: 0, informational: 0 };
  (result?.findings ?? []).forEach((f) => { c[f.severity] += 1; });
  return c;
}
