import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import * as api from "../services/api.js";
import { getHealth } from "../services/api.js";
import AiPanel from "../components/AiPanel.jsx";
import { Status } from "../components/Bits.jsx";
import { fmtMs } from "../fmt.js";
import { useTheme } from "../theme.js";
import TopBar from "../components/TopBar.jsx";
import Sidebar from "../components/Sidebar.jsx";
import InputCard from "../components/InputCard.jsx";
import { RiskSummary, ToolChecks, Overview, VerdictCard } from "../components/SummaryCards.jsx";
import CodePanel from "../components/CodePanel.jsx";
import FindingsPanel from "../components/FindingsPanel.jsx";
import { Recommendations, Timeline, Notes } from "../components/SidePanels.jsx";

import vulnerableHex from "../../../samples/vulnerable/VulnerableBank.runtime.hex?raw";
import correctedHex from "../../../samples/corrected/SafeBank.runtime.hex?raw";

const SAMPLES = [
  { label: "Vulnerable sample", hex: vulnerableHex.trim() },
  { label: "Corrected sample", hex: correctedHex.trim() },
];

export default function AnalyzePage() {
  const [bytecode, setBytecode] = useState("");
  const [options, setOptions] = useState({ run_decompiler: true, run_mythril: true });
  const [state, setState] = useState({ phase: "idle", result: null, error: null, finishedAt: null });
  const [runs, setRuns] = useState(0);
  const [health, setHealth] = useState(null);
  const [tab, setTab] = useState("instructions");
  const [highlight, setHighlight] = useState({ pcs: [], focus: null });
  const [nav, setNav] = useState("top");
  const { theme, toggle: toggleTheme } = useTheme();
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const track = useRef(0);

  useEffect(() => {
    getHealth().then(setHealth).catch((e) => setHealth({ error: e.message }));
  }, []);

  // Poll a scan until it reaches a terminal state, then load its full result.
  async function follow(id) {
    const token = ++track.current;
    setState({ phase: "loading", result: null, error: null, finishedAt: null });
    setHighlight({ pcs: [], focus: null });
    for (;;) {
      let s;
      try { s = await api.getScan(id); } catch (e) {
        if (token === track.current) setState({ phase: "error", result: null, error: e.message, finishedAt: null });
        return;
      }
      if (token !== track.current) return;
      setScan(s);
      if (s.status === "COMPLETED") {
        try {
          const result = await api.getResult(id);
          if (token !== track.current) return;
          setRuns((n) => n + 1);
          setState({ phase: "done", result, error: null, finishedAt: new Date(s.completed_at) });
        } catch (e) { setState({ phase: "error", result: null, error: e.message, finishedAt: null }); }
        return;
      }
      if (s.status === "FAILED" || s.status === "CANCELLED") {
        setState({ phase: "error", result: null, finishedAt: null,
          error: s.status === "CANCELLED" ? "This scan was cancelled." : `The scan failed: ${s.error_summary || "unknown error"}` });
        return;
      }
      await new Promise((r) => setTimeout(r, 1500));
    }
  }

  useEffect(() => {
    if (scanId) follow(Number(scanId)); else { setScan(null); }
    return () => { track.current += 1; };       // stop polling when leaving the page
  }, [scanId]);

  async function run() {
    try {
      const s = await api.createScan({ bytecode, ...options });
      navigate(`/scans/${s.id}`);
    } catch (e) {
      setState({ phase: "error", result: null, error: e.message, finishedAt: null });
    }
  }

  async function cancel() {
    try { setScan(await api.cancelScan(scan.id)); } catch (e) { setState((st) => ({ ...st, error: e.message })); }
  }

  async function rerun() {
    try { const s = await api.rerunScan(scan.id); navigate(`/scans/${s.id}`); }
    catch (e) { setState({ phase: "error", result: null, error: e.message, finishedAt: null }); }
  }

  function clear() {
    track.current += 1;
    if (scanId) navigate("/analyze");
    setBytecode("");
    setState({ phase: "idle", result: null, error: null, finishedAt: null });
    setHighlight({ pcs: [], focus: null });
  }

  function scrollTo(id) {
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function goto(id) {
    setNav(id);
    if (id === "top") window.scrollTo({ top: 0, behavior: "smooth" });
    if (id === "findings") scrollTo("findings");
    if (id === "code") { setTab("instructions"); setTimeout(() => scrollTo("code-panel"), 0); }
    if (id === "decompiled") { setTab("decompiled"); setTimeout(() => scrollTo("code-panel"), 0); }
  }

  function showFinding(f) {
    const pcs = f.evidence.pcs;
    setTab("instructions");
    setHighlight({ pcs, focus: { pc: pcs[0], nonce: Date.now() } });
    setTimeout(() => scrollTo("code-panel"), 0);
  }

  const { phase, result, error, finishedAt } = state;
  const busy = phase === "loading";

  return (
    <div className="app">
      <TopBar runs={runs} result={result} busy={busy} canRun={bytecode.trim().length > 0} onRun={run} onClear={clear}
        theme={theme} onToggleTheme={toggleTheme} />
      <div className="body">
        <Sidebar active={nav} onNav={goto} samples={SAMPLES} onSample={setBytecode} health={health} busy={busy} />
        <main className="content" aria-live="polite">
          {phase === "error" && (
            <div className="error-box" role="alert"><h2>Analysis did not run</h2><p>{error}</p></div>
          )}
          {scan && (
            <div className="scan-banner card">
              <span><b>Scan #{scan.id}</b> <Status s={scan.status} /></span>
              <span className="muted small">{scan.file_name || scan.target.slice(0, 12)} · {scan.input_bytes} bytes{scan.duration_ms != null && ` · ${fmtMs(scan.duration_ms)}`}</span>
              <span className="scan-actions">
                {(scan.status === "QUEUED" || scan.status === "RUNNING") && <button className="btn sm" onClick={cancel}>Cancel</button>}
                {scan.file_id && scan.status !== "QUEUED" && scan.status !== "RUNNING" && <button className="btn sm" onClick={rerun}>Re-run</button>}
                {scan.status === "COMPLETED" && <><a className="btn sm" href={api.exportUrl(scan.id, "json")}>Export JSON</a><a className="btn sm" href={api.exportUrl(scan.id, "md")}>Export Markdown</a></>}
                <Link className="btn sm ghost" to="/scans">History</Link>
              </span>
            </div>
          )}
          <div className="row-a">
            <InputCard value={bytecode} onChange={setBytecode} options={options} onOptionsChange={setOptions} onSubmit={run} busy={busy} />
            <RiskSummary result={result} />
            <ToolChecks result={result} />
            <Overview result={result} />
            <VerdictCard result={result} finishedAt={finishedAt} busy={busy} />
          </div>
          <div className="row-b">
            <CodePanel tab={tab} onTab={setTab} result={result} highlight={highlight}
              onClear={() => setHighlight({ pcs: [], focus: null })} />
            <FindingsPanel key={result ? finishedAt?.getTime() : "none"} result={result} onShow={showFinding} />
            <div className="side-col">
              <Recommendations result={result} />
              <Timeline result={result} busy={busy} />
            </div>
          </div>
          <Notes warnings={result?.warnings} />
          {phase === "done" && scan && <AiPanel scanId={scan.id} hasFindings={result.findings.length > 0} />}
        </main>
      </div>
    </div>
  );
}
