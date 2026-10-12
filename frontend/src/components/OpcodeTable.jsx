import { useEffect, useMemo, useRef, useState } from "react";

const ROW = 26;
const VIEW = 420;
const OVERSCAN = 12;

// Virtualized: contracts can have ~25,000 instructions.
export default function OpcodeTable({ instructions, highlightPcs, focus, onClear }) {
  const ref = useRef(null);
  const [top, setTop] = useState(0);
  const indexByPc = useMemo(() => new Map(instructions.map((ins, i) => [ins.pc, i])), [instructions]);
  const hits = useMemo(() => new Set(highlightPcs), [highlightPcs]);

  useEffect(() => {
    if (!focus || !ref.current) return;
    const idx = indexByPc.get(focus.pc);
    if (idx !== undefined) ref.current.scrollTop = Math.max(0, idx * ROW - VIEW / 2 + ROW);
  }, [focus, indexByPc]);

  const first = Math.max(0, Math.floor(top / ROW) - OVERSCAN);
  const last = Math.min(instructions.length, Math.ceil((top + VIEW) / ROW) + OVERSCAN);
  const rows = instructions.slice(first, last);

  return (
    <div className="ops">
      {hits.size > 0 && (
        <div className="ops-bar">
          <span className="muted small">{hits.size} instruction(s) highlighted</span>
          <button className="btn ghost sm" onClick={onClear}>Clear</button>
        </div>
      )}
      <div className="op-header" aria-hidden="true"><span>pc</span><span>byte</span><span>opcode</span><span>operand</span></div>
      <div className="op-scroll" ref={ref} style={{ height: VIEW }} onScroll={(e) => setTop(e.currentTarget.scrollTop)}
        tabIndex={0} role="table" aria-label="Decoded instructions" aria-rowcount={instructions.length}>
        <div style={{ height: instructions.length * ROW, position: "relative" }}>
          {rows.map((ins, k) => (
            <div key={ins.pc} role="row" className={"op-row" + (hits.has(ins.pc) ? " hit" : "")} style={{ top: (first + k) * ROW, height: ROW }}>
              <span role="cell" className="pc">{ins.pc}</span>
              <span role="cell" className="byte">{ins.opcode}</span>
              <span role="cell" className="name">{ins.name}</span>
              <span role="cell" className="operand">{ins.operand ? "0x" + ins.operand : ""}{ins.truncated ? " (cut off)" : ""}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
