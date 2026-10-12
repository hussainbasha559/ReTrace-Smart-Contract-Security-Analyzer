import { STATUS_CLS } from "../fmt.js";

export const Status = ({ s }) => (
  <span className={"status " + (STATUS_CLS[s] || "")}><span className={"dot " + ({ COMPLETED: "g", FAILED: "r", RUNNING: "blue", QUEUED: "yellow" }[s] || "")} aria-hidden="true" />{s.replace("_", " ").toLowerCase()}</span>
);

export function Pager({ page, pageSize, total, onPage }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <div className="pager">
      <button className="btn sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button>
      <span className="muted small">Page {page} of {pages} · {total} total</span>
      <button className="btn sm" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button>
    </div>
  );
}

export const Stat = ({ label, value, cls = "" }) => (
  <div className="stat"><dt>{label}</dt><dd className={cls}>{value ?? "—"}</dd></div>
);

export function Bars({ data, field = "count", height = 70, label }) {
  const max = Math.max(1, ...data.map((d) => d[field]));
  const w = 100 / data.length;
  return (
    <svg className="bars" viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" role="img" aria-label={label}>
      {data.map((d, i) => {
        const h = (d[field] / max) * (height - 4);
        return <rect key={d.date} x={i * w + w * 0.15} width={w * 0.7} y={height - h} height={h} rx="0.6"><title>{`${d.date}: ${d[field]}`}</title></rect>;
      })}
    </svg>
  );
}

export const ErrorBox = ({ error }) => error ? <div className="error-box" role="alert"><p>{error}</p></div> : null;
