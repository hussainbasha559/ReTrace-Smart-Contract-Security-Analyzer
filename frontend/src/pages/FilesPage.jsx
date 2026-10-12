import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import * as api from "../services/api.js";
import { ErrorBox, Pager, Status } from "../components/Bits.jsx";
import { fmtBytes, fmtDate, VERDICT_LABEL } from "../fmt.js";

export default function FilesPage() {
  const nav = useNavigate();
  const fileInput = useRef(null);
  const [data, setData] = useState({ items: [], total: 0, page: 1, page_size: 10 });
  const [projects, setProjects] = useState([]);
  const [filter, setFilter] = useState({ q: "", project_id: "" });
  const [page, setPage] = useState(1);
  const [target, setTarget] = useState({ project_id: "" });   // project to attach new uploads to
  const [paste, setPaste] = useState({ name: "", bytecode: "" });
  const [newProject, setNewProject] = useState("");
  const [err, setErr] = useState(null);
  const [note, setNote] = useState(null);
  const [open, setOpen] = useState(null);       // expanded file with its scans
  const [renaming, setRenaming] = useState(null);

  const load = useCallback(() => {
    api.listFiles({ ...filter, page, page_size: 10 }).then(setData).catch((e) => setErr(e.message));
    api.listProjects().then((r) => setProjects(r.items)).catch(() => {});
  }, [filter, page]);
  useEffect(load, [load]);

  const guard = (fn) => async (...a) => {
    setErr(null); setNote(null);
    try { await fn(...a); load(); } catch (e) { setErr(e.message); }
  };
  const upload = guard(async (e) => {
    const files = [...e.target.files];
    for (const f of files) await api.uploadFile(f, target.project_id);
    e.target.value = "";
    setNote(`${files.length} file(s) uploaded.`);
  });
  const doPaste = guard(async (e) => {
    e.preventDefault();
    await api.pasteFile({ ...paste, name: paste.name || null, project_id: target.project_id || null });
    setPaste({ name: "", bytecode: "" });
    setNote("Bytecode saved.");
  });
  const addProject = guard(async (e) => {
    e.preventDefault();
    await api.createProject({ project_name: newProject });
    setNewProject("");
  });
  const startScan = async (f) => {
    setErr(null);
    try { const s = await api.createScan({ file_id: f.id }); nav(`/scans/${s.id}`); } catch (e) { setErr(e.message); }
  };
  const rename = guard(async (f, name) => { await api.updateFile(f.id, { name }); setRenaming(null); });
  const remove = guard(async (f) => {
    if (!window.confirm(`Delete “${f.name}”? The stored file is removed; past scan results stay in your history.`)) return;
    await api.deleteFile(f.id);
  });
  const assign = guard(async (f, pid) => api.updateFile(f.id, pid ? { project_id: Number(pid) } : { clear_project: true }));
  const toggle = async (f) => {
    if (open?.id === f.id) return setOpen(null);
    try { setOpen(await api.getFile(f.id)); } catch (e) { setErr(e.message); }
  };

  return (
    <main className="page">
      <div className="page-head"><h1>Files</h1></div>
      <ErrorBox error={err} />
      {note && <p className="notice" role="status">{note}</p>}

      <div className="grid-2">
        <section className="card">
          <h2>Upload bytecode</h2>
          <p className="muted small">Hex text (0x… optional) or raw binary bytecode, up to 24,576 bytes. The content is checked, not the file extension.</p>
          <div className="opts">
            <label>Project{" "}
              <select value={target.project_id} onChange={(e) => setTarget({ project_id: e.target.value })}>
                <option value="">No project</option>{projects.map((p) => <option key={p.id} value={p.id}>{p.project_name}</option>)}
              </select>
            </label>
            <input ref={fileInput} type="file" multiple onChange={upload} aria-label="Choose bytecode files" />
          </div>
        </section>
        <section className="card">
          <h2>Paste bytecode</h2>
          <form onSubmit={doPaste}>
            <input className="text-in" placeholder="Name (optional)" value={paste.name} maxLength={120} onChange={(e) => setPaste({ ...paste, name: e.target.value })} />
            <textarea className="code-input" rows={3} placeholder="0x6080604052…" spellCheck="false" value={paste.bytecode} onChange={(e) => setPaste({ ...paste, bytecode: e.target.value })} />
            <button className="btn sm primary" disabled={!paste.bytecode.trim()}>Save</button>
          </form>
        </section>
      </div>

      <section className="card">
        <h2>Projects</h2>
        <div className="opts">
          {projects.length === 0 && <span className="muted small">No projects yet.</span>}
          {projects.map((p) => (
            <span key={p.id} className="chip static">{p.project_name} · {p.file_count} files
              <button className="x" aria-label={`Delete project ${p.project_name}`} onClick={guard(async () => { if (window.confirm("Delete this project? Its files are kept.")) await api.deleteProject(p.id); })}>×</button></span>
          ))}
          <form onSubmit={addProject} className="inline-form">
            <input className="text-in" placeholder="New project name" value={newProject} maxLength={120} onChange={(e) => setNewProject(e.target.value)} />
            <button className="btn sm" disabled={!newProject.trim()}>Add</button>
          </form>
        </div>
      </section>

      <section className="card">
        <h2>Your files</h2>
        <div className="filters">
          <input className="text-in" placeholder="Search by name" value={filter.q} onChange={(e) => { setPage(1); setFilter({ ...filter, q: e.target.value }); }} />
          <select value={filter.project_id} onChange={(e) => { setPage(1); setFilter({ ...filter, project_id: e.target.value }); }} aria-label="Filter by project">
            <option value="">All projects</option>{projects.map((p) => <option key={p.id} value={p.id}>{p.project_name}</option>)}
          </select>
        </div>
        {data.items.length === 0 ? <p className="empty">No files yet.</p> : (
          <div className="table-wrap"><table className="table">
            <thead><tr><th>Name</th><th>Size</th><th>Type</th><th>Project</th><th>Uploaded</th><th>Status</th><th>Scans</th><th>Actions</th></tr></thead>
            <tbody>{data.items.map((f) => (
              <>
                <tr key={f.id}>
                  <td>{renaming?.id === f.id
                    ? <form className="inline-form" onSubmit={(e) => { e.preventDefault(); rename(f, renaming.name); }}>
                        <input className="text-in" autoFocus value={renaming.name} maxLength={120} onChange={(e) => setRenaming({ id: f.id, name: e.target.value })} />
                        <button className="btn sm">Save</button></form>
                    : <><b>{f.name}</b><div className="muted small mono" title={f.sha256}>{f.sha256.slice(0, 12)}…</div></>}</td>
                  <td>{fmtBytes(f.size)}</td><td>{f.type.replace("_", " ")}</td>
                  <td><select value={f.project_id ?? ""} onChange={(e) => assign(f, e.target.value)} aria-label={`Project for ${f.name}`}>
                    <option value="">—</option>{projects.map((p) => <option key={p.id} value={p.id}>{p.project_name}</option>)}</select></td>
                  <td>{fmtDate(f.created_at)}</td>
                  <td>{f.status === "NOT_SCANNED" ? <span className="muted">not scanned</span> : <Status s={f.status} />}
                    {f.latest_scan?.verdict && <div className="muted small">{VERDICT_LABEL[f.latest_scan.verdict]}</div>}</td>
                  <td><button className="linklike" onClick={() => toggle(f)}>{f.scan_count}</button></td>
                  <td className="actions">
                    <button className="btn sm primary" onClick={() => startScan(f)}>Scan</button>
                    <a className="btn sm" href={api.downloadUrl(f.id)}>Download</a>
                    <button className="btn sm" onClick={() => setRenaming({ id: f.id, name: f.name })}>Rename</button>
                    <button className="btn sm ghost red" onClick={() => remove(f)}>Delete</button>
                  </td>
                </tr>
                {open?.id === f.id && (
                  <tr key={"o" + f.id}><td colSpan={8}>
                    {open.scans.length === 0 ? <p className="empty">No scans yet.</p> : (
                      <ul className="plain-list">{open.scans.map((s) => (
                        <li key={s.id}><Link to={`/scans/${s.id}`}>Scan #{s.id}</Link> <Status s={s.status} /> {s.verdict && VERDICT_LABEL[s.verdict]} · {s.severity_counts?.total ?? 0} findings · {fmtDate(s.created_at)}</li>
                      ))}</ul>
                    )}
                  </td></tr>
                )}
              </>
            ))}</tbody>
          </table></div>
        )}
        <Pager page={data.page} pageSize={data.page_size} total={data.total} onPage={setPage} />
      </section>
    </main>
  );
}
