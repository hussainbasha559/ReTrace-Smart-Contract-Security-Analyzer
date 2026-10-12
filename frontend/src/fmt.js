export const fmtDate = (iso) => (iso ? new Date(iso).toLocaleString() : "—");
export const fmtBytes = (n) => (n == null ? "—" : n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`);
export const fmtMs = (ms) => (ms == null ? "—" : ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`);
export const STATUS_CLS = { COMPLETED: "green", FAILED: "red", RUNNING: "blue", QUEUED: "amber", CANCELLED: "muted", NOT_SCANNED: "muted" };
export const VERDICT_LABEL = { issues_detected: "Issues detected", no_issues_detected: "None detected", analysis_incomplete: "Incomplete" };
export const VERIFY_LABEL = { corroborated: "Corroborated by two methods", symbolically_feasible: "Symbolically feasible (Mythril)", heuristic: "Heuristic warning" };
