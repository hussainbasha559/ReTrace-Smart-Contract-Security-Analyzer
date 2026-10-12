
 // All backend calls live here. The UI renders the verdict returned by the backend.
// Authentication uses a server-side session in an HttpOnly cookie.
// CSRF token is kept in memory and re-fetched from /api/auth/me after refresh.

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ??
  (import.meta.env.DEV ? "" : "https://smart-contract-analysis-retrace.onrender.com");

export class ApiError extends Error {
  constructor(message, code, fields, status) {
    super(message);
    this.code = code;
    this.fields = fields || null;
    this.status = status;
  }
}

let csrfToken = null;
let onUnauthorized = () => {};

export const setCsrf = (t) => {
  csrfToken = t;
};

export const setUnauthorizedHandler = (fn) => {
  onUnauthorized = fn;
};

async function request(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = { ...(options.headers || {}) };

  if (method !== "GET" && csrfToken) {
    headers["X-CSRF-Token"] = csrfToken;
  }

  let res;

  try {
    res = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      method,
      headers,
      credentials: "include",
    });
  } catch {
    throw new ApiError(
      "Could not reach the ReTrace backend. Please try again.",
      "network"
    );
  }

  if (options.raw && res.ok) return res;

  let body = null;
  try {
    body = await res.json();
  } catch {
    // Response was not JSON.
  }

  if (!res.ok) {
    const d = body?.detail;

    if (res.status === 401 && !path.startsWith("/api/auth/login")) {
      onUnauthorized();
    }

    if (
      d &&
      typeof d === "object" &&
      !Array.isArray(d) &&
      d.message
    ) {
      throw new ApiError(d.message, d.code, d.fields, res.status);
    }

    if (Array.isArray(d) && d[0]?.msg) {
      throw new ApiError(d[0].msg, "request_invalid", null, res.status);
    }

    throw new ApiError(
      `Request failed (HTTP ${res.status}).`,
      "http_" + res.status,
      null,
      res.status
    );
  }

  return body;
}

const send = (method) => (path, payload) =>
  request(path, {
    method,
    headers: { "Content-Type": "application/json" },
    body:
      payload === undefined
        ? undefined
        : JSON.stringify(payload),
  });

const post = send("POST");
const patch = send("PATCH");
const del = send("DELETE");

const qs = (o) => {
  const p = new URLSearchParams();

  Object.entries(o || {}).forEach(([k, v]) => {
    if (v !== "" && v != null) p.set(k, v);
  });

  const s = p.toString();
  return s ? "?" + s : "";
};

// --- Authentication / profile

export const register = (b) => post("/api/auth/register", b);
export const login = (b) => post("/api/auth/login", b);
export const logout = () => post("/api/auth/logout");
export const me = () => request("/api/auth/me");
export const getProfile = () => request("/api/profile");
export const updateProfile = (name) => patch("/api/profile", { name });
export const changePassword = (b) => post("/api/auth/change-password", b);
export const deleteMyData = () => del("/api/profile/data");
export const deleteAccount = (password) =>
  del("/api/profile", { password });

// --- Analysis

export const getHealth = () => request("/api/health");
export const disassemble = (bytecode) =>
  post("/api/disassemble", { bytecode });
export const createScan = (b) => post("/api/scans", b);
export const getScan = (id) => request(`/api/scans/${id}`);
export const getResult = (id) => request(`/api/scans/${id}/result`);
export const cancelScan = (id) => post(`/api/scans/${id}/cancel`);
export const rerunScan = (id) => post(`/api/scans/${id}/rerun`);
export const deleteScan = (id) => del(`/api/scans/${id}`);
export const listScans = (f) => request("/api/scans" + qs(f));
export const compareScans = (base, head) =>
  request("/api/scans/compare" + qs({ base, head }));
export const getDashboard = () => request("/api/dashboard");

// --- Files / projects

export const listFiles = (f) => request("/api/files" + qs(f));
export const getFile = (id) => request(`/api/files/${id}`);

export const uploadFile = (file, projectId) => {
  const fd = new FormData();
  fd.append("file", file);

  if (projectId) fd.append("project_id", projectId);

  return request("/api/files", {
    method: "POST",
    body: fd,
  });
};

export const pasteFile = (b) => post("/api/files/paste", b);
export const updateFile = (id, b) => patch(`/api/files/${id}`, b);
export const deleteFile = (id) => del(`/api/files/${id}`);
export const listProjects = () => request("/api/projects");
export const createProject = (b) => post("/api/projects", b);
export const deleteProject = (id) => del(`/api/projects/${id}`);

// --- Usage / admin

export const myUsage = () => request("/api/usage/me");
export const adminOverview = () => request("/api/admin/overview");
export const adminUsers = () => request("/api/admin/users");
export const adminSetActive = (id, is_active) =>
  patch(`/api/admin/users/${id}`, { is_active });

// --- AI

export const aiStatus = () => request("/api/ai/status");
export const aiExplain = (id) => post(`/api/scans/${id}/ai/explain`);
export const aiRemediation = (id) => post(`/api/scans/${id}/ai/remediation`);
export const aiRisk = (id) => post(`/api/scans/${id}/ai/risk`);
export const aiReport = (id, b) => post(`/api/scans/${id}/ai/report`, b);
export const aiChat = (id, messages) =>
  post(`/api/scans/${id}/ai/chat`, { messages });
export const aiHistory = (id) => request(`/api/scans/${id}/ai/history`);

export const exportUrl = (id, format) =>
  `${API_BASE_URL}/api/scans/${id}/export?format=${encodeURIComponent(format)}`;

export const downloadUrl = (id) =>
  `${API_BASE_URL}/api/files/${id}/download`;
