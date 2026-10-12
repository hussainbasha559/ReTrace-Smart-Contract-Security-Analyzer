import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { Navigate, useLocation } from "react-router-dom";
import * as api from "./services/api.js";

const Ctx = createContext(null);
export const useAuth = () => useContext(Ctx);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);   // true until /auth/me answered (restores login after refresh)

  const clear = useCallback(() => { api.setCsrf(null); setUser(null); }, []);

  useEffect(() => {
    api.setUnauthorizedHandler(clear);
    api.me().then((r) => { api.setCsrf(r.csrf_token); setUser(r.user); }).catch(() => {}).finally(() => setLoading(false));
  }, [clear]);

  const accept = (r) => { api.setCsrf(r.csrf_token); setUser(r.user); return r.user; };
  const value = {
    user, loading,
    login: async (email, password) => accept(await api.login({ email, password })),
    register: async (name, email, password) => accept(await api.register({ name, email, password })),
    logout: async () => { try { await api.logout(); } finally { clear(); } },
    setName: (name) => setUser((u) => ({ ...u, name })),
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function RequireAuth({ children, admin = false }) {
  const { user, loading } = useAuth();
  const loc = useLocation();
  if (loading) return <p className="empty center">Loading…</p>;
  if (!user) return <Navigate to="/login" replace state={{ from: loc.pathname }} />;
  if (admin && user.role !== "admin") return <Navigate to="/dashboard" replace />;
  return children;
}
