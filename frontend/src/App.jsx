import { Navigate, Route, Routes } from "react-router-dom";
import { RequireAuth } from "./auth.jsx";
import AppNav from "./components/AppNav.jsx";
import AuthPage from "./pages/AuthPage.jsx";
import AnalyzePage from "./pages/AnalyzePage.jsx";
import DashboardPage from "./pages/DashboardPage.jsx";
import FilesPage from "./pages/FilesPage.jsx";
import ScansPage from "./pages/ScansPage.jsx";
import UsagePage from "./pages/UsagePage.jsx";
import ProfilePage from "./pages/ProfilePage.jsx";
import AdminPage from "./pages/AdminPage.jsx";

const guard = (el, admin) => <RequireAuth admin={admin}><AppNav />{el}</RequireAuth>;

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<AuthPage mode="login" />} />
      <Route path="/register" element={<AuthPage mode="register" />} />
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="/dashboard" element={guard(<DashboardPage />)} />
      <Route path="/analyze" element={guard(<AnalyzePage />)} />
      <Route path="/scans/:scanId" element={guard(<AnalyzePage />)} />
      <Route path="/scans" element={guard(<ScansPage />)} />
      <Route path="/files" element={guard(<FilesPage />)} />
      <Route path="/usage" element={guard(<UsagePage />)} />
      <Route path="/profile" element={guard(<ProfilePage />)} />
      <Route path="/admin" element={guard(<AdminPage />, true)} />
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
