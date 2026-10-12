import { NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../auth.jsx";
import { useTheme } from "../theme.js";
import Icon from "./Icon.jsx";
import ThemeToggle from "./ThemeToggle.jsx";

export default function AppNav() {
  const { user, logout } = useAuth();
  const { theme, toggle } = useTheme();
  const nav = useNavigate();
  const links = [["/dashboard", "Dashboard"], ["/analyze", "Analyze"], ["/files", "Files"], ["/scans", "Scan history"], ["/usage", "Usage"]];
  if (user?.role === "admin") links.push(["/admin", "Admin"]);
  return (
    <nav className="appnav" aria-label="Main">
      <span className="appnav-brand"><Icon name="shield" size={20} /> ReTrace</span>
      <ul>
        {links.map(([to, label]) => (
          <li key={to}><NavLink to={to} className={({ isActive }) => "appnav-link" + (isActive ? " on" : "")}>{label}</NavLink></li>
        ))}
      </ul>
      <div className="appnav-right">
        <ThemeToggle theme={theme} onToggle={toggle} />
        <NavLink to="/profile" className="appnav-link">{user?.name}</NavLink>
        <button className="btn ghost sm" onClick={async () => { await logout(); nav("/login"); }}>Sign out</button>
      </div>
    </nav>
  );
}
