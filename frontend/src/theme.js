import { useCallback, useEffect, useState } from "react";

const KEY = "retrace-theme";

// Light is the default. A saved choice always wins.
export function getInitialTheme() {
  try {
    return localStorage.getItem(KEY) === "dark" ? "dark" : "light";
  } catch {
    return "light";
  }
}

export function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    /* storage unavailable (private mode): the theme still applies for this visit */
  }
}

export function useTheme() {
  const [theme, setTheme] = useState(getInitialTheme);
  useEffect(() => applyTheme(theme), [theme]);
  const toggle = useCallback(() => setTheme((t) => (t === "dark" ? "light" : "dark")), []);
  return { theme, toggle };
}
