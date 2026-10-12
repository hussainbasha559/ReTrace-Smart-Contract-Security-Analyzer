import Icon from "./Icon.jsx";

export default function ThemeToggle({ theme, onToggle }) {
  const dark = theme === "dark";
  return (
    <button
      type="button"
      role="switch"
      aria-checked={dark}
      aria-label="Dark theme"
      title={dark ? "Switch to light theme" : "Switch to dark theme"}
      className={"theme-toggle" + (dark ? " is-dark" : "")}
      onClick={onToggle}
    >
      <span className="tt-thumb" aria-hidden="true" />
      <span className={"tt-opt" + (!dark ? " on" : "")}><Icon name="sun" size={15} /></span>
      <span className={"tt-opt" + (dark ? " on" : "")}><Icon name="moon" size={15} /></span>
    </button>
  );
}
