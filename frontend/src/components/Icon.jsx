const P = {
  shield: <><path d="M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5Z" /><path d="m8.5 12 2.6 2.6L16 9.5" /></>,
  warn: <><path d="M12 3 22 21H2Z" /><path d="M12 10v5M12 18v.5" /></>,
  hold: <><rect x="3.5" y="3.5" width="17" height="17" rx="3" strokeDasharray="3.5 3" /><path d="M9.5 9.6a2.6 2.6 0 1 1 3.8 2.3c-.8.4-1.3 1-1.3 1.8M12 17v.5" /></>,
  check: <><circle cx="12" cy="12" r="9" /><path d="m8 12.3 2.8 2.8L16 9.6" /></>,
  circle: <circle cx="12" cy="12" r="8" />,
  dash: <circle cx="12" cy="12" r="8" strokeDasharray="3 3" />,
  x: <><circle cx="12" cy="12" r="9" /><path d="m9 9 6 6M15 9l-6 6" /></>,
  grid: <><rect x="4" y="4" width="7" height="7" rx="1" /><rect x="13" y="4" width="7" height="7" rx="1" /><rect x="4" y="13" width="7" height="7" rx="1" /><rect x="13" y="13" width="7" height="7" rx="1" /></>,
  list: <><path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01" /></>,
  code: <><path d="m8 8-4 4 4 4M16 8l4 4-4 4M13.5 5l-3 14" /></>,
  bug: <><rect x="8" y="8" width="8" height="11" rx="4" /><path d="M9 8a3 3 0 0 1 6 0M4 12h4M16 12h4M5 18l3-2M19 18l-3-2M5 6l3 2M19 6l-3 2" /></>,
  file: <><path d="M6 3h8l4 4v14H6Z" /><path d="M14 3v4h4" /></>,
  chev: <path d="m7 10 5 5 5-5" />,
  sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2.5v2M12 19.5v2M4.6 4.6 6 6M18 18l1.4 1.4M2.5 12h2M19.5 12h2M4.6 19.4 6 18M18 6l1.4-1.4" /></>,
  moon: <path d="M20 14.2A8 8 0 0 1 9.8 4 8 8 0 1 0 20 14.2Z" />,
  reset: <><path d="M4 12a8 8 0 1 0 3-6.2" /><path d="M4 4v4h4" /></>,
};
export default function Icon({ name, size = 18, className = "" }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {P[name]}
    </svg>
  );
}
