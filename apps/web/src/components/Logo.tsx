/** Brand mark: a keyhole inside a rounded square. Uses currentColor so it follows the theme. */
export function Logo({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" className="logo">
      <rect x="1" y="1" width="22" height="22" rx="6" fill="currentColor" />
      <circle cx="12" cy="10" r="3.2" className="logo-cut" />
      <path d="M10.6 12.2 9.6 18h4.8l-1-5.8" className="logo-cut" />
    </svg>
  );
}
