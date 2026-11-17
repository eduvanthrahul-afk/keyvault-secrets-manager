// Theme preference (light / dark / system). A per-viewer convenience, so localStorage is fine;
// every access is guarded because storage can be unavailable (private mode, blocked site data).

export type ThemePref = 'light' | 'dark' | 'system';
const KEY = 'kv-theme';

export function getThemePref(): ThemePref {
  try {
    const v = localStorage.getItem(KEY);
    return v === 'light' || v === 'dark' ? v : 'system';
  } catch {
    return 'system';
  }
}

export function applyTheme(pref: ThemePref): void {
  const root = document.documentElement;
  if (pref === 'system') root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', pref);
  try {
    if (pref === 'system') localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, pref);
  } catch {
    /* ignore */
  }
}
