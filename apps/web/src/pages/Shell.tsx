import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom';
import { CommandPalette } from '../components/CommandPalette';
import { Identicon } from '../components/Identicon';
import { Logo } from '../components/Logo';
import { Button, Icon, Modal, anyDialogOpen, isTyping } from '../components/ui';
import { api, type ProjectSummary } from '../lib/api';
import { applyTheme, getThemePref, type ThemePref } from '../lib/theme';
import { useVault } from '../lib/vault';

const TAB_LABELS: Record<string, string> = {
  secrets: 'Secrets', health: 'Health', compare: 'Compare', members: 'Members', environments: 'Environments',
  tokens: 'Access tokens', activity: 'Activity', settings: 'Settings', changes: 'Changes', webhooks: 'Webhooks',
};

function Breadcrumbs() {
  const { pathname } = useLocation();
  const qc = useQueryClient();
  const parts: { label: string; to?: string }[] = [];
  const m = /^\/app\/p\/([^/]+)(?:\/([^/?]+))?/.exec(pathname);
  if (m) {
    const name = qc.getQueryData<ProjectSummary[]>(['projects'])?.find((p) => p.id === m[1])?.name ?? 'Project';
    parts.push({ label: 'Projects', to: '/app' }, { label: name, to: `/app/p/${m[1]}` });
    if (m[2]) parts.push({ label: TAB_LABELS[m[2]] ?? m[2] });
  } else if (pathname.startsWith('/app/account')) parts.push({ label: 'Account & security' });
  else if (pathname.startsWith('/app/send')) parts.push({ label: 'One-time share' });
  else parts.push({ label: 'Projects' });
  return (
    <nav className="crumbs" aria-label="Breadcrumb">
      {parts.map((p, i) => (
        <span key={i} className="row" style={{ gap: 6, minWidth: 0 }}>
          {i > 0 && <span className="sep">/</span>}
          {p.to && i < parts.length - 1 ? <Link to={p.to}>{p.label}</Link> : <span className="here">{p.label}</span>}
        </span>
      ))}
    </nav>
  );
}

function ThemeSwitch() {
  const [pref, setPref] = useState<ThemePref>(getThemePref());
  const opts: [ThemePref, 'sun' | 'moon' | 'monitor', string][] = [['light', 'sun', 'Light'], ['dark', 'moon', 'Dark'], ['system', 'monitor', 'System']];
  return (
    <div className="theme-switch" role="group" aria-label="Theme">
      {opts.map(([v, icon, label]) => (
        <button key={v} type="button" aria-pressed={pref === v} title={label} aria-label={`${label} theme`}
          onClick={() => { applyTheme(v); setPref(v); }}><Icon name={icon} size={14} /></button>
      ))}
    </div>
  );
}

export function Shell() {
  const vault = useVault();
  const location = useLocation();
  const [open, setOpen] = useState(false);
  const [palette, setPalette] = useState(false);
  const [help, setHelp] = useState(false);
  const projects = useQuery({ queryKey: ['projects'], queryFn: api.projects.list });

  useEffect(() => setOpen(false), [location.pathname]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPalette((p) => !p); }
      else if (e.key === '?' && !isTyping() && !anyDialogOpen()) { e.preventDefault(); setHelp(true); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);
  const mac = /Mac|iPhone|iPad/.test(navigator.platform);

  return (
    <div className="shell">
      <nav className={`sidebar ${open ? 'open' : ''}`} aria-label="Primary">
        <div className="row spread">
          <Link to="/app" className="brand"><Logo /> KeyVault</Link>
          <Button variant="ghost" size="icon" className="mobile-only" aria-label="Close navigation" onClick={() => setOpen(false)}><Icon name="x" /></Button>
        </div>
        <button type="button" className="search-btn" onClick={() => setPalette(true)}>
          <Icon name="search" size={14} /> Search <span className="kbd">{mac ? '⌘' : 'Ctrl'} K</span>
        </button>
        <NavLink end to="/app" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}><Icon name="layers" /> All projects</NavLink>
        <NavLink to="/app/send" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}><Icon name="send" /> One-time share</NavLink>
        <NavLink to="/app/account" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}><Icon name="shield" /> Account &amp; security</NavLink>

        <div className="nav-group">Projects</div>
        {projects.data?.map((p) => (
          <NavLink key={p.id} to={`/app/p/${p.id}`} className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            <Identicon seed={p.id} size={16} />
            <span className="grow" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.name}</span>
            {p.rotationNeeded && <span className="dot" title="Key rotation recommended" />}
          </NavLink>
        ))}
        {projects.data?.length === 0 && <p className="xs faint" style={{ padding: '2px 8px' }}>No projects yet.</p>}

        <div className="sidebar-foot">
          <div className="user-card">
            <Identicon publicKey={vault.bundle?.publicKey} size={30} title="Your identicon" />
            <div className="grow">
              <div className="name">{vault.bundle?.user.displayName}</div>
              <div className="email">{vault.bundle?.user.email}</div>
            </div>
          </div>
          <div className="row spread" style={{ padding: '0 4px 4px' }}>
            <ThemeSwitch />
            <div className="row" style={{ gap: 4 }}>
              <Button size="icon" variant="ghost" onClick={() => vault.lock()} title="Lock vault (wipes keys from memory)" aria-label="Lock"><Icon name="lock" /></Button>
              <Button size="icon" variant="ghost" onClick={() => vault.logout()} title="Sign out" aria-label="Sign out"><Icon name="logout" /></Button>
            </div>
          </div>
        </div>
      </nav>
      <div className="scrim" onClick={() => setOpen(false)} />

      <div className="main-col">
        <header className="topbar">
          <Button variant="ghost" size="icon" className="mobile-only" aria-label="Open navigation" aria-expanded={open} onClick={() => setOpen(true)}><Icon name="menu" /></Button>
          <Breadcrumbs />
          <div className="actions">
            <span className="badge ok" title="Keys are decrypted in this tab only"><span className="dot" /> Unlocked</span>
          </div>
        </header>
        <main className="main" id="main">
          <Outlet />
        </main>
      </div>
      <CommandPalette open={palette} onClose={() => setPalette(false)} />
      <Modal open={help} onClose={() => setHelp(false)} title="Keyboard shortcuts">
        <div className="shortcuts">
          {([
            ['Search projects and actions', [mac ? '⌘' : 'Ctrl', 'K']],
            ['Filter secrets', ['/']],
            ['Add a secret', ['N']],
            ['Import a .env file', ['I']],
            ['Reveal or hide all values', ['R']],
            ['Save inline edit', ['↵']],
            ['Save in the editor', [mac ? '⌘' : 'Ctrl', '↵']],
            ['Cancel, clear selection', ['Esc']],
            ['Select a range of rows', ['Shift', 'click']],
            ['Import by pasting a .env', [mac ? '⌘' : 'Ctrl', 'V']],
            ['Show this help', ['?']],
          ] as [string, string[]][]).map(([label, keys]) => (
            <div key={label} style={{ display: 'contents' }}>
              <span>{label}</span>
              <span className="keys">{keys.map((k) => <span key={k} className="kbd">{k}</span>)}</span>
            </div>
          ))}
        </div>
      </Modal>
    </div>
  );
}
