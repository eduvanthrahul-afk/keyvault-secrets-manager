import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import type { ProjectSummary } from '../lib/api';
import { applyTheme } from '../lib/theme';
import { useVault } from '../lib/vault';
import { Icon } from './ui';

interface Item { id: string; group: string; label: string; hint?: string; icon: Parameters<typeof Icon>[0]['name']; run: () => void }

/** ⌘K / Ctrl+K command palette: jump to any project section or run an account action. */
export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const navigate = useNavigate();
  const vault = useVault();
  const qc = useQueryClient();
  const [q, setQ] = useState('');
  const [sel, setSel] = useState(0);

  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) { d.showModal(); setQ(''); setSel(0); }
    if (!open && d.open) d.close();
  }, [open]);

  const items = useMemo<Item[]>(() => {
    const go = (to: string) => () => { navigate(to); onClose(); };
    const projects = qc.getQueryData<ProjectSummary[]>(['projects']) ?? [];
    const list: Item[] = [
      { id: 'projects', group: 'Navigate', label: 'All projects', icon: 'layers', run: go('/app') },
      { id: 'send', group: 'Navigate', label: 'One-time share', icon: 'send', run: go('/app/send') },
      { id: 'account', group: 'Navigate', label: 'Account & security', icon: 'shield', run: go('/app/account') },
    ];
    for (const p of projects) {
      for (const [tab, label, icon] of [['secrets', 'Secrets', 'key'], ['changes', 'Changes', 'history'], ['health', 'Health', 'heart'], ['compare', 'Compare', 'diff'], ['members', 'Members', 'users'], ['tokens', 'Access tokens', 'terminal'], ['activity', 'Activity', 'activity']] as const) {
        list.push({ id: `${p.id}-${tab}`, group: 'Projects', label: `${p.name} / ${label}`, icon, run: go(`/app/p/${p.id}/${tab}`) });
      }
    }
    list.push(
      { id: 'light', group: 'Preferences', label: 'Theme: light', icon: 'sun', run: () => { applyTheme('light'); onClose(); } },
      { id: 'dark', group: 'Preferences', label: 'Theme: dark', icon: 'moon', run: () => { applyTheme('dark'); onClose(); } },
      { id: 'system', group: 'Preferences', label: 'Theme: system', icon: 'monitor', run: () => { applyTheme('system'); onClose(); } },
      { id: 'lock', group: 'Session', label: 'Lock vault', hint: 'Wipes keys from memory', icon: 'lock', run: () => { onClose(); vault.lock(); } },
      { id: 'logout', group: 'Session', label: 'Sign out', icon: 'logout', run: () => { onClose(); void vault.logout(); } },
    );
    return list;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const filtered = items.filter((i) => i.label.toLowerCase().includes(q.trim().toLowerCase()));
  const groups = [...new Set(filtered.map((i) => i.group))];

  return (
    <dialog ref={ref} className="palette" aria-label="Command palette" onClose={onClose}
      onCancel={(e) => { e.preventDefault(); onClose(); }} onClick={(e) => { if (e.target === ref.current) onClose(); }}>
      {open && (
        <>
          <div className="palette-input">
            <Icon name="search" />
            <input autoFocus placeholder="Search projects, pages and actions…" value={q} aria-label="Search"
              onChange={(e) => { setQ(e.target.value); setSel(0); }}
              onKeyDown={(e) => {
                if (e.key === 'ArrowDown') { e.preventDefault(); setSel((s) => Math.min(s + 1, filtered.length - 1)); }
                if (e.key === 'ArrowUp') { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
                if (e.key === 'Enter') filtered[sel]?.run();
              }} />
            <span className="kbd">Esc</span>
          </div>
          <div className="palette-list" role="listbox">
            {filtered.length === 0 && <div className="palette-empty">No results for "{q}"</div>}
            {groups.map((g) => (
              <div key={g}>
                <div className="palette-group">{g}</div>
                {filtered.filter((i) => i.group === g).map((i) => {
                  const idx = filtered.indexOf(i);
                  return (
                    <button key={i.id} type="button" role="option" aria-selected={idx === sel} className="palette-item"
                      onMouseEnter={() => setSel(idx)} onClick={i.run}>
                      <Icon name={i.icon} /> {i.label} {i.hint && <span className="hint">{i.hint}</span>}
                    </button>
                  );
                })}
              </div>
            ))}
          </div>
        </>
      )}
    </dialog>
  );
}
